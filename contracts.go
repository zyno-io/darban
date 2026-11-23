package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"sigs.k8s.io/yaml"
)

type registration struct {
	serviceName       string
	openAPI           string
	rewrites          string
	defaultVisibility *operationVisibility
	// invalid marks a registration that could not be decoded. The compiler
	// rejects the service instead of failing the whole contract set.
	invalid error
}

type rewriteRule struct {
	From struct {
		Method string `json:"method"`
		Path   string `json:"path"`
	} `json:"from"`
	To struct {
		ServiceName string `json:"serviceName"`
		Path        string `json:"path"`
	} `json:"to"`
}

type serviceBinding struct {
	Origin           string
	Prefix           string
	Mount            string
	DebugOrigin      string
	Operations       []operationSelection
	RegistrationOnly bool
}

type operationSelection struct {
	Method string
	Path   string
	Legacy *legacySecurity
}

type legacySecurity struct {
	Source   securityRequirements
	Profiles []string
}

// Some backends already mount routes under their module name. Map that
// upstream mount to the public service prefix.
func (b serviceBinding) publicPath(path string) (string, bool) {
	suffix, ok := strings.CutPrefix(path, b.Mount)
	if !ok || !literalPath.MatchString(suffix) {
		return "", false
	}
	return b.Prefix + suffix, true
}

type upstreamBindings struct {
	ServiceRoutes          map[string]serviceRoute
	BrowserOrigins         []string
	UpstreamRequestHeaders []string
	Hostname               string
	Authz                  string
	Authorization          authorizationConfig
	Debug                  debugConfig
	ContractAPIGroup       string
	Services               map[string]serviceBinding
	DefaultVisibility      *operationVisibility
	OpenAPI                openAPIConfig
}

type openAPIConfig struct {
	YAMLPath                       string
	JSONPath                       string
	PrefixTags                     string
	PopulateEmptyTags              bool
	OmitOperationExtensionPrefixes []string
}

type operationVisibility string

const (
	visibilityPublic    operationVisibility = "public"
	visibilityUnlisted  operationVisibility = "unlisted"
	visibilityInternal  operationVisibility = "internal"
	visibilityExtension                     = "x-darban-visibility"
	policyExtension                         = "x-gateway-policy"
	firstTagOnly                            = "firstOnly"
)

func (v operationVisibility) valid() bool {
	return v == visibilityPublic || v == visibilityUnlisted || v == visibilityInternal
}

func readVisibility(op map[string]any, fallback operationVisibility) (operationVisibility, error) {
	value, exists := op[visibilityExtension]
	if !exists {
		return fallback, nil
	}
	text, ok := value.(string)
	if !ok || !operationVisibility(text).valid() {
		return "", fmt.Errorf("%s must be public, unlisted, or internal", visibilityExtension)
	}
	return operationVisibility(text), nil
}

func readOperationID(op map[string]any) (string, error) {
	value, exists := op["operationId"]
	if !exists {
		return "", nil
	}
	upstream, ok := value.(string)
	if !ok || strings.TrimSpace(upstream) == "" {
		return "", errors.New("operationId must be a non-empty string")
	}
	return upstream, nil
}

func applyTagOptions(operation map[string]any, service string, settings openAPIConfig) error {
	value := operation["tags"]
	tags, ok := value.([]any)
	if value != nil && !ok {
		return errors.New("tags must be an array of strings")
	}
	if len(tags) == 0 {
		if settings.PopulateEmptyTags {
			operation["tags"] = []string{service}
		}
		return nil
	}

	parts := strings.Split(service, "-")
	var prefix strings.Builder
	prefix.WriteString(parts[0])
	for _, part := range parts[1:] {
		prefix.WriteString(uppercaseFirst(part))
	}
	servicePrefix := prefix.String()
	for i, tag := range tags {
		name, ok := tag.(string)
		if !ok || strings.TrimSpace(name) == "" {
			return errors.New("each tag must be a non-empty string")
		}
		if i == 0 || settings.PrefixTags != firstTagOnly {
			tags[i] = servicePrefix + uppercaseFirst(name)
		}
	}
	return nil
}

func uppercaseFirst(value string) string {
	first, width := utf8.DecodeRuneInString(value)
	return string(unicode.ToUpper(first)) + value[width:]
}

type securityRequirements []map[string][]string

type sourceDoc struct {
	OpenAPI    string                    `json:"openapi"`
	Paths      map[string]map[string]any `json:"paths"`
	Components map[string]map[string]any `json:"components"`
	Security   securityRequirements      `json:"security"`
}

type sourceOperation struct {
	service      string
	path         string
	credentials  []string
	visibility   operationVisibility
	operationID  string
	doc          map[string]any
	requirements securityRequirements
	source       *sourceDoc
}

type compiledOperation struct {
	key         operationKey
	service     string
	path        string
	credentials []string
}

type candidate struct {
	contractServices []string
	denied           []operationKey
	routes           []compiledOperation
	specYAML         []byte
	specJSON         []byte
	revision         string
}

var (
	serviceName = regexp.MustCompile("^[a-z][a-z0-9]*(-[a-z0-9]+)*$")
	prefixPath  = regexp.MustCompile("^/[a-z][a-z0-9-]*$")
	docPath     = regexp.MustCompile(`^(/[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)*)+$`)
	apiVersion  = regexp.MustCompile(`^3\.1\.[0-9]+$`)
	componentID = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
)

func loadBindings(path string, local bool) (upstreamBindings, error) {
	var bindings upstreamBindings
	if err := readJSON(path, &bindings); err != nil {
		return bindings, err
	}
	if !dnsName.MatchString(bindings.Hostname) || len(bindings.Services) == 0 {
		return bindings, errors.New("hostname and service bindings required")
	}
	if bindings.Authz != "" {
		if _, err := upstreamOrigin(bindings.Authz, local); err != nil {
			return bindings, err
		}
	}
	if err := bindings.Authorization.validate(bindings.Authz); err != nil {
		return bindings, err
	}
	if err := bindings.Debug.validate(bindings.Authorization); err != nil {
		return bindings, err
	}
	if err := bindings.validateServiceRoutes(local); err != nil {
		return bindings, err
	}
	if (!local || bindings.ContractAPIGroup != "") && !dnsName.MatchString(bindings.ContractAPIGroup) {
		return bindings, errors.New("contractAPIGroup must be a DNS name in Kubernetes mode")
	}
	for _, path := range []string{bindings.OpenAPI.YAMLPath, bindings.OpenAPI.JSONPath} {
		if path != "" && !docPath.MatchString(path) {
			return bindings, fmt.Errorf("invalid OpenAPI endpoint path %q", path)
		}
	}
	if bindings.OpenAPI.YAMLPath != "" && bindings.OpenAPI.YAMLPath == bindings.OpenAPI.JSONPath {
		return bindings, errors.New("OpenAPI endpoints need distinct paths")
	}
	switch bindings.OpenAPI.PrefixTags {
	case "", "all", firstTagOnly:
	default:
		return bindings, errors.New("openapi.prefixTags must be firstOnly or all")
	}
	if bindings.DefaultVisibility != nil && !bindings.DefaultVisibility.valid() {
		return bindings, errors.New("defaultVisibility must be public, unlisted, or internal")
	}
	for _, prefix := range bindings.OpenAPI.OmitOperationExtensionPrefixes {
		if !strings.HasPrefix(prefix, "x-") {
			return bindings, fmt.Errorf("invalid OpenAPI extension prefix %q", prefix)
		}
	}
	prefixes := make(map[string]string)
	for name, binding := range bindings.Services {
		if !serviceName.MatchString(name) || !prefixPath.MatchString(binding.Prefix) ||
			(binding.Mount != "" && !literalPath.MatchString(binding.Mount)) {
			return bindings, fmt.Errorf("invalid service binding %q", name)
		}
		if other, exists := prefixes[binding.Prefix]; exists {
			return bindings, fmt.Errorf("prefix collision between %q and %q", name, other)
		}
		prefixes[binding.Prefix] = name
		if binding.RegistrationOnly && len(binding.Operations) != 0 {
			return bindings, fmt.Errorf("registration-only service %q cannot select operations", name)
		}
		if _, err := upstreamOrigin(binding.Origin, local); err != nil {
			return bindings, err
		}
		if binding.DebugOrigin != "" {
			if bindings.Debug == (debugConfig{}) {
				return bindings, fmt.Errorf("service %q has a debug origin without a debug policy", name)
			}
			if _, err := upstreamOrigin(binding.DebugOrigin, local); err != nil {
				return bindings, err
			}
		}
	}
	return bindings, nil
}

func operationSecurity(doc map[string]any, source sourceDoc) (securityRequirements, error) {
	value, exists := doc["security"]
	if !exists {
		return source.Security, nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var requirements securityRequirements
	if err := json.Unmarshal(raw, &requirements); err != nil {
		return nil, err
	}
	return requirements, nil
}

func effectiveSecurity(doc map[string]any, source sourceDoc, allowed map[string]credentialProfile) (securityRequirements, []string, error) {
	requirements, err := operationSecurity(doc, source)
	if err != nil {
		return nil, nil, err
	}
	if len(requirements) == 0 {
		security, explicit := doc["security"].([]any)
		if explicit && len(security) == 0 && doc[policyExtension] == "anonymous" {
			return securityRequirements{}, nil, nil
		}
		return nil, nil, errors.New("explicit credential policy required")
	}
	if _, hasPolicy := doc[policyExtension]; hasPolicy {
		return nil, nil, errors.New("unknown or conflicting gateway policy")
	}
	profiles := make([]string, 0, len(requirements))
	schemes := make(map[string]bool, len(requirements))
	for _, alternative := range requirements {
		if len(alternative) != 1 {
			return nil, nil, errors.New("each alternative must specify one approved credential")
		}
		for name, scopes := range alternative {
			profile, configured := allowed[name]
			scheme, _ := source.Components["securitySchemes"][name].(map[string]any)
			declaredScheme, _ := scheme["scheme"].(string)
			if !configured || scopes == nil || len(scopes) != 0 || scheme["type"] != "http" ||
				!strings.EqualFold(declaredScheme, profile.Scheme) || schemes[profile.Scheme] {
				return nil, nil, fmt.Errorf("invalid or ambiguous credential profile %q", name)
			}
			schemes[profile.Scheme] = true
			profiles = append(profiles, name)
		}
	}
	return requirements, profiles, nil
}

func applyLegacySecurity(op map[string]any, source *sourceDoc, legacy *legacySecurity, allowed map[string]credentialProfile) error {
	security, err := operationSecurity(op, *source)
	if err != nil {
		return err
	}
	target := make(securityRequirements, 0, len(legacy.Profiles))
	for _, name := range legacy.Profiles {
		if _, exists := allowed[name]; !exists {
			return fmt.Errorf("unknown legacy credential profile %q", name)
		}
		target = append(target, map[string][]string{name: {}})
	}
	native := len(legacy.Profiles) != 0 && sameRequirementSet(security, target)
	if !native && ((security == nil) != (legacy.Source == nil) || !sameRequirementSet(security, legacy.Source)) {
		return errors.New("legacy source security changed")
	}
	if source.Components == nil {
		source.Components = make(map[string]map[string]any)
	}
	if source.Components["securitySchemes"] == nil {
		source.Components["securitySchemes"] = make(map[string]any)
	}
	schemes := source.Components["securitySchemes"]
	if native {
		// The service already emits the target security. Keep its operation and
		// the schemes it declares, and only fill in a scheme it left out.
		for _, name := range legacy.Profiles {
			if _, declared := schemes[name]; !declared {
				schemes[name] = map[string]any{"type": "http", "scheme": allowed[name].Scheme}
			}
		}
		return nil
	}
	for _, name := range legacy.Profiles {
		schemes[name] = map[string]any{"type": "http", "scheme": allowed[name].Scheme}
	}
	op["security"] = target
	return nil
}

// sameRequirementSet compares security requirement objects as an unordered
// set. A nil and an empty scope list are equal.
func sameRequirementSet(a, b securityRequirements) bool {
	if len(a) != len(b) {
		return false
	}
	same := func(x, y map[string][]string) bool {
		return len(x) == len(y) && !slices.ContainsFunc(slices.Collect(maps.Keys(x)), func(name string) bool {
			scopes, exists := y[name]
			return !exists || !slices.Equal(x[name], scopes)
		})
	}
	for _, expected := range b {
		if !slices.ContainsFunc(a, func(actual map[string][]string) bool { return same(actual, expected) }) {
			return false
		}
	}
	return true
}

// Import only components referenced by a published operation. Prefix names
// by service and keep recursive schemas local to the composed document.
func importComponent(service, kind, name string, source sourceDoc, out map[string]map[string]any) (string, error) {
	component, exists := source.Components[kind][name]
	if !exists || !componentID.MatchString(name) {
		return "", fmt.Errorf("unknown component %s/%s", kind, name)
	}
	prefixed := service + "." + name
	if out[kind] == nil {
		out[kind] = make(map[string]any)
	}
	if _, imported := out[kind][prefixed]; imported {
		return prefixed, nil
	}
	out[kind][prefixed] = nil
	expanded, err := importReferences(component, service, source, out)
	if err != nil {
		return "", err
	}
	out[kind][prefixed] = expanded
	return prefixed, nil
}

func importReferences(value any, service string, source sourceDoc, out map[string]map[string]any) (any, error) {
	switch item := value.(type) {
	case map[string]any:
		copy := make(map[string]any, len(item))
		for key, val := range item {
			switch key {
			case "$ref":
				ref, _ := val.(string)
				parts := strings.Split(ref, "/")
				if len(parts) != 4 || parts[0] != "#" || parts[1] != "components" ||
					!slices.Contains([]string{"schemas", "responses", "parameters", "examples", "requestBodies", "headers"}, parts[2]) {
					return nil, fmt.Errorf("unsupported reference %q", ref)
				}
				name, err := importComponent(service, parts[2], parts[3], source, out)
				if err != nil {
					return nil, err
				}
				copy[key] = "#/components/" + parts[2] + "/" + name
			case "$id", "$dynamicRef", "discriminator":
				return nil, fmt.Errorf("unsupported reference feature %q", key)
			case "example", "examples", "default", "const", "enum":
				// Singular example and schema values contain data, not references.
				// Examples maps can hold OpenAPI Reference Objects.
				if key == "examples" {
					expanded, err := importReferences(val, service, source, out)
					if err != nil {
						return nil, err
					}
					copy[key] = expanded
				} else {
					copy[key] = val
				}
			default:
				expanded, err := importReferences(val, service, source, out)
				if err != nil {
					return nil, err
				}
				copy[key] = expanded
			}
		}
		return copy, nil
	case []any:
		copy := make([]any, 0, len(item))
		for _, element := range item {
			expanded, err := importReferences(element, service, source, out)
			if err != nil {
				return nil, err
			}
			copy = append(copy, expanded)
		}
		return copy, nil
	default:
		return value, nil
	}
}

func parseOpenAPI(openAPI string) (sourceDoc, error) {
	var source sourceDoc
	raw, err := yaml.YAMLToJSONStrict([]byte(openAPI))
	if err != nil || json.Unmarshal(raw, &source) != nil {
		return source, errors.New("invalid OpenAPI YAML")
	}
	if !apiVersion.MatchString(source.OpenAPI) || source.Paths == nil {
		return source, errors.New("expected an OpenAPI 3.1 document with paths")
	}
	return source, nil
}

func readOperations(service string, source sourceDoc, binding serviceBinding, fallback operationVisibility, bindings upstreamBindings, native map[operationKey]sourceOperation, denied *[]operationKey) error {
	selected := make(map[operationKey]*legacySecurity, len(binding.Operations))
	for _, operation := range binding.Operations {
		key := operationKey{operation.Method, operation.Path}
		if _, exists := selected[key]; exists {
			return fmt.Errorf("duplicate operation selection %s %s", key.method, key.path)
		}
		selected[key] = operation.Legacy
	}
	matched := 0
	for path, item := range source.Paths {
		for key, value := range item {
			legacy, included := selected[operationKey{key, path}]
			excluded := len(selected) != 0 && !included
			_, direct := bindings.ServiceRoutes[binding.Prefix]
			if excluded && !direct {
				continue
			}
			if key == "parameters" || key == "servers" || key == "summary" || key == "description" || strings.HasPrefix(key, "x-") {
				continue
			}
			if !slices.Contains([]string{"get", "post", "put", "patch", "delete", "head", "options", "trace"}, key) {
				return fmt.Errorf("unsupported path item field %q", key)
			}
			op, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf("invalid operation %s %s", key, path)
			}
			visibility, err := readVisibility(op, fallback)
			if err != nil {
				return fmt.Errorf("%s %s: %w", key, path, err)
			}
			if visibility == visibilityInternal && direct {
				if suffix, ok := strings.CutPrefix(path, binding.Mount); ok {
					*denied = append(*denied, operationKey{strings.ToUpper(key), binding.Prefix + suffix})
				}
			}
			if excluded {
				continue
			}
			matched++
			publicPath, mapped := binding.publicPath(path)
			if !mapped {
				if visibility == visibilityInternal {
					continue
				}
				return fmt.Errorf("unmapped or non-literal public path %q", path)
			}
			publicKey := operationKey{strings.ToUpper(key), publicPath}
			if visibility == visibilityInternal {
				native[publicKey] = sourceOperation{visibility: visibilityInternal}
				continue
			}
			if legacy != nil {
				if err := applyLegacySecurity(op, &source, legacy, bindings.Authorization.Profiles); err != nil {
					return fmt.Errorf("%s %s: %w", key, path, err)
				}
			}
			requirements, profiles, err := effectiveSecurity(op, source, bindings.Authorization.Profiles)
			if err != nil {
				return fmt.Errorf("%s %s: %w", key, path, err)
			}
			if _, exists := op["callbacks"]; exists {
				return errors.New("callbacks require explicit public URL handling")
			}
			if responses, ok := op["responses"].(map[string]any); !ok || len(responses) == 0 {
				return fmt.Errorf("responses required for %s %s", key, path)
			}
			operationID, err := readOperationID(op)
			if err != nil {
				return fmt.Errorf("%s %s: %w", key, path, err)
			}
			// Preserve path-item parameters wherever the operation can be published,
			// including at an alias. Operation-level declarations override them.
			contract := make(map[string]any)
			for _, field := range []string{"summary", "description"} {
				if val, exists := item[field]; exists {
					contract[field] = val
				}
			}
			for field, val := range op {
				switch field {
				case "servers", "security", "operationId", visibilityExtension, policyExtension:
				default:
					if !slices.ContainsFunc(bindings.OpenAPI.OmitOperationExtensionPrefixes, func(prefix string) bool {
						return strings.HasPrefix(field, prefix)
					}) {
						contract[field] = val
					}
				}
			}
			if parameters, exists := item["parameters"]; exists {
				if _, overridden := op["parameters"]; overridden {
					return errors.New("mixed path and operation parameters require merge support")
				}
				contract["parameters"] = parameters
			}
			native[publicKey] = sourceOperation{
				service:      service,
				path:         path,
				credentials:  profiles,
				visibility:   visibility,
				operationID:  operationID,
				doc:          contract,
				requirements: requirements,
				source:       &source,
			}
		}
	}
	if len(selected) != 0 && matched != len(selected) {
		return errors.New("selected operations are missing")
	}
	return nil
}

type aliasTarget struct {
	key     operationKey
	service string
}

// serviceUnit is one service's contract after per-service validation. It is
// the unit of isolation: the compiler keeps, replaces or drops whole units.
type serviceUnit struct {
	digest           [sha256.Size]byte
	openAPIDigest    [sha256.Size]byte
	registrationOnly bool
	native           map[operationKey]sourceOperation
	aliases          map[operationKey]aliasTarget
	denied           []operationKey
}

const (
	servingCurrent  = "current"
	servingLastGood = "last-good"
	servingNone     = "none"
)

type serviceOutcome struct {
	serving   string
	rejection string
	missing   bool
}

// compileReport describes what compile did with each service. accepted holds
// the units that are serving and becomes the next call's lastGood.
type compileReport struct {
	services map[string]serviceOutcome
	accepted map[string]*serviceUnit
}

func registrationDigest(reg registration) [sha256.Size]byte {
	hash := sha256.New()
	visibility := "-"
	if reg.defaultVisibility != nil {
		visibility = string(*reg.defaultVisibility)
	}
	fmt.Fprintf(hash, "%q %q %q %q", reg.serviceName, reg.openAPI, reg.rewrites, visibility)
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func compileService(reg registration, binding serviceBinding, bindings upstreamBindings, defaultVisibility operationVisibility) (*serviceUnit, error) {
	fallback := defaultVisibility
	if reg.defaultVisibility != nil {
		if !reg.defaultVisibility.valid() {
			return nil, errors.New("defaultVisibility must be public, unlisted, or internal")
		}
		fallback = *reg.defaultVisibility
	}
	source, err := parseOpenAPI(reg.openAPI)
	if err != nil {
		return nil, err
	}
	var rules []rewriteRule
	if err := yaml.UnmarshalStrict([]byte(reg.rewrites), &rules); err != nil || rules == nil {
		return nil, errors.New("requires a rewrites list")
	}
	unit := &serviceUnit{
		digest:           registrationDigest(reg),
		openAPIDigest:    sha256.Sum256([]byte(reg.openAPI)),
		registrationOnly: binding.RegistrationOnly,
		native:           make(map[operationKey]sourceOperation),
		aliases:          make(map[operationKey]aliasTarget),
	}
	if binding.RegistrationOnly {
		if len(rules) != 0 {
			return nil, errors.New("registration-only service cannot define rewrites")
		}
		return unit, nil
	}
	if err := readOperations(reg.serviceName, source, binding, fallback, bindings, unit.native, &unit.denied); err != nil {
		return nil, err
	}
	for _, rule := range rules {
		from := operationKey{rule.From.Method, rule.From.Path}
		target, approved := bindings.Services[rule.To.ServiceName]
		destination, mapped := target.publicPath(rule.To.Path)
		if !approved || !mapped || !strings.HasPrefix(from.path, binding.Prefix+"/") ||
			!literalPath.MatchString(from.path) {
			return nil, errors.New("rewrite outside its registered service bindings")
		}
		if _, exists := unit.aliases[from]; exists {
			return nil, fmt.Errorf("duplicate rewrite for %s %s", from.method, from.path)
		}
		unit.aliases[from] = aliasTarget{operationKey{from.method, destination}, rule.To.ServiceName}
	}
	return unit, nil
}

// compile builds one candidate from per-service contracts. A service whose
// contract is unbound, invalid, or conflicts with another service is isolated:
// it keeps its entry in lastGood when it has one, and is otherwise omitted.
// Other services are unaffected.
func compile(regs []registration, bindings upstreamBindings, lastGood map[string]*serviceUnit) (candidate, compileReport) {
	defaultVisibility := visibilityPublic
	if bindings.DefaultVisibility != nil {
		defaultVisibility = *bindings.DefaultVisibility
	}
	report := compileReport{services: make(map[string]serviceOutcome)}
	sorted := slices.SortedStableFunc(slices.Values(regs), func(a, b registration) int {
		return strings.Compare(a.serviceName, b.serviceName)
	})
	count := make(map[string]int, len(sorted))
	for _, reg := range sorted {
		count[reg.serviceName]++
	}
	current := make(map[string]*serviceUnit)
	rejected := make(map[string]string)
	for _, reg := range sorted {
		name := reg.serviceName
		binding, bound := bindings.Services[name]
		switch {
		case !bound:
			report.services[name] = serviceOutcome{serving: servingNone,
				rejection: fmt.Sprintf("service %q is not in bindings.services; contract ignored", name)}
		case count[name] > 1:
			rejected[name] = fmt.Sprintf("service %s: duplicate contract registrations", name)
		case reg.invalid != nil:
			rejected[name] = fmt.Sprintf("service %s: %v", name, reg.invalid)
		default:
			if prev := lastGood[name]; prev != nil && prev.digest == registrationDigest(reg) {
				current[name] = prev
				continue
			}
			unit, err := compileService(reg, binding, bindings, defaultVisibility)
			if err != nil {
				rejected[name] = fmt.Sprintf("service %s: %v", name, err)
				continue
			}
			current[name] = unit
		}
	}
	preferred := maps.Clone(current)
	for name := range rejected {
		if prev := lastGood[name]; prev != nil {
			preferred[name] = prev
		}
	}

	out, accepted, conflicts := selectUnits(preferred, lastGood, bindings)
	report.accepted = accepted
	for name := range count {
		if _, bound := bindings.Services[name]; !bound {
			continue
		}
		outcome := serviceOutcome{serving: servingNone, rejection: rejected[name]}
		if message, failed := conflicts[name]; failed {
			outcome.rejection = message
		}
		if unit := accepted[name]; unit != nil {
			outcome.serving = servingLastGood
			if unit == current[name] {
				outcome.serving = servingCurrent
			}
		}
		report.services[name] = outcome
	}
	for _, name := range slices.Sorted(maps.Keys(bindings.Services)) {
		if !bindings.Services[name].RegistrationOnly && count[name] == 0 {
			report.services[name] = serviceOutcome{serving: servingNone, missing: true}
		}
	}
	out.contractServices = slices.Sorted(maps.Keys(accepted))
	return out, report
}

// compileStrict treats any rejected, unbound or missing contract as an error.
// It is for one-shot use such as -print-spec.
func compileStrict(regs []registration, bindings upstreamBindings) (candidate, error) {
	out, report := compile(regs, bindings, nil)
	for _, name := range slices.Sorted(maps.Keys(report.services)) {
		outcome := report.services[name]
		if outcome.rejection != "" {
			return out, errors.New(outcome.rejection)
		}
		if outcome.missing {
			return out, fmt.Errorf("missing contract for service %q", name)
		}
	}
	return out, nil
}

// selectUnits assembles every preferred unit together. When that fails it
// admits units one at a time: unchanged last-good units first, then changed
// ones, each group in service-name order. A unit that makes the set fail is
// replaced by its last-good unit if that fits, else omitted. So the newer or
// changed contract loses a conflict; between two changed contracts the
// lexically first service name wins.
func selectUnits(preferred, lastGood map[string]*serviceUnit, bindings upstreamBindings) (candidate, map[string]*serviceUnit, map[string]string) {
	if out, err := assemble(preferred, bindings); err == nil {
		return out, preferred, nil
	}
	var unchanged, changed []string
	for _, name := range slices.Sorted(maps.Keys(preferred)) {
		if preferred[name] == lastGood[name] {
			unchanged = append(unchanged, name)
		} else {
			changed = append(changed, name)
		}
	}
	accepted := make(map[string]*serviceUnit)
	conflicts := make(map[string]string)
	var best candidate
	haveBest := false
	try := func(name string, unit *serviceUnit) error {
		accepted[name] = unit
		out, err := assemble(accepted, bindings)
		if err != nil {
			delete(accepted, name)
			return err
		}
		best, haveBest = out, true
		return nil
	}
	for _, name := range append(unchanged, changed...) {
		unit := preferred[name]
		err := try(name, unit)
		if err == nil {
			continue
		}
		conflicts[name] = fmt.Sprintf("service %s: %v", name, err)
		if prev := lastGood[name]; prev != nil && prev != unit {
			try(name, prev)
		}
	}
	if !haveBest {
		best, _ = assemble(accepted, bindings)
	}
	return best, accepted, conflicts
}

// assemble merges validated units into one candidate and runs the checks that
// span services: rewrites, route and OpenAPI endpoint conflicts, duplicate
// operationIds and component imports.
func assemble(units map[string]*serviceUnit, bindings upstreamBindings) (candidate, error) {
	var out candidate
	registrationOnlyDigests := make(map[string][sha256.Size]byte)
	native := make(map[operationKey]sourceOperation)
	aliases := make(map[operationKey]aliasTarget)
	components := make(map[string]map[string]any)
	for _, name := range slices.Sorted(maps.Keys(units)) {
		unit := units[name]
		if unit.registrationOnly {
			registrationOnlyDigests[name] = unit.openAPIDigest
			continue
		}
		maps.Copy(native, unit.native)
		maps.Copy(aliases, unit.aliases)
		out.denied = append(out.denied, unit.denied...)
	}

	published := make(map[operationKey]sourceOperation, len(native)+len(aliases))
	for key, op := range native {
		if op.visibility == visibilityInternal {
			out.denied = append(out.denied, key)
		} else {
			published[key] = op
		}
	}
	for from, alias := range aliases {
		if _, serving := units[alias.service]; !serving {
			// The target service has no serving contract. Do not publish the alias.
			delete(published, from)
			continue
		}
		to := alias.key
		original := native[from]
		target, exists := native[to]
		if original.visibility == visibilityInternal || target.visibility == visibilityInternal {
			delete(published, from)
			out.denied = append(out.denied, from)
			continue
		}
		_, targetRewritten := aliases[to]
		if !exists || targetRewritten {
			return out, fmt.Errorf("rewrite %s %s has missing or rewritten target %s", from.method, from.path, to.path)
		}
		if original.visibility == visibilityUnlisted {
			target.visibility = visibilityUnlisted
		}
		// A rewrite keeps the SDK identity of the original public route.
		target.operationID = original.operationID
		published[from] = target
	}
	paths := make(map[string]map[string]any)
	operationIDs := make(map[string]operationKey)
	unlistedComponents := make(map[string]map[string]any)
	for _, key := range slices.SortedFunc(maps.Keys(published), compareOperationKeys) {
		source := published[key]
		if key.path == bindings.OpenAPI.YAMLPath || key.path == bindings.OpenAPI.JSONPath {
			return out, fmt.Errorf("OpenAPI endpoint conflicts with route %s %s", key.method, key.path)
		}
		out.routes = append(out.routes, compiledOperation{key, source.service, source.path, source.credentials})
		operationComponents := components
		if source.visibility == visibilityUnlisted {
			operationComponents = unlistedComponents
		}
		normalized, err := importReferences(source.doc, source.service, *source.source, operationComponents)
		if err != nil {
			return out, fmt.Errorf("%s %s: %w", key.method, key.path, err)
		}
		if source.visibility == visibilityUnlisted {
			continue
		}
		if paths[key.path] == nil {
			paths[key.path] = make(map[string]any)
		}
		operation := normalized.(map[string]any)
		if err := applyTagOptions(operation, source.service, bindings.OpenAPI); err != nil {
			return out, fmt.Errorf("%s %s: %w", key.method, key.path, err)
		}
		security := make(securityRequirements, 0, len(source.requirements))
		for _, alternative := range source.requirements {
			for profile, scopes := range alternative {
				name, err := importComponent(source.service, "securitySchemes", profile, *source.source, components)
				if err != nil {
					return out, err
				}
				security = append(security, map[string][]string{name: scopes})
			}
		}
		operation["security"] = security
		if id := source.operationID; id != "" {
			if other, exists := operationIDs[id]; exists {
				return out, fmt.Errorf("duplicate operationId %q on %s %s and %s %s", id, other.method, other.path, key.method, key.path)
			}
			operationIDs[id] = key
			operation["operationId"] = id
		}
		paths[key.path][strings.ToLower(key.method)] = operation
	}

	document := map[string]any{
		"openapi":    "3.1.0",
		"info":       map[string]string{"title": "Darban", "version": "1"},
		"servers":    []map[string]string{{"url": "https://" + bindings.Hostname}},
		"paths":      paths,
		"components": components,
	}
	rawJSON, err := json.Marshal(document)
	if err != nil {
		return out, err
	}
	out.specYAML, err = yaml.JSONToYAML(rawJSON)
	if err != nil {
		return out, err
	}
	if bindings.OpenAPI.JSONPath != "" {
		out.specJSON = rawJSON
	}
	slices.SortFunc(out.routes, func(a, b compiledOperation) int {
		return strings.Compare(a.key.method+" "+a.key.path, b.key.method+" "+b.key.path)
	})
	hash := sha256.New()
	hash.Write(out.specYAML)
	for _, name := range slices.Sorted(maps.Keys(registrationOnlyDigests)) {
		fmt.Fprintf(hash, "registered %s %x\n", name, registrationOnlyDigests[name])
	}
	for _, route := range out.routes {
		fmt.Fprintf(hash, "%s %s => %s %s %v\n", route.key.method, route.key.path, route.service, route.path, route.credentials)
	}
	slices.SortFunc(out.denied, compareOperationKeys)
	out.denied = slices.Compact(out.denied)
	for _, key := range out.denied {
		fmt.Fprintf(hash, "internal %s %s\n", key.method, key.path)
	}
	out.revision = hex.EncodeToString(hash.Sum(nil))
	return out, nil
}

func compareOperationKeys(a, b operationKey) int {
	if cmp := strings.Compare(a.method, b.method); cmp != 0 {
		return cmp
	}
	return strings.Compare(a.path, b.path)
}
