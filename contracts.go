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
	"time"
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
	// created orders conflicts between changed contracts. Zero when unknown.
	created time.Time
	// upstream and prefix are the contract's spec.upstream and spec.prefix.
	upstream, prefix string
	// namespace is the contract's namespace. local marks a manifest contract,
	// which may name loopback upstreams and any Service namespace.
	namespace string
	local     bool
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
	Origin      string
	Prefix      string
	Mount       string
	DebugOrigin string
	Operations  []operationSelection
	// Route and Publish default to true. Route false keeps the service's
	// traffic on its serviceRoutes entry and makes the contract docs-only.
	// Publish false keeps its operations out of the combined OpenAPI.
	Route   *bool `json:",omitempty"`
	Publish *bool `json:",omitempty"`
}

// routed reports whether the contract routes the service's traffic.
func (b serviceBinding) routed() bool { return b.Route == nil || *b.Route }

// published reports whether the service's operations are documented.
func (b serviceBinding) published() bool { return b.Publish == nil || *b.Publish }

// validate checks the fields of a service binding. Origins are optional
// because a contract can supply them, so only present ones are checked. A
// binding that came from the bindings file also checks its origins.
func (b serviceBinding) validate(name string, bindings upstreamBindings, local, checkOrigins bool) error {
	if !serviceName.MatchString(name) || (b.Prefix != "" && !prefixPath.MatchString(b.Prefix)) ||
		(b.Mount != "" && !literalPath.MatchString(b.Mount)) {
		return fmt.Errorf("invalid service binding %q", name)
	}
	for _, operation := range b.Operations {
		if err := operation.Legacy.validate(); err != nil {
			return fmt.Errorf("service %q: %w", name, err)
		}
	}
	if !b.routed() && len(b.Operations) != 0 {
		return fmt.Errorf("service %q has route: false, so it cannot select operations", name)
	}
	if !b.routed() && b.published() {
		// The document describes the direct route, which proxies <prefix>/X to X.
		if _, direct := bindings.ServiceRoutes[b.Prefix]; b.Prefix == "" || !direct || b.Mount != "" {
			return fmt.Errorf("service %q has route: false and publish: true, which requires a prefix with a serviceRoutes entry and no mount", name)
		}
	}
	if checkOrigins && b.Origin != "" {
		if _, err := upstreamOrigin(b.Origin, local); err != nil {
			return err
		}
	}
	if b.DebugOrigin != "" {
		if bindings.Debug == (debugConfig{}) {
			return fmt.Errorf("service %q has a debug origin without a debug policy", name)
		}
		if checkOrigins {
			if _, err := upstreamOrigin(b.DebugOrigin, local); err != nil {
				return err
			}
		}
	}
	return nil
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

func (l *legacySecurity) validate() error {
	if l == nil {
		return nil
	}
	if len(slices.Compact(slices.Sorted(slices.Values(l.Profiles)))) != len(l.Profiles) {
		return errors.New("duplicate legacy profiles")
	}
	for i, requirement := range l.Source {
		for _, other := range l.Source[i+1:] {
			if sameRequirementSet(securityRequirements{requirement}, securityRequirements{other}) {
				return errors.New("duplicate legacy source security requirements")
			}
		}
	}
	return nil
}

// Some backends already mount routes under their module name. Map that
// upstream mount to the public service prefix. The rest of the path must be a
// valid operation path (see templatePath).
func (b serviceBinding) publicPath(path string) (string, bool) {
	suffix, ok := strings.CutPrefix(path, b.Mount)
	if !ok || !templatePath(suffix) {
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
	UpstreamTLS            upstreamTLSConfig
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
	policyExtension                         = "x-darban-policy"
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
	// unrouted marks an operation of a docs-only service (route: false). It
	// can be documented but is never routed.
	unrouted bool
}

type compiledOperation struct {
	key         operationKey
	service     string
	path        string
	credentials []string
}

// serviceCounts is what the assembled snapshot does with one service's
// public operation keys, including the rewrites it owns.
type serviceCounts struct {
	routes, documented, denied int
}

type candidate struct {
	contractServices []string
	// unserved lists public prefixes of bound services with no serving contract.
	unserved []string
	denied   []operationKey
	// passthrough lists operations left unselected by their bindings.
	passthrough []operationKey
	routes      []compiledOperation
	// services holds the effective binding of every assembled service.
	services map[string]serviceBinding
	// aliasWarnings holds, by owning service, why a rewrite of that service is
	// denied although its target is served. It never rejects a contract.
	aliasWarnings map[string][]string
	// counts holds, by service, its routed, documented and denied keys.
	counts   map[string]serviceCounts
	specYAML []byte
	specJSON []byte
	revision string
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
	if !dnsName.MatchString(bindings.Hostname) {
		return bindings, errors.New("hostname required")
	}
	if err := bindings.UpstreamTLS.validate(); err != nil {
		return bindings, err
	}
	if bindings.UpstreamTLS.CAFile != "" {
		if _, err := loadCAPool(bindings.UpstreamTLS.CAFile); err != nil {
			return bindings, fmt.Errorf("upstreamTLS.caFile: %w", err)
		}
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
		if err := binding.validate(name, bindings, local, true); err != nil {
			return bindings, err
		}
		if binding.Prefix == "" {
			continue
		}
		if _, direct := bindings.ServiceRoutes[binding.Prefix]; direct && binding.Mount != "" {
			return bindings, fmt.Errorf("service %q has a mount, which a serviceRoutes prefix %s does not support", name, binding.Prefix)
		}
		if other, exists := prefixes[binding.Prefix]; exists {
			return bindings, fmt.Errorf("prefix collision between %q and %q", name, other)
		}
		prefixes[binding.Prefix] = name
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
		if len(x) != len(y) {
			return false
		}
		for name, scopes := range x {
			other, exists := y[name]
			if !exists || !slices.Equal(scopes, other) {
				return false
			}
		}
		return true
	}
	contains := func(set securityRequirements, item map[string][]string) bool {
		return slices.ContainsFunc(set, func(other map[string][]string) bool { return same(item, other) })
	}
	for _, item := range b {
		if !contains(a, item) {
			return false
		}
	}
	for _, item := range a {
		if !contains(b, item) {
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

// nameMaps are the fields whose keys are names, such as property names, and
// whose values are objects to import. A name such as default or $ref is then
// not a keyword.
var nameMaps = []string{"properties", "patternProperties", "$defs", "definitions", "dependentSchemas",
	"responses", "headers", "content", "encoding", "links", "schemas", "requestBodies", "parameters", "securitySchemes", "examples"}

func importReferences(value any, service string, source sourceDoc, out map[string]map[string]any) (any, error) {
	return importValue(value, false, service, source, out)
}

func importValue(value any, names bool, service string, source sourceDoc, out map[string]map[string]any) (any, error) {
	switch item := value.(type) {
	case map[string]any:
		copy := make(map[string]any, len(item))
		for _, key := range slices.Sorted(maps.Keys(item)) {
			val := item[key]
			if names {
				expanded, err := importValue(val, false, service, source, out)
				if err != nil {
					return nil, err
				}
				copy[key] = expanded
				continue
			}
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
			case "$id", "$dynamicRef":
				return nil, fmt.Errorf("unsupported reference feature %q", key)
			case "discriminator":
				expanded, err := importDiscriminator(val, service, source, out)
				if err != nil {
					return nil, err
				}
				copy[key] = expanded
			case "example", "default", "const", "enum":
				// Singular example and schema values contain data, not references.
				copy[key] = val
			default:
				_, isMap := val.(map[string]any)
				expanded, err := importValue(val, isMap && slices.Contains(nameMaps, key), service, source, out)
				if err != nil {
					return nil, err
				}
				copy[key] = expanded
			}
		}
		if !names {
			// A discriminator without a full mapping infers each oneOf or anyOf
			// schema's name. Map them, since importing renames them.
			var candidates []string
			for _, key := range []string{"oneOf", "anyOf"} {
				alternatives, _ := item[key].([]any)
				for _, alternative := range alternatives {
					if ref, ok := alternative.(map[string]any)["$ref"].(string); ok {
						if name, found := strings.CutPrefix(ref, "#/components/schemas/"); found {
							candidates = append(candidates, name)
						}
					}
				}
			}
			if err := mapInferredDiscriminator(item, copy, candidates, service, source, out); err != nil {
				return nil, err
			}
		}
		return copy, nil
	case []any:
		copy := make([]any, 0, len(item))
		for _, element := range item {
			expanded, err := importValue(element, false, service, source, out)
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

// discriminatorObject returns a Discriminator Object: a string propertyName,
// an optional mapping of strings, and x- extensions.
func discriminatorObject(value any) (map[string]any, bool) {
	object, ok := value.(map[string]any)
	if _, named := object["propertyName"].(string); !ok || !named {
		return nil, false
	}
	for key, field := range object {
		switch {
		case key == "propertyName" || strings.HasPrefix(key, "x-"):
		case key == "mapping":
			mapping, ok := field.(map[string]any)
			if !ok {
				return nil, false
			}
			for _, target := range mapping {
				if _, ok := target.(string); !ok {
					return nil, false
				}
			}
		default:
			return nil, false
		}
	}
	return object, true
}

// mappedSchema returns the schema name a discriminator mapping value names.
func mappedSchema(target string) (string, bool) {
	name, _ := strings.CutPrefix(target, "#/components/schemas/")
	return name, componentID.MatchString(name)
}

// importDiscriminator imports the schemas a Discriminator Object maps to and
// renames its mapping values like a $ref. A mapping value is a schema
// reference or a bare schema name, and keeps its form. A property named
// discriminator is imported as a name (see nameMaps), so any other value here
// is a malformed discriminator.
func importDiscriminator(value any, service string, source sourceDoc, out map[string]map[string]any) (any, error) {
	object, ok := discriminatorObject(value)
	if !ok {
		return nil, errors.New("a discriminator needs a string propertyName, an optional mapping of strings and x- extensions only")
	}
	imported := make(map[string]any, len(object))
	for _, key := range slices.Sorted(maps.Keys(object)) {
		switch {
		case key == "propertyName":
			imported[key] = object[key]
		case key == "mapping":
			mapping := object[key].(map[string]any)
			renamed := make(map[string]any, len(mapping))
			for _, value := range slices.Sorted(maps.Keys(mapping)) {
				target := mapping[value].(string)
				name, valid := mappedSchema(target)
				if !valid {
					return nil, fmt.Errorf("unsupported discriminator mapping %q", target)
				}
				prefixed, err := importComponent(service, "schemas", name, source, out)
				if err != nil {
					return nil, err
				}
				if strings.HasPrefix(target, "#/") {
					prefixed = "#/components/schemas/" + prefixed
				}
				renamed[value] = prefixed
			}
			imported[key] = renamed
		default:
			expanded, err := importReferences(object[key], service, source, out)
			if err != nil {
				return nil, err
			}
			imported[key] = expanded
		}
	}
	return imported, nil
}

// mapInferredDiscriminator adds a mapping entry for each candidate schema the
// discriminator of the source schema would name implicitly: one that no
// mapping value targets and no mapping key already claims. The entry keeps
// the original name as the value and targets the renamed schema.
func mapInferredDiscriminator(source any, imported any, candidates []string, service string, doc sourceDoc, out map[string]map[string]any) error {
	original, _ := source.(map[string]any)
	discriminator, ok := discriminatorObject(original["discriminator"])
	copy, _ := imported.(map[string]any)
	if !ok || copy == nil || len(candidates) == 0 {
		return nil
	}
	explicit, _ := discriminator["mapping"].(map[string]any)
	covered := make(map[string]bool, len(explicit))
	for _, target := range explicit {
		if name, valid := mappedSchema(target.(string)); valid {
			covered[name] = true
		}
	}
	result, _ := copy["discriminator"].(map[string]any)
	mapping, _ := result["mapping"].(map[string]any)
	added := false
	for _, name := range candidates {
		if _, claimed := explicit[name]; claimed || covered[name] {
			continue
		}
		prefixed, err := importComponent(service, "schemas", name, doc, out)
		if err != nil {
			return err
		}
		if mapping == nil {
			mapping = make(map[string]any)
		}
		mapping[name] = "#/components/schemas/" + prefixed
		covered[name], added = true, true
	}
	if added {
		result["mapping"] = mapping
	}
	return nil
}

// mapImportedExtenders maps, for each imported base schema of a service whose
// discriminator has no oneOf or anyOf, the imported schemas that extend it
// with allOf. Their inferred names change with renaming. It runs after the
// import so it adds no schema that no operation references.
func mapImportedExtenders(service string, source sourceDoc, out map[string]map[string]any) error {
	schemas := source.Components["schemas"]
	imported := func(name string) bool {
		_, ok := out["schemas"][service+"."+name]
		return ok
	}
	extenders := make(map[string][]string)
	for _, name := range slices.Sorted(maps.Keys(schemas)) {
		schema, _ := schemas[name].(map[string]any)
		parts, _ := schema["allOf"].([]any)
		for _, part := range parts {
			ref, _ := part.(map[string]any)["$ref"].(string)
			if base, ok := strings.CutPrefix(ref, "#/components/schemas/"); ok && imported(name) {
				extenders[base] = append(extenders[base], name)
			}
		}
	}
	for _, base := range slices.Sorted(maps.Keys(extenders)) {
		schema, _ := schemas[base].(map[string]any)
		if !imported(base) || schema["oneOf"] != nil || schema["anyOf"] != nil {
			continue
		}
		if err := mapInferredDiscriminator(schema, out["schemas"][service+"."+base], extenders[base], service, source, out); err != nil {
			return err
		}
	}
	return nil
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

// readOperations validates a contract's operations and collects them by public
// key: the routable ones in native, the internal ones in denied, and in
// passthrough those the binding's operations leave unselected, so a selected
// template cannot capture their paths.
func readOperations(service string, source sourceDoc, binding serviceBinding, fallback operationVisibility, bindings upstreamBindings, native map[operationKey]sourceOperation, denied, passthrough *[]operationKey) error {
	selected := make(map[operationKey]*legacySecurity, len(binding.Operations))
	for _, operation := range binding.Operations {
		key := operationKey{operation.Method, operation.Path}
		if _, exists := selected[key]; exists {
			return fmt.Errorf("duplicate operation selection %s %s", key.method, key.path)
		}
		selected[key] = operation.Legacy
	}
	matched := 0
	// shapes holds the first path of each method and path shape.
	shapes := make(map[operationKey]string)
	for _, path := range slices.Sorted(maps.Keys(source.Paths)) {
		item := source.Paths[path]
		for _, key := range slices.Sorted(maps.Keys(item)) {
			value := item[key]
			legacy, included := selected[operationKey{key, path}]
			excluded := len(selected) != 0 && !included
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
			// Deny an internal operation whatever its path, even one that is not a
			// valid template, such as /items{batch} or /items:batch, so no other
			// template can capture it.
			if visibility == visibilityInternal {
				if suffix, ok := strings.CutPrefix(path, binding.Mount); ok && strings.HasPrefix(suffix, "/") {
					*denied = append(*denied, operationKey{strings.ToUpper(key), binding.Prefix + suffix})
				}
			}
			publicPath, mapped := binding.publicPath(path)
			if mapped {
				shape := operationKey{strings.ToUpper(key), pathShape(path)}
				if other, exists := shapes[shape]; exists {
					return fmt.Errorf("%s %s and %s %s have the same path shape", key, other, key, path)
				}
				shapes[shape] = path
			}
			if excluded {
				// Like an internal operation, an unselected one counts as written,
				// even when its path is not a valid template.
				if suffix, ok := strings.CutPrefix(path, binding.Mount); ok && strings.HasPrefix(suffix, "/") && visibility != visibilityInternal {
					*passthrough = append(*passthrough, operationKey{strings.ToUpper(key), binding.Prefix + suffix})
				}
				continue
			}
			matched++
			if !mapped {
				if visibility == visibilityInternal {
					continue
				}
				return fmt.Errorf("invalid or unmapped public path %q: each segment must be a literal or a whole {name}", path)
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

// aliasTarget is a rewrite destination. key.path is the target's upstream
// path; assemble maps it to a public path with the binding the target is
// actually served with.
type aliasTarget struct {
	key     operationKey
	service string
}

// serviceUnit is one service's contract after per-service validation. It is
// the unit of isolation: the compiler keeps, replaces or drops whole units.
type serviceUnit struct {
	// binding is the effective binding the unit was compiled with.
	binding       serviceBinding
	digest        [sha256.Size]byte
	openAPIDigest [sha256.Size]byte
	native        map[operationKey]sourceOperation
	aliases       map[operationKey]aliasTarget
	denied        []operationKey
	passthrough   []operationKey
	// warnings lists operations a docs-only unit leaves out of the document
	// because its direct route would refuse them.
	warnings []string
}

const (
	servingCurrent  = "current"
	servingLastGood = "last-good"
	servingNone     = "none"
)

// Service states reported in /status.
const (
	stateServing           = "serving"
	stateServingLastGood   = "serving_last_good"
	stateNotInstalled      = "not_installed"
	stateDirectRouteClosed = "direct_route_closed"
)

type serviceOutcome struct {
	serving   string
	rejection string
	missing   bool
	// state and reason are set by the reconciler.
	state  string
	reason string
	// warnings describe rewrites denied although their target is served, and
	// operations a docs-only service leaves out of the document.
	warnings []string
	// route and publish are the service's effective binding settings.
	route, publish bool
	counts         serviceCounts
}

// compileReport describes what compile did with each service. accepted holds
// the units that are serving and becomes the next call's lastGood.
type compileReport struct {
	// overrides describes where a contract overrides its bindings entry.
	overrides map[string]string
	services  map[string]serviceOutcome
	accepted  map[string]*serviceUnit
}

// registrationDigest identifies everything a compiled unit depends on: the
// contract and its effective binding. Rewrite destinations are resolved against
// the served target binding in assemble, so they are not part of it.
func registrationDigest(reg registration, binding serviceBinding) [sha256.Size]byte {
	hash := sha256.New()
	visibility := "-"
	if reg.defaultVisibility != nil {
		visibility = string(*reg.defaultVisibility)
	}
	fmt.Fprintf(hash, "%q %q %q %q", reg.serviceName, reg.openAPI, reg.rewrites, visibility)
	encoded, _ := json.Marshal(binding)
	fmt.Fprintf(hash, " %s", encoded)
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
		binding:       binding,
		digest:        registrationDigest(reg, binding),
		openAPIDigest: sha256.Sum256([]byte(reg.openAPI)),
		native:        make(map[operationKey]sourceOperation),
		aliases:       make(map[operationKey]aliasTarget),
	}
	if !binding.routed() && len(rules) != 0 {
		return nil, errors.New("a service with route: false cannot define rewrites")
	}
	if err := readOperations(reg.serviceName, source, binding, fallback, bindings, unit.native, &unit.denied, &unit.passthrough); err != nil {
		return nil, err
	}
	if !binding.routed() {
		// A docs-only contract has no traffic effect: no routes and no denials.
		// Its service keeps its serviceRoutes entry. Only the operations it
		// documents are kept, so its component references are imported, and
		// checked, only when it publishes.
		unit.denied = nil
		for key, op := range unit.native {
			if op.visibility != visibilityPublic || !binding.published() {
				delete(unit.native, key)
				continue
			}
			op.unrouted = true
			unit.native[key] = op
		}
		if binding.published() {
			unit.warnings = omitRefusedOperations(unit.native, bindings.ServiceRoutes[binding.Prefix])
		}
	}
	if !binding.published() {
		for key, op := range unit.native {
			if op.visibility == visibilityPublic {
				op.visibility = visibilityUnlisted
				unit.native[key] = op
			}
		}
	}
	for _, rule := range rules {
		from := operationKey{rule.From.Method, rule.From.Path}
		_, approved := bindings.Services[rule.To.ServiceName]
		if !approved || !literalPath.MatchString(rule.To.Path) || !strings.HasPrefix(from.path, binding.Prefix+"/") ||
			!literalPath.MatchString(from.path) {
			return nil, errors.New("rewrite outside its registered service bindings")
		}
		if _, exists := unit.aliases[from]; exists {
			return nil, fmt.Errorf("duplicate rewrite for %s %s", from.method, from.path)
		}
		unit.aliases[from] = aliasTarget{operationKey{from.method, rule.To.Path}, rule.To.ServiceName}
	}
	return unit, nil
}

// compile builds one candidate from per-service contracts. Every contract is a
// candidate: its effective binding comes from the contract, with the bindings
// entry as the fallback. A service whose contract is invalid, resolves to no
// upstream or conflicts with another service is isolated: it keeps its entry
// in lastGood when it has one, and is otherwise omitted. Other services are
// unaffected.
func compile(regs []registration, bindings upstreamBindings, lastGood map[string]*serviceUnit) (candidate, compileReport) {
	defaultVisibility := visibilityPublic
	if bindings.DefaultVisibility != nil {
		defaultVisibility = *bindings.DefaultVisibility
	}
	report := compileReport{services: make(map[string]serviceOutcome), overrides: make(map[string]string)}
	sorted := slices.SortedStableFunc(slices.Values(regs), func(a, b registration) int {
		return strings.Compare(a.serviceName, b.serviceName)
	})
	count := make(map[string]int, len(sorted))
	created := make(map[string]time.Time, len(sorted))
	for _, reg := range sorted {
		count[reg.serviceName]++
		created[reg.serviceName] = reg.created
	}
	current := make(map[string]*serviceUnit)
	rejected := make(map[string]string)
	resolved := make(map[string]serviceBinding)
	for _, reg := range sorted {
		name := reg.serviceName
		switch {
		case count[name] > 1:
			rejected[name] = fmt.Sprintf("service %s: duplicate contract registrations", name)
		case reg.invalid != nil:
			rejected[name] = fmt.Sprintf("service %s: %v", name, reg.invalid)
		default:
			binding, note, err := resolveBinding(reg, bindings)
			if err != nil {
				rejected[name] = fmt.Sprintf("service %s: %v", name, err)
				continue
			}
			resolved[name] = binding
			if note != "" {
				report.overrides[name] = note
			}
		}
	}
	// Rewrites may target any service with a contract, so validate them against
	// the effective bindings.
	effective := maps.Clone(bindings.Services)
	if effective == nil {
		effective = make(map[string]serviceBinding)
	}
	for name := range count {
		if unit := lastGood[name]; unit != nil {
			effective[name] = unit.binding
		}
	}
	maps.Copy(effective, resolved)
	// Approve a rewrite target whichever way it fails: any registration counts.
	// Rewrites into a target that is not served stay denied in assemble.
	for name := range count {
		if _, known := effective[name]; !known {
			effective[name] = serviceBinding{}
		}
	}
	effectiveBindings := bindings
	effectiveBindings.Services = effective
	for _, reg := range sorted {
		name := reg.serviceName
		binding, ok := resolved[name]
		if !ok {
			continue
		}
		if prev := lastGood[name]; prev != nil && prev.digest == registrationDigest(reg, binding) {
			current[name] = prev
			continue
		}
		unit, err := compileService(reg, binding, effectiveBindings, defaultVisibility)
		if err != nil {
			rejected[name] = fmt.Sprintf("service %s: %v", name, err)
			continue
		}
		current[name] = unit
	}
	preferred := maps.Clone(current)
	for name := range rejected {
		if prev := lastGood[name]; prev != nil {
			preferred[name] = prev
		}
	}

	out, accepted, conflicts := selectUnits(preferred, lastGood, created, effectiveBindings)
	report.accepted = accepted
	for name := range count {
		binding, ok := resolved[name]
		if !ok {
			binding = bindings.Services[name]
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
			binding = unit.binding
			outcome.counts = out.counts[name]
			outcome.warnings = slices.Concat(slices.Sorted(slices.Values(out.aliasWarnings[name])), unit.warnings)
		}
		outcome.route, outcome.publish = binding.routed(), binding.published()
		report.services[name] = outcome
	}
	// Only bindings entries declare that a service must have a contract and
	// own a direct service route, so only they are reported missing or unserved.
	// A service with route: false keeps its traffic on serviceRoutes, so its
	// contract is optional.
	for _, name := range slices.Sorted(maps.Keys(bindings.Services)) {
		binding := bindings.Services[name]
		if !binding.routed() {
			continue
		}
		if count[name] == 0 {
			report.services[name] = serviceOutcome{serving: servingNone, missing: true, route: true, publish: binding.published()}
		}
		if binding.Prefix != "" && accepted[name] == nil {
			out.unserved = append(out.unserved, binding.Prefix)
		}
	}
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
	for _, name := range slices.Sorted(maps.Keys(report.accepted)) {
		unit := report.accepted[name]
		for _, from := range slices.SortedFunc(maps.Keys(unit.aliases), compareOperationKeys) {
			if target := unit.aliases[from].service; report.accepted[target] == nil {
				return out, fmt.Errorf("service %s: rewrite %s %s targets service %q without a contract", name, from.method, from.path, target)
			}
		}
	}
	return out, nil
}

// selectUnits assembles every preferred unit together. When that fails it
// starts from every service's last-good unit, which is valid because a subset
// of a previously valid set is valid. It then tries to upgrade each changed
// established service, then admits services that have no last-good unit, each
// group ordered by contract creation time (older first) and then service name.
// When admitting a unit fails, one unit is rejected and admission restarts
// from the seed without it, so every undo is re-validated. The rejected unit
// is the one being admitted, unless the failure lies in another unit that was
// itself admitted in this pass (for example a rewrite owner), which is
// rejected instead. A service with a last-good unit therefore ends up current
// or last-good, never omitted. The exception is a docs-only service (route:
// false): assemble blames it for any conflict with a routed service, and it
// is then rejected even with its last-good unit, so it can never cost a routed
// service its place. Among new contracts the older one wins. A pod
// that already serves last-good units may differ from a fresh pod when an old
// and a changed contract conflict.
func selectUnits(preferred, lastGood map[string]*serviceUnit, created map[string]time.Time, bindings upstreamBindings) (candidate, map[string]*serviceUnit, map[string]string) {
	if out, err := assemble(preferred, bindings, ""); err == nil {
		return out, preferred, nil
	}
	order := slices.SortedFunc(maps.Keys(preferred), func(a, b string) int {
		if c := created[a].Compare(created[b]); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	})
	conflicts := make(map[string]string)
	rejected := make(map[string]bool)
	seed := make(map[string]*serviceUnit)
	for _, name := range order {
		if unit := lastGood[name]; unit != nil {
			seed[name] = unit
		}
	}
	for {
		_, err := assemble(seed, bindings, "")
		if err == nil {
			break
		}
		// Cannot happen while bindings are fixed. Drop only the service at fault.
		bad := faultService(err)
		if _, present := seed[bad]; !present {
			clear(seed)
			break
		}
		conflicts[bad] = fmt.Sprintf("service %s: %v", bad, err)
		delete(seed, bad)
	}
restart:
	for {
		accepted := maps.Clone(seed)
		for _, established := range []bool{true, false} {
			for _, name := range order {
				unit := preferred[name]
				if (lastGood[name] != nil) != established || accepted[name] == unit || rejected[name] {
					continue
				}
				previous, had := accepted[name]
				accepted[name] = unit
				_, err := assemble(accepted, bindings, name)
				if err == nil {
					continue
				}
				if had {
					accepted[name] = previous
				} else {
					delete(accepted, name)
				}
				culprit := faultService(err)
				other, present := accepted[culprit]
				blameCulprit := culprit != "" && culprit != name && present
				if blameCulprit && !other.binding.routed() && unit.binding.routed() {
					// A docs-only culprit is blamed for any conflict with a routed
					// unit, so first check that the routed unit fits without it.
					// Otherwise the routed unit is at fault on its own.
					trial := maps.Clone(accepted)
					trial[name] = unit
					delete(trial, culprit)
					if _, alone := assemble(trial, bindings, name); alone != nil {
						blameCulprit, culprit, err = false, "", alone
					}
				}
				switch {
				case blameCulprit && other != lastGood[culprit]:
					conflicts[culprit] = fmt.Sprintf("service %s: %v", culprit, err)
					rejected[culprit] = true
				case blameCulprit && !other.binding.routed() && unit.binding.routed():
					// A docs-only service never holds its place against a routed
					// one, not even with its last good contract.
					conflicts[culprit] = fmt.Sprintf("service %s: %v", culprit, err)
					rejected[culprit] = true
					delete(seed, culprit)
				case culprit != "" && culprit != name:
					conflicts[name] = fmt.Sprintf("service %s: conflicts with service %s: %v", name, culprit, err)
					rejected[name] = true
				default:
					conflicts[name] = fmt.Sprintf("service %s: %v", name, err)
					rejected[name] = true
				}
				continue restart
			}
		}
		out, err := assemble(accepted, bindings, "")
		if err != nil {
			// Unreachable: every admitted step was validated. Fall back to the seed.
			out, _ = assemble(seed, bindings, "")
			return out, seed, conflicts
		}
		return out, accepted, conflicts
	}
}

// assemblyError names the service whose contract caused a cross-service
// failure, so the compiler can reject that service.
type assemblyError struct {
	service string
	err     error
}

func (e *assemblyError) Error() string { return e.err.Error() }
func (e *assemblyError) Unwrap() error { return e.err }

func faultService(err error) string {
	var fault *assemblyError
	if errors.As(err, &fault) {
		return fault.service
	}
	return ""
}

// assemble merges validated units into one candidate and runs the checks that
// span services: rewrites, route and OpenAPI endpoint conflicts, duplicate
// operationIds and component imports.
func assemble(units map[string]*serviceUnit, bindings upstreamBindings, prefer string) (candidate, error) {
	var out candidate
	unroutedDigests := make(map[string][sha256.Size]byte)
	native := make(map[operationKey]sourceOperation)
	aliases := make(map[operationKey]aliasTarget)
	// owners maps each rewrite to the service that defines it, and keyOwners
	// each public key to the service whose prefix it is under.
	owners := make(map[operationKey]string)
	keyOwners := make(map[operationKey]string)
	deniedBy := make(map[operationKey]string)
	deny := func(key operationKey, owner string) {
		out.denied = append(out.denied, key)
		deniedBy[key] = owner
	}
	components := make(map[string]map[string]any)
	out.contractServices = slices.Sorted(maps.Keys(units))
	out.services = make(map[string]serviceBinding, len(units))
	prefixOwners := make(map[string]string)
	for _, name := range out.contractServices {
		unit := units[name]
		out.services[name] = unit.binding
		if unit.binding.Prefix != "" {
			if other, taken := prefixOwners[unit.binding.Prefix]; taken {
				// A docs-only service never displaces a routed one. Otherwise blame
				// the service being admitted, else the later one.
				blamed, holder := name, other
				if routed := unit.binding.routed(); routed != units[other].binding.routed() {
					if routed {
						blamed, holder = other, name
					}
				} else if prefer == other {
					blamed, holder = other, name
				}
				return out, &assemblyError{blamed, fmt.Errorf("prefix %s is already used by service %s", unit.binding.Prefix, holder)}
			}
			prefixOwners[unit.binding.Prefix] = name
		}
		if !unit.binding.routed() {
			unroutedDigests[name] = unit.openAPIDigest
		}
		maps.Copy(native, unit.native)
		for key := range unit.native {
			keyOwners[key] = name
		}
		maps.Copy(aliases, unit.aliases)
		for from := range unit.aliases {
			owners[from] = name
			keyOwners[from] = name
		}
		for _, key := range unit.denied {
			deny(key, name)
		}
		out.passthrough = append(out.passthrough, unit.passthrough...)
	}

	published := make(map[operationKey]sourceOperation, len(native)+len(aliases))
	for key, op := range native {
		if op.visibility == visibilityInternal {
			deny(key, keyOwners[key])
		} else {
			published[key] = op
		}
	}
	// Check rewrites in a stable order, those owned by the service being
	// admitted first, so the reported fault does not depend on map order.
	aliasKeys := slices.SortedFunc(maps.Keys(aliases), compareOperationKeys)
	slices.SortStableFunc(aliasKeys, func(a, b operationKey) int {
		return cmpBool(owners[b] == prefer, owners[a] == prefer)
	})
	for _, from := range aliasKeys {
		alias := aliases[from]
		owner := owners[from]
		targetUnit, serving := units[alias.service]
		// A rewrite that cannot reach its served target is denied and reported
		// on its owner. It never faults a service, so the outcome does not
		// depend on arrival order or on what was served before.
		warn := func(format string, args ...any) {
			delete(published, from)
			deny(from, owner)
			if out.aliasWarnings == nil {
				out.aliasWarnings = make(map[string][]string)
			}
			out.aliasWarnings[owner] = append(out.aliasWarnings[owner], fmt.Sprintf(format, args...))
		}
		if !serving {
			// The target service has no serving contract. Deny the alias path so
			// it cannot reach a direct service route.
			if target, bound := bindings.Services[alias.service]; bound && !target.routed() {
				warn("rewrite %s %s targets service %s, which has route: false", from.method, from.path, alias.service)
				continue
			}
			delete(published, from)
			deny(from, owner)
			continue
		}
		if !targetUnit.binding.routed() {
			warn("rewrite %s %s targets service %s, which has route: false", from.method, from.path, alias.service)
			continue
		}
		destination, mapped := targetUnit.binding.publicPath(alias.key.path)
		if !mapped {
			warn("rewrite %s %s targets %s outside service %s", from.method, from.path, alias.key.path, alias.service)
			continue
		}
		to := operationKey{alias.key.method, destination}
		original := native[from]
		target, exists := native[to]
		if original.visibility == visibilityInternal || target.visibility == visibilityInternal {
			delete(published, from)
			deny(from, owner)
			continue
		}
		_, targetRewritten := aliases[to]
		if !exists || targetRewritten {
			warn("rewrite %s %s has missing or rewritten target %s", from.method, from.path, to.path)
			continue
		}
		// An unlisted source, or an owner that does not publish, keeps the
		// rewrite out of the document. An unlisted target already does.
		if original.visibility == visibilityUnlisted || !units[owner].binding.published() {
			target.visibility = visibilityUnlisted
		}
		// A rewrite keeps the SDK identity of the original public route.
		target.operationID = original.operationID
		published[from] = target
	}
	paths := make(map[string]map[string]any)
	operationIDs := make(map[string]operationKey)
	unlistedComponents := make(map[string]map[string]any)
	documentedSources := make(map[string]*sourceDoc)
	out.counts = make(map[string]serviceCounts, len(units))
	count := func(owner string, update func(*serviceCounts)) {
		counts := out.counts[owner]
		update(&counts)
		out.counts[owner] = counts
	}
	for _, key := range slices.SortedFunc(maps.Keys(published), compareOperationKeys) {
		source := published[key]
		if key.path == bindings.OpenAPI.YAMLPath || key.path == bindings.OpenAPI.JSONPath {
			return out, &assemblyError{source.service, fmt.Errorf("OpenAPI endpoint conflicts with route %s %s", key.method, key.path)}
		}
		if !source.unrouted {
			out.routes = append(out.routes, compiledOperation{key, source.service, source.path, source.credentials})
			count(keyOwners[key], func(c *serviceCounts) { c.routes++ })
		}
		operationComponents := components
		if source.visibility == visibilityUnlisted {
			operationComponents = unlistedComponents
		}
		normalized, err := importReferences(source.doc, source.service, *source.source, operationComponents)
		if err != nil {
			return out, &assemblyError{source.service, fmt.Errorf("%s %s: %w", key.method, key.path, err)}
		}
		if source.visibility == visibilityUnlisted {
			continue
		}
		documentedSources[source.service] = source.source
		if paths[key.path] == nil {
			paths[key.path] = make(map[string]any)
		}
		operation := normalized.(map[string]any)
		if err := applyTagOptions(operation, source.service, bindings.OpenAPI); err != nil {
			return out, &assemblyError{source.service, fmt.Errorf("%s %s: %w", key.method, key.path, err)}
		}
		security := make(securityRequirements, 0, len(source.requirements))
		for _, alternative := range source.requirements {
			for profile, scopes := range alternative {
				name, err := importComponent(source.service, "securitySchemes", profile, *source.source, components)
				if err != nil {
					return out, &assemblyError{source.service, err}
				}
				security = append(security, map[string][]string{name: scopes})
			}
		}
		operation["security"] = security
		if id := source.operationID; id != "" {
			if other, exists := operationIDs[id]; exists {
				// A docs-only service is at fault against a routed one. Otherwise
				// both are, so name neither.
				blamed := ""
				if first := published[other]; first.unrouted != source.unrouted {
					blamed = source.service
					if first.unrouted {
						blamed = first.service
					}
				}
				return out, &assemblyError{blamed, fmt.Errorf("duplicate operationId %q on %s %s and %s %s", id, other.method, other.path, key.method, key.path)}
			}
			operationIDs[id] = key
			operation["operationId"] = id
		}
		paths[key.path][strings.ToLower(key.method)] = operation
		count(keyOwners[key], func(c *serviceCounts) { c.documented++ })
	}
	for _, service := range slices.Sorted(maps.Keys(documentedSources)) {
		if err := mapImportedExtenders(service, *documentedSources[service], components); err != nil {
			return out, &assemblyError{service, err}
		}
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
	fmt.Fprintf(hash, "services %v\n", out.contractServices)
	for _, name := range out.contractServices {
		binding := units[name].binding
		fmt.Fprintf(hash, "upstream %s %s %s %s %s\n", name, binding.Origin, binding.Prefix, binding.Mount, binding.DebugOrigin)
	}
	for _, name := range slices.Sorted(maps.Keys(unroutedDigests)) {
		fmt.Fprintf(hash, "unrouted %s %x\n", name, unroutedDigests[name])
	}
	for _, route := range out.routes {
		fmt.Fprintf(hash, "%s %s => %s %s %v\n", route.key.method, route.key.path, route.service, route.path, route.credentials)
	}
	slices.SortFunc(out.denied, compareOperationKeys)
	out.denied = slices.Compact(out.denied)
	for _, key := range out.denied {
		fmt.Fprintf(hash, "internal %s %s\n", key.method, key.path)
		count(deniedBy[key], func(c *serviceCounts) { c.denied++ })
	}
	slices.SortFunc(out.passthrough, compareOperationKeys)
	for _, key := range out.passthrough {
		fmt.Fprintf(hash, "unselected %s %s\n", key.method, key.path)
	}
	out.revision = hex.EncodeToString(hash.Sum(nil))
	return out, nil
}

func cmpBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	default:
		return -1
	}
}

func compareOperationKeys(a, b operationKey) int {
	if cmp := strings.Compare(a.method, b.method); cmp != 0 {
		return cmp
	}
	return strings.Compare(a.path, b.path)
}
