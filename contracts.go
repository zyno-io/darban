package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
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
	Hostname          string
	Authz             string
	Authorization     authorizationConfig
	Debug             debugConfig
	ContractAPIGroup  string
	Services          map[string]serviceBinding
	DefaultVisibility *operationVisibility
	OpenAPI           openAPIConfig
}

type openAPIConfig struct {
	YAMLPath                       string
	JSONPath                       string
	OmitOperationExtensionPrefixes []string
}

type operationVisibility string

const (
	visibilityPublic    operationVisibility = "public"
	visibilityUnlisted  operationVisibility = "unlisted"
	visibilityInternal  operationVisibility = "internal"
	visibilityExtension                     = "x-darban-visibility"
	policyExtension                         = "x-gateway-policy"
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

func readOperationID(op map[string]any, service string) (string, error) {
	value, exists := op["operationId"]
	if !exists {
		return "", nil
	}
	upstream, ok := value.(string)
	if !ok || strings.TrimSpace(upstream) == "" {
		return "", errors.New("operationId must be a non-empty string")
	}
	parts := strings.Split(service, "-")
	var id strings.Builder
	id.WriteString(parts[0])
	for _, part := range parts[1:] {
		id.WriteString(uppercaseFirst(part))
	}
	id.WriteString(uppercaseFirst(upstream))
	return id.String(), nil
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
	routes   []compiledOperation
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
	if len(security) != len(legacy.Source) || (security == nil) != (legacy.Source == nil) {
		return errors.New("legacy source security changed")
	}
	for _, expected := range legacy.Source {
		if !slices.ContainsFunc(security, func(actual map[string][]string) bool {
			return reflect.DeepEqual(actual, expected)
		}) {
			return errors.New("legacy source security changed")
		}
	}
	if source.Components == nil {
		source.Components = make(map[string]map[string]any)
	}
	if source.Components["securitySchemes"] == nil {
		source.Components["securitySchemes"] = make(map[string]any)
	}
	schemes := source.Components["securitySchemes"]
	requirements := make(securityRequirements, 0, len(legacy.Profiles))
	for _, name := range legacy.Profiles {
		profile, exists := allowed[name]
		if !exists {
			return fmt.Errorf("unknown legacy credential profile %q", name)
		}
		schemes[name] = map[string]any{"type": "http", "scheme": profile.Scheme}
		requirements = append(requirements, map[string][]string{name: {}})
	}
	op["security"] = requirements
	return nil
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

func readOperations(reg registration, binding serviceBinding, fallback operationVisibility, bindings upstreamBindings, native map[operationKey]sourceOperation) error {
	var source sourceDoc
	raw, err := yaml.YAMLToJSONStrict([]byte(reg.openAPI))
	if err != nil || json.Unmarshal(raw, &source) != nil {
		return errors.New("invalid OpenAPI YAML")
	}
	if !apiVersion.MatchString(source.OpenAPI) || source.Paths == nil {
		return errors.New("expected an OpenAPI 3.1 document with paths")
	}
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
			if len(selected) != 0 && !included {
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
			matched++
			visibility, err := readVisibility(op, fallback)
			if err != nil {
				return fmt.Errorf("%s %s: %w", key, path, err)
			}
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
			operationID, err := readOperationID(op, reg.serviceName)
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
				service:      reg.serviceName,
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

func compile(regs []registration, bindings upstreamBindings) (candidate, error) {
	var out candidate
	if len(regs) != len(bindings.Services) {
		return out, errors.New("contract set is incomplete or has unregistered services")
	}
	defaultVisibility := visibilityPublic
	if bindings.DefaultVisibility != nil {
		defaultVisibility = *bindings.DefaultVisibility
	}
	registered := make(map[string]bool)
	native := make(map[operationKey]sourceOperation)
	aliases := make(map[operationKey]operationKey)
	components := make(map[string]map[string]any)
	for _, reg := range regs {
		binding, exists := bindings.Services[reg.serviceName]
		if !exists || registered[reg.serviceName] {
			return out, fmt.Errorf("unknown or duplicate service %q", reg.serviceName)
		}
		registered[reg.serviceName] = true
		fallback := defaultVisibility
		if reg.defaultVisibility != nil {
			if !reg.defaultVisibility.valid() {
				return out, fmt.Errorf("service %s defaultVisibility must be public, unlisted, or internal", reg.serviceName)
			}
			fallback = *reg.defaultVisibility
		}
		if err := readOperations(reg, binding, fallback, bindings, native); err != nil {
			return out, fmt.Errorf("service %s: %w", reg.serviceName, err)
		}
		var rules []rewriteRule
		if err := yaml.UnmarshalStrict([]byte(reg.rewrites), &rules); err != nil || rules == nil {
			return out, fmt.Errorf("service %s requires a rewrites list", reg.serviceName)
		}
		for _, rule := range rules {
			from := operationKey{rule.From.Method, rule.From.Path}
			target, approved := bindings.Services[rule.To.ServiceName]
			destination, mapped := target.publicPath(rule.To.Path)
			if !approved || !mapped || !strings.HasPrefix(from.path, binding.Prefix+"/") ||
				!literalPath.MatchString(from.path) {
				return out, fmt.Errorf("service %s has a rewrite outside its registered service bindings", reg.serviceName)
			}
			if _, exists := aliases[from]; exists {
				return out, fmt.Errorf("duplicate rewrite for %s %s", from.method, from.path)
			}
			aliases[from] = operationKey{from.method, destination}
		}
	}

	published := make(map[operationKey]sourceOperation, len(native)+len(aliases))
	for key, op := range native {
		if op.visibility != visibilityInternal {
			published[key] = op
		}
	}
	for from, to := range aliases {
		original := native[from]
		target, exists := native[to]
		if original.visibility == visibilityInternal || target.visibility == visibilityInternal {
			delete(published, from)
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
	for key, source := range published {
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
	for _, route := range out.routes {
		fmt.Fprintf(hash, "%s %s => %s %s %v\n", route.key.method, route.key.path, route.service, route.path, route.credentials)
	}
	out.revision = hex.EncodeToString(hash.Sum(nil))
	return out, nil
}
