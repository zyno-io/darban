package main

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"sigs.k8s.io/yaml"
)

// writeReport writes what the gateway would do with a contract set and
// bindings, as a stable table for diffing two configurations: one line per
// service, contract operation, rewrite and extra route, then a summary. It
// reports false when a contract is rejected or a rewrite targets a service
// without a contract. A bound service without a contract shows as missing and
// fails closed, which is not an error.
//
// Each outcome comes from the snapshot's route table, so it is what a request
// for that template gets. Compare two reports to see what a change of
// contracts or bindings does.
func writeReport(w io.Writer, regs []registration, bindings upstreamBindings) (bool, error) {
	compiled, report := compile(regs, bindings, nil)
	active := newGateway(bindings).build(compiled)
	table := active.routeTable()
	var document struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if raw, err := yaml.YAMLToJSON(compiled.specYAML); err != nil || json.Unmarshal(raw, &document) != nil {
		return false, fmt.Errorf("cannot read the composed document: %v", err)
	}
	ok := true
	summary := map[string]int{}
	var lines []string
	byName := make(map[string]registration, len(regs))
	for _, reg := range regs {
		byName[reg.serviceName] = reg
	}

	for _, name := range slices.Sorted(maps.Keys(report.services)) {
		outcome := report.services[name]
		state := outcome.serving
		switch {
		case outcome.rejection != "":
			state, ok = "rejected", false
		case !outcome.enabled:
			state = "disabled"
		case outcome.missing:
			state = "missing"
		}
		fmt.Fprintf(w, "service %s publish=%v state=%s routes=%d documented=%d denied=%d\n",
			name, outcome.publish, state, outcome.counts.routes, outcome.counts.documented, outcome.counts.denied)
		if outcome.rejection != "" {
			fmt.Fprintf(w, "  rejected: %s\n", oneLine(outcome.rejection))
		}
		for _, warning := range outcome.warnings {
			fmt.Fprintf(w, "  warning: %s\n", oneLine(warning))
		}
		summary["services"]++
	}
	// The checks -print-spec applies beyond rejections.
	for _, problem := range rewritesWithoutContract(report) {
		fmt.Fprintf(w, "problem: %s\n", oneLine(problem))
		ok = false
	}

	for _, name := range slices.Sorted(maps.Keys(byName)) {
		reg := byName[name]
		binding, accepted := compiled.services[name]
		disabled := !bindings.Services[name].enabled() || accepted && !binding.enabled()
		if !accepted {
			binding, _, _ = resolveBinding(reg, bindings)
			if binding.Prefix == "" {
				binding.Prefix = "/" + name
			}
		}
		source, err := parseOpenAPI(reg.openAPI)
		if reg.invalid != nil || err != nil {
			continue
		}
		fallback := visibilityPublic
		if bindings.DefaultVisibility != nil {
			fallback = *bindings.DefaultVisibility
		}
		if reg.defaultVisibility != nil {
			fallback = *reg.defaultVisibility
		}
		for path, item := range source.Paths {
			for method, value := range item {
				if !slices.Contains([]string{"get", "post", "put", "patch", "delete", "head", "options", "trace"}, method) {
					continue
				}
				op, _ := value.(map[string]any)
				visibility, err := readVisibility(op, fallback)
				vis := string(visibility)
				if err != nil {
					vis = "invalid"
				}
				public := "(outside mount)" + path
				if suffix, mapped := strings.CutPrefix(path, binding.Mount); mapped && strings.HasPrefix(suffix, "/") {
					public = binding.Prefix + suffix
				}
				key := operationKey{strings.ToUpper(method), public}
				_, documented := document.Paths[public][method]
				_, bound := bindings.Services[name]
				result := reportOutcome(key, accepted, bound, table, compiled.services)
				if disabled {
					result = "503 disabled"
				}
				summary[result]++
				summary["operations"]++
				lines = append(lines, fmt.Sprintf("%s %s %s %s documented=%s -> %s", key.method, key.path, name, vis, yesNo(documented), result))
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(report.accepted)) {
		unit := report.accepted[name]
		outcome := func(key operationKey) string {
			if !unit.binding.enabled() {
				return "503 disabled"
			}
			return reportOutcome(key, true, true, table, compiled.services)
		}
		for _, from := range slices.SortedFunc(maps.Keys(unit.aliases), compareOperationKeys) {
			target := unit.aliases[from]
			result := outcome(from)
			summary[result]++
			summary["rewrites"]++
			lines = append(lines, fmt.Sprintf("%s %s %s rewrite to=%s:%s -> %s", from.method, from.path, name, target.service, target.key.path, result))
		}
		for _, extra := range unit.extras {
			result := outcome(extra.key)
			summary[result]++
			summary["extras"]++
			auth := extraAuthNone
			if extra.protected {
				auth = extraAuthGateway
			}
			lines = append(lines, fmt.Sprintf("%s %s %s extra auth=%s -> %s", extra.key.method, extra.key.path, name, auth, result))
		}
	}
	slices.SortFunc(lines, func(a, b string) int {
		fa, fb := strings.Fields(a), strings.Fields(b)
		if c := strings.Compare(fa[1], fb[1]); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	})
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	var counts []string
	for _, kind := range slices.Sorted(maps.Keys(summary)) {
		counts = append(counts, fmt.Sprintf("%s=%d", summaryLabel.Replace(kind), summary[kind]))
	}
	fmt.Fprintf(w, "summary ok=%v %s\n", ok, strings.Join(counts, " "))
	return ok, nil
}

// reportOutcome says what a request for an operation's template gets: 404
// internal, 404 unselected (left out by the service's operations), 404
// unmatched, 503 closed (a bound service without an accepted contract), 503
// disabled (set by the caller for a disabled service), or
// proxy with the authorization that applies: authz (the gateway's
// authorizer), none (an anonymous operation) or backend (a backendAuth
// service).
func reportOutcome(key operationKey, accepted, bound bool, table routeTable, services map[string]serviceBinding) string {
	switch {
	case !accepted && bound:
		return "503 closed"
	case !accepted:
		return "404 unmatched"
	}
	entry := table.lookup(key.method, strings.Split(strings.TrimPrefix(key.path, "/"), "/"))
	switch {
	case entry == nil:
		return "404 unmatched"
	case entry.kind == entryDenied:
		return "404 internal"
	case entry.kind == entryPassthrough:
		return "404 unselected"
	case entry.route.protected && services[entry.route.service].BackendAuth:
		return "proxy auth=backend"
	case entry.route.protected:
		return "proxy auth=authz"
	default:
		return "proxy auth=none"
	}
}

// summaryLabel turns an outcome such as "proxy auth=authz" into a summary
// label such as proxy-authz.
var summaryLabel = strings.NewReplacer(" auth=", "-", " ", "-")

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func oneLine(text string) string {
	return strings.Join(strings.Fields(text), " ")
}
