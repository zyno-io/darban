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
// reports false when a contract is rejected or missing.
//
// A route: false service's operations are evaluated against its direct
// route's rules, so the report shows the traffic of today. Compare it with a
// report for route: true to see what a cutover changes.
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
		case outcome.missing:
			state, ok = "missing", false
		case outcome.rejection != "":
			state, ok = "rejected", false
		}
		fmt.Fprintf(w, "service %s route=%v publish=%v state=%s routes=%d documented=%d denied=%d\n",
			name, outcome.route, outcome.publish, state, outcome.counts.routes, outcome.counts.documented, outcome.counts.denied)
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
				result := reportOutcome(key, name, binding, accepted, bindings, table)
				summary[result]++
				summary["operations"]++
				lines = append(lines, fmt.Sprintf("%s %s %s %s documented=%s -> %s", key.method, key.path, name, vis, yesNo(documented), result))
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(report.accepted)) {
		unit := report.accepted[name]
		for _, from := range slices.SortedFunc(maps.Keys(unit.aliases), compareOperationKeys) {
			target := unit.aliases[from]
			result := reportOutcome(from, name, unit.binding, true, bindings, table)
			summary[result]++
			summary["rewrites"]++
			lines = append(lines, fmt.Sprintf("%s %s %s rewrite to=%s:%s -> %s", from.method, from.path, name, target.service, target.key.path, result))
		}
		for _, extra := range unit.extras {
			result := reportOutcome(extra.key, name, unit.binding, true, bindings, table)
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
// internal, 404 unmatched, 404 route-rule (refused by the direct route's path
// rules), 503 closed (a routed service on a direct route without an accepted
// contract), or proxy with the authorization and the policy that serves it.
func reportOutcome(key operationKey, service string, binding serviceBinding, accepted bool, bindings upstreamBindings, table routeTable) string {
	route, direct := bindings.ServiceRoutes[binding.Prefix]
	servicePath := strings.TrimPrefix(key.path, binding.Prefix)
	byRoute := func() string {
		if !direct {
			return "404 unmatched"
		}
		if templateMatches(route.DeniedPaths, servicePath, false) ||
			len(route.AllowedPaths) > 0 && !templateMatches(route.AllowedPaths, servicePath, true) {
			return "404 route-rule"
		}
		auth := "authz"
		if route.BackendAuth || templateMatches(route.PublicPaths, servicePath, true) {
			auth = "backend"
		}
		return "proxy auth=" + auth + " via=service-route"
	}
	switch {
	case !binding.routed():
		return byRoute()
	case !accepted && direct:
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
		return byRoute()
	case entry.route.protected && direct && route.BackendAuth && entry.route.direct != "":
		return "proxy auth=backend via=contract"
	case entry.route.protected:
		return "proxy auth=authz via=contract"
	default:
		return "proxy auth=none via=contract"
	}
}

// summaryLabel turns an outcome such as "proxy auth=authz via=contract" into
// a summary label such as proxy-authz-contract.
var summaryLabel = strings.NewReplacer(" auth=", "-", " via=", "-", " ", "-")

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func oneLine(text string) string {
	return strings.Join(strings.Fields(text), " ")
}
