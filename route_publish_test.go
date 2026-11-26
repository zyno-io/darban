package main

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/yaml"
)

func TestPublishOnlyBindingsRequireADirectRoutePrefix(t *testing.T) {
	route := `"serviceRoutes": {"/talk": {"origin": "http://talk.fixtures.svc.cluster.local:80", "backendAuth": true}}`
	if err := writeBindings(t, `{"hostname": "api.example.net", `+route+`, "services": {"talk": {"prefix": "/talk", "route": false}}}`); err != nil {
		t.Fatalf("valid publish-only binding: %v", err)
	}
	for name, body := range map[string]string{
		"no prefix":         `{"hostname": "api.example.net", ` + route + `, "services": {"talk": {"route": false}}}`,
		"no direct route":   `{"hostname": "api.example.net", ` + route + `, "services": {"talk": {"prefix": "/other", "route": false}}}`,
		"mount":             `{"hostname": "api.example.net", ` + route + `, "services": {"talk": {"prefix": "/talk", "mount": "/api", "route": false}}}`,
		"operations":        `{"hostname": "api.example.net", ` + route + `, "services": {"talk": {"prefix": "/talk", "route": false, "operations": [{"method": "get", "path": "/x"}]}}}`,
		"unrouted selected": `{"hostname": "api.example.net", "services": {"talk": {"route": false, "publish": false, "operations": [{"method": "get", "path": "/x"}]}}}`,
	} {
		if err := writeBindings(t, body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

const talkContract = `openapi: 3.1.0
paths:
  /items:
    get:
      operationId: listItems
      security: []
      x-darban-policy: anonymous
      responses: {'200': {description: OK}}
  /hidden:
    get:
      operationId: hiddenItems
      x-darban-visibility: unlisted
      security: []
      x-darban-policy: anonymous
      responses: {'200': {description: OK}}
  /secret:
    get:
      x-darban-visibility: internal
`

func talkBindings(origin string, route, publish bool) upstreamBindings {
	return upstreamBindings{
		Hostname:      "api.example.net",
		Services:      map[string]serviceBinding{"talk": {Prefix: "/talk", Origin: origin, Route: &route, Publish: &publish}},
		ServiceRoutes: map[string]serviceRoute{"/talk": {Origin: origin, BackendAuth: true}},
	}
}

func documentedPaths(t *testing.T, c candidate) []string {
	t.Helper()
	var document struct {
		Paths map[string]map[string]any `json:"paths"`
	}
	if err := yaml.Unmarshal(c.specYAML, &document); err != nil {
		t.Fatal(err)
	}
	var paths []string
	for path, item := range document.Paths {
		for method := range item {
			paths = append(paths, strings.ToUpper(method)+" "+path)
		}
	}
	slices.Sort(paths)
	return paths
}

func TestRouteAndPublishCombinations(t *testing.T) {
	origin := teapotUpstream(t)
	secret := operationKey{"GET", "/talk/secret"}
	for _, test := range []struct {
		route, publish bool
		routes         []string
		documented     []string
		denied         bool
		secretStatus   int
	}{
		{true, true, []string{"/talk/hidden", "/talk/items"}, []string{"GET /talk/items"}, true, 404},
		{true, false, []string{"/talk/hidden", "/talk/items"}, nil, true, 404},
		{false, true, nil, []string{"GET /talk/items"}, false, 418},
		{false, false, nil, nil, false, 418},
	} {
		bindings := talkBindings(origin, test.route, test.publish)
		reg := registration{serviceName: "talk", openAPI: talkContract, rewrites: "[]"}
		got, report := compile([]registration{reg}, bindings, nil)
		label := fmt.Sprintf("route=%v publish=%v", test.route, test.publish)
		outcome := report.services["talk"]
		if outcome.serving != servingCurrent || outcome.rejection != "" || outcome.route != test.route || outcome.publish != test.publish {
			t.Fatalf("%s: outcome %+v", label, outcome)
		}
		wantPaths(t, got, test.routes...)
		if paths := documentedPaths(t, got); !slices.Equal(paths, test.documented) {
			t.Errorf("%s: documented %v, want %v", label, paths, test.documented)
		}
		if slices.Contains(got.denied, secret) != test.denied {
			t.Errorf("%s: denied %v", label, got.denied)
		}
		if !slices.Contains(got.contractServices, "talk") {
			t.Errorf("%s: contractServices %v", label, got.contractServices)
		}

		h := newSkipHarness(t, bindings)
		h.apply(reg)
		if code := h.get("/talk/secret"); code != test.secretStatus {
			t.Errorf("%s: GET /talk/secret = %d, want %d", label, code, test.secretStatus)
		}
		if code := h.get("/talk/items"); code != 418 {
			t.Errorf("%s: GET /talk/items = %d", label, code)
		}
		status := h.status()["talk"]
		wantDenied := 0
		if test.denied {
			wantDenied = 1
		}
		if status.Route != test.route || status.Publish != test.publish || status.Routes != len(test.routes) ||
			status.Documented != len(test.documented) || status.Denied != wantDenied || status.State != stateServing {
			t.Errorf("%s: status %+v", label, status)
		}
	}
}

func TestRejectedUnroutedContractLeavesTrafficAlone(t *testing.T) {
	bindings := talkBindings(teapotUpstream(t), false, false)
	good := registration{serviceName: "talk", openAPI: talkContract, rewrites: "[]"}
	bad := registration{serviceName: "talk", rewrites: "[]",
		openAPI: strings.Replace(talkContract, "x-darban-visibility: internal", "x-darban-visibility: bogus", 1)}
	for name, sequence := range map[string][]registration{"bad first": {bad}, "bad update": {good, bad}} {
		h := newSkipHarness(t, bindings)
		for _, reg := range sequence {
			h.apply(reg)
			for _, path := range []string{"/talk/items", "/talk/secret", "/talk/undeclared"} {
				if code := h.get(path); code != 418 {
					t.Errorf("%s: GET %s = %d", name, path, code)
				}
			}
		}
		if status := h.status()["talk"]; !status.Rejected || status.Route || status.LastRejection == nil {
			t.Errorf("%s: status %+v", name, status)
		}
	}
}

func TestPublishOnlyOmitsOperationsTheDirectRouteRefuses(t *testing.T) {
	op := func(path, security string) string {
		policy := "      security: [{bearerAuth: []}]\n"
		if security == "anonymous" {
			policy = "      security: []\n      x-darban-policy: anonymous\n"
		}
		return "  " + path + ":\n    get:\n" + policy + "      responses: {'200': {description: OK}}\n"
	}
	contract := "openapi: 3.1.0\npaths:\n" +
		op("/public/info", "anonymous") + // covered by publicPaths
		op("/public/{id}", "anonymous") + // a subtree covers every value
		op("/items/list", "protected") +
		op("/protected", "protected") +
		op("/items/{id}", "protected") + // may be /items/blocked
		op("/admin/users", "protected") + // denied subtree
		op("/other", "protected") + // outside allowedPaths
		op("/items/open", "anonymous") + // the gateway would require credentials
		"components:\n  securitySchemes:\n    bearerAuth: {type: http, scheme: bearer}\n"
	route := serviceRoute{
		Origin: "http://talk.fixtures.svc.cluster.local:80", AuthProfiles: []string{"bearerAuth"},
		PublicPaths:  []string{"/public/*"},
		AllowedPaths: []string{"/items/*", "/public/*", "/admin/*", "/protected"},
		DeniedPaths:  []string{"/admin/*", "/items/blocked"},
	}
	bindings := talkBindings(route.Origin, false, true)
	bindings.ServiceRoutes["/talk"] = route
	bindings.Authorization.Profiles = map[string]credentialProfile{"bearerAuth": {Scheme: "bearer"}}
	reg := registration{serviceName: "talk", openAPI: contract, rewrites: "[]"}
	got, report := compile([]registration{reg}, bindings, nil)
	outcome := report.services["talk"]
	if outcome.serving != servingCurrent || outcome.rejection != "" {
		t.Fatalf("outcome %+v", outcome)
	}
	want := []string{"GET /talk/items/list", "GET /talk/protected", "GET /talk/public/info", "GET /talk/public/{id}"}
	if paths := documentedPaths(t, got); !slices.Equal(paths, want) {
		t.Fatalf("documented %v, want %v", paths, want)
	}
	wantPaths(t, got)
	wantWarnings := map[string]string{
		"GET /talk/admin/users": "deniedPaths", "GET /talk/items/{id}": "deniedPaths",
		"GET /talk/other": "allowedPaths", "GET /talk/items/open": "publicPaths",
	}
	if len(outcome.warnings) != len(wantWarnings) || outcome.counts.documented != len(want) {
		t.Fatalf("warnings %q counts %+v", outcome.warnings, outcome.counts)
	}
	for _, warning := range outcome.warnings {
		key, _, _ := strings.Cut(warning, " omitted")
		if reason, ok := wantWarnings[key]; !ok || !strings.Contains(warning, reason) {
			t.Errorf("unexpected warning %q", warning)
		}
	}
	h := newSkipHarness(t, bindings)
	h.apply(reg)
	if status := h.status()["talk"]; len(status.Warnings) != len(wantWarnings) || status.Documented != len(want) {
		t.Errorf("status %+v", status)
	}

	// A backendAuth route accepts anonymous requests on every path.
	route.BackendAuth, route.AuthProfiles = true, nil
	bindings.ServiceRoutes["/talk"] = route
	got, report = compile([]registration{reg}, bindings, nil)
	if paths := documentedPaths(t, got); !slices.Contains(paths, "GET /talk/items/open") || len(report.services["talk"].warnings) != 3 {
		t.Fatalf("backendAuth: documented %v warnings %q", paths, report.services["talk"].warnings)
	}
}

func TestTemplateMatches(t *testing.T) {
	for _, test := range []struct {
		pattern, template string
		all, some         bool
	}{
		{"/a", "/a", true, true},
		{"/a", "/{x}", false, true},
		{"/a", "/a/b", false, false},
		{"/a/*", "/a", true, true},
		{"/a/*", "/a/{x}/c", true, true},
		{"/a/*", "/{x}/b", false, true},
		{"/a/*", "/b/{x}", false, false},
		{"/a/b/*", "/a", false, false},
		{"/", "/a", false, false},
	} {
		if all := templateMatches([]string{test.pattern}, test.template, true); all != test.all {
			t.Errorf("%s covers %s = %v", test.pattern, test.template, all)
		}
		if some := templateMatches([]string{test.pattern}, test.template, false); some != test.some {
			t.Errorf("%s may match %s = %v", test.pattern, test.template, some)
		}
	}
}

func TestDocsOnlyUnitNeverFaultsARoutedUnit(t *testing.T) {
	older := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := older.Add(time.Hour)

	// Duplicate operationId: the docs-only talk documents alpha's operationId.
	bindings := talkBindings("http://talk.fixtures.svc.cluster.local:80", false, true)
	bindings.Services["alpha"] = serviceBinding{Prefix: "/alpha", Origin: "http://alpha.fixtures.svc.cluster.local:80"}
	talk := contractFor("talk", "/items", "shared")
	alpha := contractFor("alpha", "/items", "shared")
	// Prefix conflict: the docs-only archive moves onto beta's prefix.
	prefixBindings := contractOnlyBindings()
	prefixBindings.Services["archive"] = serviceBinding{Prefix: "/archive", Origin: "http://archive.fixtures.svc.cluster.local:80",
		Route: new(false), Publish: new(false)}
	archive := contractFor("archive", "/items", "archiveItems")
	archive.prefix = "/beta"
	beta := clusterContract("beta", "/items", "betaItems", "http://beta", "")

	for _, conflict := range []struct {
		name            string
		bindings        upstreamBindings
		docsOnly, other registration
	}{
		{"operationId", bindings, talk, alpha},
		{"prefix", prefixBindings, archive, beta},
	} {
		docs, routed := conflict.docsOnly.serviceName, conflict.other.serviceName
		check := func(label string, report compileReport) {
			t.Helper()
			if outcome := report.services[routed]; outcome.serving != servingCurrent || outcome.rejection != "" {
				t.Errorf("%s %s: routed %s = %+v", conflict.name, label, routed, outcome)
			}
			if outcome := report.services[docs]; outcome.serving != servingNone || outcome.rejection == "" {
				t.Errorf("%s %s: docs-only %s = %+v", conflict.name, label, docs, outcome)
			}
		}
		for _, docsCreated := range []time.Time{older, newer} {
			d, r := conflict.docsOnly, conflict.other
			d.created, r.created = docsCreated, older.Add(30*time.Minute)
			for _, order := range [][]registration{{d, r}, {r, d}} {
				_, report := compile(order, conflict.bindings, nil)
				check("fresh", report)
			}
			// Each established alone, then the other arrives.
			for _, first := range []registration{d, r} {
				_, r1 := compile([]registration{first}, conflict.bindings, nil)
				_, r2 := compile([]registration{d, r}, conflict.bindings, r1.accepted)
				check("established "+first.serviceName, r2)
			}
		}
	}
}

func TestRewritesIntoUnroutedOrUnpublishedServices(t *testing.T) {
	bindings := talkBindings("http://talk.fixtures.svc.cluster.local:80", false, false)
	bindings.Services["alpha"] = serviceBinding{Prefix: "/alpha", Origin: "http://alpha.fixtures.svc.cluster.local:80"}
	bindings.Services["beta"] = serviceBinding{Prefix: "/beta", Origin: "http://beta.fixtures.svc.cluster.local:80", Publish: new(false)}
	alpha := registration{serviceName: "alpha", openAPI: anonymousContract("/items", "listAlpha"),
		rewrites: `[{from: {method: GET, path: /alpha/old}, to: {serviceName: talk, path: /items}},
			{from: {method: GET, path: /alpha/beta}, to: {serviceName: beta, path: /items}}]`}
	talk := contractFor("talk", "/items", "listTalk")
	beta := contractFor("beta", "/items", "listBeta")
	got, report := compile([]registration{alpha, talk, beta}, bindings, nil)
	if !slices.Contains(got.denied, operationKey{"GET", "/alpha/old"}) {
		t.Fatalf("rewrite into a route: false service is not denied: %v", got.denied)
	}
	if warnings := report.services["alpha"].warnings; len(warnings) != 1 || !strings.Contains(warnings[0], "route: false") {
		t.Fatalf("alpha warnings %q", warnings)
	}
	// beta does not publish, so the rewrite into it is routed but not documented.
	wantPaths(t, got, "/alpha/beta", "/alpha/items", "/beta/items")
	if paths := documentedPaths(t, got); !slices.Equal(paths, []string{"GET /alpha/items"}) {
		t.Fatalf("documented %v", paths)
	}
	if counts := report.services["alpha"].counts; counts != (serviceCounts{routes: 2, documented: 1, denied: 1}) {
		t.Fatalf("alpha counts %+v", counts)
	}

	// An owner that does not publish keeps its rewrites out too.
	bindings.Services["alpha"] = serviceBinding{Prefix: "/alpha", Origin: "http://alpha.fixtures.svc.cluster.local:80", Publish: new(false)}
	bindings.Services["beta"] = serviceBinding{Prefix: "/beta", Origin: "http://beta.fixtures.svc.cluster.local:80"}
	got, _ = compile([]registration{alpha, talk, beta}, bindings, nil)
	if paths := documentedPaths(t, got); !slices.Equal(paths, []string{"GET /beta/items"}) {
		t.Fatalf("documented %v", paths)
	}
}
