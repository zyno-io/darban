package main

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

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

func talkBindings(origin string, publish bool) upstreamBindings {
	return upstreamBindings{
		Hostname: "api.example.net",
		Services: map[string]serviceBinding{"talk": {Prefix: "/talk", Origin: origin, BackendAuth: true, Publish: &publish}},
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

func TestPublishOnlyChangesTheDocument(t *testing.T) {
	origin := teapotUpstream(t)
	secret := operationKey{"GET", "/talk/secret"}
	for _, test := range []struct {
		publish    bool
		documented []string
	}{
		{true, []string{"GET /talk/items"}},
		{false, nil},
	} {
		bindings := talkBindings(origin, test.publish)
		reg := registration{serviceName: "talk", openAPI: talkContract, rewrites: "[]"}
		got, report := compile([]registration{reg}, bindings, nil)
		label := fmt.Sprintf("publish=%v", test.publish)
		outcome := report.services["talk"]
		if outcome.serving != servingCurrent || outcome.rejection != "" || outcome.publish != test.publish {
			t.Fatalf("%s: outcome %+v", label, outcome)
		}
		wantPaths(t, got, "/talk/hidden", "/talk/items")
		if paths := documentedPaths(t, got); !slices.Equal(paths, test.documented) {
			t.Errorf("%s: documented %v, want %v", label, paths, test.documented)
		}
		if !slices.Contains(got.denied, secret) || !slices.Contains(got.contractServices, "talk") {
			t.Errorf("%s: denied %v contractServices %v", label, got.denied, got.contractServices)
		}

		h := newSkipHarness(t, bindings)
		h.apply(reg)
		for path, want := range map[string]int{"/talk/secret": 404, "/talk/undeclared": 404, "/talk/items": 418, "/talk/hidden": 418} {
			if code := h.get(path); code != want {
				t.Errorf("%s: GET %s = %d, want %d", label, path, code, want)
			}
		}
		status := h.status()["talk"]
		if status.Publish != test.publish || status.Routes != 2 || status.Documented != len(test.documented) ||
			status.Denied != 1 || status.State != stateServing {
			t.Errorf("%s: status %+v", label, status)
		}
	}
}

func TestRejectedContractWithoutLastGoodFailsClosed(t *testing.T) {
	origin := teapotUpstream(t)
	bad := registration{serviceName: "talk", rewrites: "[]",
		openAPI: strings.Replace(talkContract, "x-darban-visibility: internal", "x-darban-visibility: bogus", 1)}
	h := newSkipHarness(t, talkBindings(origin, true))
	h.apply(bad)
	for _, path := range []string{"/talk/items", "/talk/secret", "/talk/undeclared"} {
		if code := h.get(path); code != 503 {
			t.Errorf("GET %s = %d", path, code)
		}
	}
	if status := h.status()["talk"]; !status.Rejected || status.State != stateClosed || status.LastRejection == nil {
		t.Errorf("status %+v", status)
	}
}

func TestRewritesIntoUnpublishedOrMissingServices(t *testing.T) {
	bindings := talkBindings("http://talk.fixtures.svc.cluster.local:80", false)
	bindings.Services["alpha"] = serviceBinding{Prefix: "/alpha", Origin: "http://alpha.fixtures.svc.cluster.local:80"}
	bindings.Services["beta"] = serviceBinding{Prefix: "/beta", Origin: "http://beta.fixtures.svc.cluster.local:80", Publish: new(false)}
	alpha := registration{serviceName: "alpha", openAPI: anonymousContract("/items", "listAlpha"),
		rewrites: `[{from: {method: GET, path: /alpha/old}, to: {serviceName: talk, path: /items}},
			{from: {method: GET, path: /alpha/beta}, to: {serviceName: beta, path: /items}}]`}
	beta := contractFor("beta", "/items", "listBeta")
	// talk has no contract, so the rewrite into it is denied.
	got, report := compile([]registration{alpha, beta}, bindings, nil)
	if !slices.Contains(got.denied, operationKey{"GET", "/alpha/old"}) {
		t.Fatalf("rewrite into a service without a contract is not denied: %v", got.denied)
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
	got, _ = compile([]registration{alpha, beta}, bindings, nil)
	if paths := documentedPaths(t, got); !slices.Equal(paths, []string{"GET /beta/items"}) {
		t.Fatalf("documented %v", paths)
	}
}
