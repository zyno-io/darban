package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

const reportContract = `openapi: 3.1.0
paths:
  /items/{id}:
    get:
      operationId: getItem%[1]s
      security: [{account: []}]
      responses: {'200': {description: OK}}
    delete:
      operationId: deleteItem%[1]s
      security: [{account: []}]
      responses: {'200': {description: OK}}
  /public/{id}:
    get:
      operationId: getPublic%[1]s
      security: []
      x-darban-policy: anonymous
      responses: {'200': {description: OK}}
  /zrpc/{method}:
    post:
      x-darban-visibility: internal
  /admin/stats:
    get:
      x-darban-visibility: internal
  /hidden:
    get:
      operationId: hidden%[1]s
      x-darban-visibility: unlisted
      security: [{account: []}]
      responses: {'200': {description: OK}}
components:
  securitySchemes:
    account: {type: http, scheme: bearer}
`

// reportFixture has a docs-only service (talk), a routed service on a
// direct route with a selection, an extra route and a rewrite (suite), a
// routed service without a direct route (shop), and a rejected one (bad).
func reportFixture(t *testing.T, talkRoute bool) ([]registration, upstreamBindings) {
	t.Helper()
	authz := "http://authz.fixtures.svc.cluster.local:80"
	bindings := upstreamBindings{
		Hostname: "api.example.net", Authz: authz, Authorization: authorizationConfig{Path: "/authz"},
		OpenAPI: openAPIConfig{YAMLPath: "/openapi.yaml"},
		ServiceRoutes: map[string]serviceRoute{
			"/talk":  {Origin: "http://talk.fixtures.svc.cluster.local:80", PublicPaths: []string{"/public/*"}, DeniedPaths: []string{"/zrpc/*"}},
			"/suite": {Origin: "http://suite.fixtures.svc.cluster.local:80", AllowedPaths: []string{"/items/*", "/public/*", "/health"}},
		},
		Services: map[string]serviceBinding{
			"talk":  {Prefix: "/talk", Route: &talkRoute, Publish: new(false)},
			"suite": {Prefix: "/suite", Operations: []operationSelection{{Method: "get", Path: "/items/{id}"}}},
			"shop":  {Prefix: "/shop", Origin: "http://shop.fixtures.svc.cluster.local:80"},
			"bad":   {Prefix: "/bad", Origin: "http://bad.fixtures.svc.cluster.local:80"},
		},
	}
	if talkRoute {
		bindings.Services["talk"] = serviceBinding{Prefix: "/talk", Route: &talkRoute, Publish: new(false),
			ExtraRoutes: []extraRoute{{Method: "GET", Path: "/healthz", Auth: extraAuthNone}}}
	}
	suite := bindings.Services["suite"]
	suite.ExtraRoutes = []extraRoute{{Method: "GET", Path: "/health", Auth: extraAuthNone}}
	bindings.Services["suite"] = suite
	regs := []registration{
		{serviceName: "talk", openAPI: fmt.Sprintf(reportContract, "Talk"), rewrites: "[]"},
		{serviceName: "suite", openAPI: fmt.Sprintf(reportContract, "Suite"), rewrites: "[]"},
		{serviceName: "shop", openAPI: fmt.Sprintf(reportContract, "Shop"),
			rewrites: `[{from: {method: GET, path: /shop/old}, to: {serviceName: shop, path: /hidden}}]`},
		{serviceName: "bad", openAPI: strings.Replace(fmt.Sprintf(reportContract, "Bad"), "x-darban-policy: anonymous", "x-darban-policy: bogus", 1), rewrites: "[]"},
	}
	return regs, bindings
}

func TestReportGolden(t *testing.T) {
	for name, routed := range map[string]bool{"report-today.golden": false, "report-routed.golden": true} {
		regs, bindings := reportFixture(t, routed)
		var out bytes.Buffer
		ok, err := writeReport(&out, regs, bindings)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Errorf("%s: a rejected contract must fail the report", name)
		}
		path := filepath.Join("testdata", name)
		if os.Getenv("UPDATE_GOLDEN") != "" {
			if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if out.String() != string(want) {
			t.Errorf("%s differs; run with UPDATE_GOLDEN=1 and review the diff\n%s", name, out.String())
		}
		// The same input gives the same report.
		var again bytes.Buffer
		if _, err := writeReport(&again, regs, bindings); err != nil || again.String() != out.String() {
			t.Errorf("%s: report is not stable", name)
		}
	}
	// Without the rejected contract the report passes.
	regs, bindings := reportFixture(t, false)
	delete(bindings.Services, "bad")
	if ok, err := writeReport(new(bytes.Buffer), regs[:3], bindings); err != nil || !ok {
		t.Errorf("clean report: ok=%v err=%v", ok, err)
	}
}

func gzipContract(t *testing.T, service, upstream, yaml string) map[string]any {
	t.Helper()
	var packed bytes.Buffer
	writer := gzip.NewWriter(&packed)
	writer.Write([]byte(yaml))
	writer.Close()
	digest := sha256.Sum256([]byte(yaml))
	return map[string]any{
		"apiVersion": "darban.zyno.io/v1alpha1", "kind": "GatewayContract",
		"metadata": map[string]any{"name": contractNamePrefix + service, "namespace": testNamespace, "creationTimestamp": "2026-11-01T00:00:00Z"},
		"spec": map[string]any{"serviceName": service, "upstream": upstream,
			"openapi":  map[string]any{"gzipBase64": base64.StdEncoding.EncodeToString(packed.Bytes()), "sha256": hex.EncodeToString(digest[:])},
			"rewrites": []any{}},
	}
}

func TestLoadContractListDecodesLikeClusterMode(t *testing.T) {
	plain := plainGatewayContract("plain", anonymousContract("/items", "listPlain"))
	plain.SetNamespace(testNamespace)
	plain.Object["spec"].(map[string]any)["upstream"] = "http://plain:3000"
	broken := plainGatewayContract("broken", "openapi: 3.1.0\n")
	broken.Object["spec"].(map[string]any)["openapi"].(map[string]any)["sha256"] = "00"
	list := map[string]any{"apiVersion": "v1", "kind": "List", "items": []any{
		gzipContract(t, "zipped", "http://zipped:3000", anonymousContract("/items", "listZipped")),
		plain.Object, broken.Object,
	}}
	path := filepath.Join(t.TempDir(), "contracts.json")
	raw, _ := json.Marshal(list)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	regs, err := loadContractList(path)
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(regs, func(a, b registration) int { return strings.Compare(a.serviceName, b.serviceName) })
	if len(regs) != 3 || regs[0].serviceName != "broken" || regs[0].invalid == nil ||
		regs[2].serviceName != "zipped" || regs[2].upstream != "http://zipped:3000" || regs[2].namespace != testNamespace ||
		regs[2].created.IsZero() || !strings.Contains(regs[2].openAPI, "listZipped") {
		t.Fatalf("registrations %+v", regs)
	}
	compiled, report := compile(regs, contractOnlyBindings(), nil)
	wantPaths(t, compiled, "/plain/items", "/zipped/items")
	if report.services["broken"].rejection == "" {
		t.Fatal("a broken contract was not rejected on its own")
	}
	for name, body := range map[string]string{
		"not a list": `{"kind": "GatewayContract"}`,
		"other kind": `{"items": [{"kind": "ConfigMap", "metadata": {"name": "x"}}]}`,
		"not JSON":   `items: []`,
	} {
		os.WriteFile(path, []byte(body), 0o600)
		if _, err := loadContractList(path); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestShadowModeCountsWhatTheContractWouldDo(t *testing.T) {
	upstream := teapotUpstream(t)
	regs, bindings := reportFixture(t, false)
	route := bindings.ServiceRoutes["/talk"]
	route.Origin = upstream
	route.DeniedPaths = nil
	bindings.ServiceRoutes["/talk"] = route
	authz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer authz.Close()
	bindings.Authz = authz.URL
	h := newSkipHarness(t, bindings)
	h.apply(regs...)
	requests := []struct{ method, path string }{
		{"GET", "/talk/items/123e4567-e89b-12d3-a456-426614174000"},
		{"GET", "/talk/items/42"},
		{"GET", "/talk/public/7"},
		{"POST", "/talk/zrpc/doThing"},
		{"GET", "/talk/admin/stats"},
		{"GET", "/talk/undeclared/99/secret-token?key=abc"},
		{"GET", "/talk/a/b/c/d/e/f/g/h"},
	}
	var wait sync.WaitGroup
	for range 20 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for _, request := range requests {
				req := httptest.NewRequest(request.method, request.path, nil)
				req.Host = bindings.Hostname
				req.Header.Set("Authorization", "Bearer x")
				res := httptest.NewRecorder()
				h.g.serve(h.active.Load(), res, req)
			}
		}()
	}
	wait.Wait()
	shadow := h.status()["talk"].Shadow
	if shadow == nil {
		t.Fatal("no shadow status for a route: false service")
	}
	if shadow.Matched != 60 || shadow.WouldAuthorize != 40 || shadow.WouldSkipAuth != 20 || shadow.WouldDeny != 40 || shadow.Unmatched != 40 {
		t.Fatalf("shadow %+v", shadow)
	}
	want := []string{
		"unmatched GET /talk/a/b/c/d/e/...", "unmatched GET /talk/undeclared/{}/secret-token",
		"wouldAuthorize GET /talk/items/{id}", "wouldDeny GET /talk/admin/stats", "wouldDeny POST /talk/zrpc/{method}",
		"wouldSkipAuth GET /talk/public/{id}",
	}
	samples := slices.Sorted(slices.Values(shadow.Samples))
	if !slices.Equal(samples, want) {
		t.Fatalf("samples %q, want %q", samples, want)
	}
	for _, sample := range shadow.Samples {
		if strings.ContainsAny(sample, "?=") || strings.Contains(sample, "123e4567") || strings.Contains(sample, "42") {
			t.Errorf("sample leaks request data: %q", sample)
		}
	}
	// Routed services have no shadow.
	if h.status()["suite"].Shadow != nil {
		t.Error("a routed service has a shadow status")
	}
	// The traffic itself is unchanged: the route's own policy served it.
	req := httptest.NewRequest("GET", "/talk/undeclared/1", nil)
	req.Host = bindings.Hostname
	req.Header.Set("Authorization", "Bearer x")
	res := httptest.NewRecorder()
	h.g.serve(h.active.Load(), res, req)
	if res.Code == http.StatusNotFound {
		t.Error("shadow mode changed the traffic")
	}
}

func TestRedactPath(t *testing.T) {
	for raw, want := range map[string]string{
		"/talk/items/abc123":               "/talk/items/{}",
		"/talk/v2/items":                   "/talk/{}/items",
		"/talk/%73ecret":                   "/talk/{}",
		"/talk/Users/john.doe@example.com": "/talk/{}/{}",
		"/talk/a/b/c/d/e/f":                "/talk/a/b/c/d/e/...",
		"/talk/" + strings.Repeat("a", 40): "/talk/{}",
		"/talk/well-known_name.json":       "/talk/well-known_name.json",
	} {
		if got := redactPath(raw, ""); got != want {
			t.Errorf("%s: %s, want %s", raw, got, want)
		}
	}
}

func BenchmarkShadowObserve(b *testing.B) {
	operations := []shadowOperation{
		{operationKey{"GET", "/talk/items/{id}"}, true, false},
		{operationKey{"GET", "/talk/public/{id}"}, false, false},
		{operationKey{"POST", "/talk/zrpc/{method}"}, false, true},
	}
	shadow := newShadowTable("talk", operations, new(shadowRegistry).counters("talk"))
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			shadow.observe("GET", "/talk/items/42", "/talk/items/42", "", false)
		}
	})
}
