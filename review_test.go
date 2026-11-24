package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const catalogGood = `openapi: 3.1.0
paths:
  /prices:
    get:
      security: []
      x-gateway-policy: anonymous
      responses:
        "200": {description: OK}
  /private/{id}:
    post:
      x-darban-visibility: internal
`

func directRouteBindings(origin string) upstreamBindings {
	return upstreamBindings{
		Hostname: "api.example.net",
		Services: map[string]serviceBinding{
			"catalog": {Prefix: "/catalog", Origin: origin, Operations: []operationSelection{{Method: "get", Path: "/prices"}}},
		},
		ServiceRoutes: map[string]serviceRoute{"/catalog": {Origin: origin, BackendAuth: true}},
	}
}

func TestOmittedServiceFailsClosed(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusTeapot)
	}))
	defer upstream.Close()
	bindings := directRouteBindings(upstream.URL)
	g := newGateway(bindings)
	var active atomic.Pointer[snapshot]
	rec := &reconciler{gateway: g, active: &active}
	probe := func(method, path string) int {
		req := httptest.NewRequest(method, path, nil)
		req.Host = bindings.Hostname
		res := httptest.NewRecorder()
		g.serve(active.Load(), res, req)
		return res.Code
	}
	good := registration{serviceName: "catalog", rewrites: "[]", openAPI: catalogGood}
	bad := registration{serviceName: "catalog", rewrites: "[]", openAPI: strings.Replace(catalogGood, "x-gateway-policy: anonymous", "x-gateway-policy: bogus", 1)}

	// A fresh pod with only a bad contract becomes ready, but the direct route
	// fails closed because the internal operations are unknown.
	freshGateway := newGateway(bindings)
	fresh := &reconciler{gateway: freshGateway, active: new(atomic.Pointer[snapshot])}
	fresh.apply(func() ([]registration, error) { return []registration{bad}, nil })
	if fresh.active.Load() == nil {
		t.Fatal("fresh pod with a bad contract did not become ready")
	}
	freshReq := httptest.NewRequest(http.MethodPost, "/catalog/private/42", nil)
	freshReq.Host = bindings.Hostname
	freshRes := httptest.NewRecorder()
	freshGateway.serve(fresh.active.Load(), freshRes, freshReq)
	if freshRes.Code != http.StatusServiceUnavailable {
		t.Fatalf("fresh pod direct route returned %d, want 503", freshRes.Code)
	}

	rec.apply(func() ([]registration, error) { return []registration{good}, nil })
	if code := probe(http.MethodPost, "/catalog/private/42"); code != http.StatusNotFound {
		t.Fatalf("internal operation returned %d", code)
	}
	// A rejected update keeps last-good, including its deny list.
	rec.apply(func() ([]registration, error) { return []registration{bad}, nil })
	if code := probe(http.MethodPost, "/catalog/private/42"); code != http.StatusNotFound {
		t.Fatalf("internal operation returned %d while serving last-good", code)
	}
	// With the contract deleted the service is gone: the direct route fails
	// closed for everything, as on a fresh pod.
	rec.apply(func() ([]registration, error) { return nil, nil })
	if code := probe(http.MethodPost, "/catalog/private/42"); code != http.StatusServiceUnavailable {
		t.Errorf("internal operation returned %d after deletion, want 503", code)
	}
	if code := probe(http.MethodGet, "/catalog/anything"); code != http.StatusServiceUnavailable {
		t.Errorf("direct route returned %d after deletion, want 503", code)
	}
	if hits.Load() != 0 {
		t.Fatalf("upstream received %d requests", hits.Load())
	}
}

func TestNeverServedServiceFailsClosed(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer upstream.Close()
	bindings := directRouteBindings(upstream.URL)
	g := newGateway(bindings)
	compiled, _ := compile(nil, bindings, nil)
	for _, path := range []string{"/catalog/private/42", "/catalog/anything"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Host = bindings.Hostname
		res := httptest.NewRecorder()
		g.serve(g.build(compiled), res, req)
		if res.Code != http.StatusServiceUnavailable {
			t.Errorf("POST %s returned %d, want 503", path, res.Code)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("upstream received %d requests", hits.Load())
	}
}

func TestDeletedContractFailsLegacyAndPublicPathsClosed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer upstream.Close()
	bindings := directRouteBindings(upstream.URL)
	route := bindings.ServiceRoutes["/catalog"]
	route.PublicPaths = []string{"/public/*"}
	route.DeniedPaths = []string{"/zrpc/*"}
	route.LegacyHosts = []string{"catalog.example.net"}
	bindings.ServiceRoutes["/catalog"] = route
	g := newGateway(bindings)
	var active atomic.Pointer[snapshot]
	rec := &reconciler{gateway: g, active: &active}
	probe := func(host, path string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = host
		res := httptest.NewRecorder()
		g.serve(active.Load(), res, req)
		return res.Code
	}
	rec.apply(func() ([]registration, error) {
		return []registration{{serviceName: "catalog", rewrites: "[]", openAPI: catalogGood}}, nil
	})
	if got := probe("api.example.net", "/catalog/public/x"); got != http.StatusNoContent {
		t.Fatalf("served: %d", got)
	}
	for pass := 0; pass < 2; pass++ {
		rec.apply(func() ([]registration, error) { return nil, nil })
		for _, test := range []struct {
			host, path string
			want       int
		}{
			{"api.example.net", "/catalog/public/x", http.StatusServiceUnavailable},
			{"catalog.example.net", "/public/x", http.StatusServiceUnavailable},
			{"api.example.net", "/catalog/zrpc/x", http.StatusNotFound},
		} {
			if got := probe(test.host, test.path); got != test.want {
				t.Errorf("pass %d: %s%s returned %d, want %d", pass, test.host, test.path, got, test.want)
			}
		}
	}
}

func TestCascadingUndoNeverOmitsEstablishedService(t *testing.T) {
	bindings := isolationBindings("a", "m", "z")
	_, r1 := compile([]registration{
		contractFor("a", "/items", "x"), contractFor("m", "/items", "m"), contractFor("z", "/thing", "z"),
	}, bindings, nil)
	a2 := contractFor("a", "/items", "a-new")
	a2.rewrites = `[{from: {method: GET, path: /a/old}, to: {serviceName: z, path: /thing}}]`
	got, r2 := compile([]registration{a2, contractFor("m", "/items", "x"), contractFor("z", "/other", "z")}, bindings, r1.accepted)
	wantPaths(t, got, "/a/items", "/m/items", "/z/other")
	// z moved its operation, so a2's rewrite is denied and warned on a. Nothing
	// is undone: every service serves its current contract.
	for _, name := range []string{"a", "m", "z"} {
		if r2.services[name].serving != servingCurrent || r2.services[name].rejection != "" {
			t.Errorf("service %s: %+v", name, r2.services[name])
		}
	}
	if r2.services["a"].warning == "" || !slices.Contains(got.denied, operationKey{"GET", "/a/old"}) {
		t.Fatalf("a = %+v denied=%v", r2.services["a"], got.denied)
	}
}

func TestAliasFaultAttributionIsDeterministic(t *testing.T) {
	const bTwoOps = "openapi: 3.1.0\npaths:\n" +
		"  /x:\n    get:\n      operationId: bx\n      security: []\n      x-gateway-policy: anonymous\n      responses: {'200': {description: OK}}\n" +
		"  /y:\n    get:\n      operationId: by\n      security: []\n      x-gateway-policy: anonymous\n      responses: {'200': {description: OK}}\n"
	bindings := isolationBindings("a", "b", "c")
	c1 := contractFor("c", "/items", "c")
	c1.rewrites = `[{from: {method: GET, path: /c/old}, to: {serviceName: b, path: /y}}]`
	_, r1 := compile([]registration{contractFor("a", "/items", "a"), {serviceName: "b", openAPI: bTwoOps, rewrites: "[]"}, c1}, bindings, nil)
	if len(r1.accepted) != 3 {
		t.Fatalf("setup rejected: %v", r1.services)
	}
	outcomes := map[string]int{}
	for range 200 {
		a2 := contractFor("a", "/items", "a")
		a2.rewrites = `[{from: {method: GET, path: /a/old}, to: {serviceName: b, path: /x}}]`
		got, r2 := compile([]registration{a2, contractFor("b", "/z", "bz"), c1}, bindings, r1.accepted)
		outcomes[fmt.Sprintf("a=%s b=%s c=%s rev=%s", r2.services["a"].serving, r2.services["b"].serving, r2.services["c"].serving, got.revision)]++
	}
	if len(outcomes) != 1 {
		t.Fatalf("distinct outcomes: %v", outcomes)
	}
	for outcome := range outcomes {
		if !strings.HasPrefix(outcome, "a=current b=current c=current") {
			t.Fatalf("unexpected outcome %s", outcome)
		}
	}
}

func TestRegistrationOnlyDeploymentBecomesReadyWithoutContracts(t *testing.T) {
	bindings := upstreamBindings{Hostname: "api.example.net",
		Services:      map[string]serviceBinding{"archive": {Prefix: "/archive", RegistrationOnly: true}},
		ServiceRoutes: map[string]serviceRoute{"/archive": {Origin: "http://archive.default.svc.cluster.local:80", BackendAuth: true}}}
	var active atomic.Pointer[snapshot]
	rec := &reconciler{gateway: newGateway(bindings), active: &active}
	rec.apply(func() ([]registration, error) { return nil, nil })
	if active.Load() == nil {
		t.Fatal("not ready")
	}
}

func TestAliasToUnservedTargetIsDenied(t *testing.T) {
	bindings := upstreamBindings{Hostname: "api.example.net", Services: map[string]serviceBinding{
		"alpha": {Prefix: "/alpha", Origin: "http://alpha.fixtures.svc.cluster.local:80"}, "beta": {Prefix: "/beta", Origin: "http://beta.fixtures.svc.cluster.local:80"},
	}}
	alpha := registration{serviceName: "alpha", openAPI: anonymousContract("/items", "listAlpha"),
		rewrites: `[{from: {method: GET, path: /alpha/old}, to: {serviceName: beta, path: /thing}}]`}
	betaBad := registration{serviceName: "beta", rewrites: "[]", openAPI: "openapi: 3.0.0\npaths: {}\n"}
	got, _ := compile([]registration{alpha, betaBad}, bindings, nil)
	if !slices.Contains(got.denied, operationKey{"GET", "/alpha/old"}) {
		t.Fatalf("alias to an unserved target is not denied: %v", got.denied)
	}
	wantPaths(t, got, "/alpha/items")
	if !slices.Equal(got.unserved, []string{"/beta"}) {
		t.Fatalf("unserved = %v", got.unserved)
	}
}

func TestEstablishedServiceSurvivesNewerConflict(t *testing.T) {
	bindings := isolationBindings("alpha", "beta")
	_, r1 := compile([]registration{contractFor("alpha", "/items", "a1"), contractFor("beta", "/items", "dup")}, bindings, nil)
	// Alpha takes beta's operationId and loses.
	_, r2 := compile([]registration{contractFor("alpha", "/items", "dup"), contractFor("beta", "/items", "dup")}, bindings, r1.accepted)
	if r2.services["alpha"].serving != servingLastGood {
		t.Fatalf("alpha = %+v", r2.services["alpha"])
	}
	// Beta changes while alpha's conflicting contract is still pending.
	got, r3 := compile([]registration{contractFor("alpha", "/items", "dup"), contractFor("beta", "/items2", "dup")}, bindings, r2.accepted)
	wantPaths(t, got, "/alpha/items", "/beta/items2")
	if r3.services["beta"].serving != servingCurrent || r3.services["alpha"].serving != servingLastGood {
		t.Fatalf("alpha=%+v beta=%+v", r3.services["alpha"], r3.services["beta"])
	}
}

func TestBrokenRewriteIsDeniedAndWarnedOnItsOwner(t *testing.T) {
	bindings := isolationBindings("alpha", "beta")
	broken := registration{serviceName: "alpha", openAPI: anonymousContract("/items", "listAlpha"),
		rewrites: `[{from: {method: GET, path: /alpha/old}, to: {serviceName: beta, path: /missing}}]`}
	beta := contractFor("beta", "/items", "listBeta")
	got, report := compile([]registration{broken, beta}, bindings, nil)
	wantPaths(t, got, "/alpha/items", "/beta/items")
	if report.services["alpha"].serving != servingCurrent || report.services["alpha"].warning == "" ||
		report.services["beta"].serving != servingCurrent || !slices.Contains(got.denied, operationKey{"GET", "/alpha/old"}) {
		t.Fatalf("alpha=%+v beta=%+v", report.services["alpha"], report.services["beta"])
	}
	// The same on an established pod.
	_, r1 := compile([]registration{contractFor("alpha", "/items", "listAlpha"), beta}, bindings, nil)
	got2, r2 := compile([]registration{broken, beta}, bindings, r1.accepted)
	if r2.services["alpha"].serving != servingCurrent || r2.services["alpha"].warning == "" || got2.revision != got.revision {
		t.Fatalf("alpha = %+v", r2.services["alpha"])
	}
	// A change that removes a target an established rewrite needs only denies
	// the rewrite. Neither service is rejected.
	rewrite := registration{serviceName: "alpha", openAPI: anonymousContract("/items", "listAlpha"),
		rewrites: `[{from: {method: GET, path: /alpha/old}, to: {serviceName: beta, path: /items}}]`}
	_, s1 := compile([]registration{rewrite, beta}, bindings, nil)
	moved := contractFor("beta", "/moved", "listBeta")
	got, s2 := compile([]registration{rewrite, moved}, bindings, s1.accepted)
	if s2.services["beta"].serving != servingCurrent || s2.services["alpha"].serving != servingCurrent || s2.services["alpha"].warning == "" {
		t.Fatalf("alpha=%+v beta=%+v", s2.services["alpha"], s2.services["beta"])
	}
	wantPaths(t, got, "/alpha/items", "/beta/moved")
}

func TestConflictOrderUsesCreationTimeThenName(t *testing.T) {
	bindings := isolationBindings("alpha", "beta")
	newer := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	older := newer.Add(-time.Hour)
	alpha, beta := contractFor("alpha", "/items", "same"), contractFor("beta", "/other", "same")
	beta.created, alpha.created = older, newer
	got, report := compile([]registration{alpha, beta}, bindings, nil)
	wantPaths(t, got, "/beta/other")
	if report.services["alpha"].serving != servingNone {
		t.Fatalf("alpha = %+v", report.services["alpha"])
	}
	beta.created = newer
	got, _ = compile([]registration{beta, alpha}, bindings, nil)
	wantPaths(t, got, "/alpha/items")

	// A pod that already serves alpha keeps it even if beta's contract is older,
	// so a running pod and a fresh pod can differ for old-versus-changed conflicts.
	beta.created = older
	_, first := compile([]registration{contractFor("alpha", "/items", "alpha-only"), contractFor("beta", "/other", "beta-only")}, bindings, nil)
	got, report = compile([]registration{alpha, beta}, bindings, first.accepted)
	wantPaths(t, got, "/alpha/items", "/beta/other")
	if report.services["alpha"].serving != servingLastGood || report.services["beta"].serving != servingCurrent {
		t.Fatalf("alpha=%+v beta=%+v", report.services["alpha"], report.services["beta"])
	}
}

func TestFirstSnapshotNeverWaitsOnContracts(t *testing.T) {
	bindings := isolationBindings("alpha", "beta")
	for name, regs := range map[string][]registration{
		"no contracts":     nil,
		"missing contract": {contractFor("alpha", "/items", "listAlpha")},
		"rejected contract": {contractFor("alpha", "/items", "listAlpha"),
			contractFor("beta", "/items", "listBeta", "      x-darban-visibility: bogus\n")},
	} {
		var active atomic.Pointer[snapshot]
		rec := &reconciler{gateway: newGateway(bindings), active: &active}
		rec.apply(func() ([]registration, error) { return regs, nil })
		if active.Load() == nil {
			t.Fatalf("%s: pod did not become ready", name)
		}
	}
	var active atomic.Pointer[snapshot]
	rec := &reconciler{gateway: newGateway(bindings), active: &active}
	apply := func(regs ...registration) { rec.apply(func() ([]registration, error) { return regs, nil }) }
	apply(contractFor("alpha", "/items", "listAlpha"), contractFor("beta", "/items", "listBeta"))
	// Once ready, a bad contract keeps last-good and a deletion drops the service.
	apply(contractFor("alpha", "/items", "listAlpha"), contractFor("beta", "/items", "listBeta", "      x-darban-visibility: bogus\n"))
	if active.Load() == nil || len(active.Load().routes) != 2 {
		t.Fatal("running pod lost last-good routes")
	}
	apply(contractFor("alpha", "/items", "listAlpha"))
	if s := active.Load(); !slices.Equal(s.contractServices, []string{"alpha"}) || len(s.routes) != 1 {
		t.Fatalf("snapshot is stale: %v", s.contractServices)
	}
}

func TestSecurityRequirementSetsMatchBothWays(t *testing.T) {
	a := securityRequirements{{"sessionBearer": {}}, {"clientBasic": {}}}
	if !sameRequirementSet(a, securityRequirements{{"clientBasic": nil}, {"sessionBearer": {}}}) {
		t.Fatal("order or nil scopes changed the result")
	}
	if sameRequirementSet(securityRequirements{{"sessionBearer": {}}, {"sessionBearer": {}}}, a) ||
		sameRequirementSet(a, securityRequirements{{"sessionBearer": {}}, {"sessionBearer": {}}}) {
		t.Fatal("a duplicate matched a distinct set")
	}
	allowed := fixtureAuthorization().Profiles
	legacy := &legacySecurity{Source: securityRequirements{{"staffBearer": {}}}, Profiles: []string{"sessionBearer", "sessionBearer"}}
	op := map[string]any{"security": []any{map[string]any{"sessionBearer": []any{}}, map[string]any{"clientBasic": []any{}}}}
	source := &sourceDoc{}
	if err := applyLegacySecurity(op, source, legacy, allowed); err == nil {
		t.Fatal("a superset was accepted as the native target")
	}
	if err := legacy.validate(); err == nil {
		t.Fatal("duplicate profiles accepted")
	}
	dupSource := &legacySecurity{Source: securityRequirements{{"a": {}}, {"a": {}}}, Profiles: []string{"sessionBearer"}}
	if err := dupSource.validate(); err == nil {
		t.Fatal("duplicate source requirements accepted")
	}
	raw := `{"hostname":"api.example.net","services":{"alpha":{"prefix":"/alpha","origin":"http://localhost:1",` +
		`"operations":[{"method":"get","path":"/x","legacy":{"source":[{"a":[]}],"profiles":["p","p"]}}]}}}`
	path := filepath.Join(t.TempDir(), "bindings.json")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBindings(path, true); err == nil || !strings.Contains(err.Error(), "duplicate legacy profiles") {
		t.Fatalf("loadBindings = %v", err)
	}
}

func TestRevisionTracksServingServices(t *testing.T) {
	bindings := isolationBindings("alpha", "gamma")
	empty := registration{serviceName: "gamma", rewrites: "[]", openAPI: "openapi: 3.1.0\npaths: {}\n"}
	both, _ := compile([]registration{contractFor("alpha", "/items", "listAlpha"), empty}, bindings, nil)
	one, _ := compile([]registration{contractFor("alpha", "/items", "listAlpha")}, bindings, nil)
	if both.revision == one.revision {
		t.Fatal("revision ignores which services serve")
	}
}

func TestStrictRejectsRewriteToServiceWithoutContract(t *testing.T) {
	bindings := upstreamBindings{Hostname: "api.example.net", Services: map[string]serviceBinding{
		"alpha": {Prefix: "/alpha", Origin: "http://alpha.fixtures.svc.cluster.local:80"}, "archive": {Prefix: "/archive", RegistrationOnly: true},
	}}
	alpha := registration{serviceName: "alpha", openAPI: anonymousContract("/items", "listAlpha"),
		rewrites: `[{from: {method: GET, path: /alpha/old}, to: {serviceName: archive, path: /thing}}]`}
	if _, err := compileStrict([]registration{alpha}, bindings); err == nil {
		t.Fatal("rewrite to a service without a contract was accepted")
	}
}

func TestRejectionMessagesAreStable(t *testing.T) {
	bindings := isolationBindings("alpha")
	raw := "openapi: 3.1.0\npaths:\n"
	for _, path := range []string{"/a", "/b", "/c", "/d"} {
		raw += "  " + path + ":\n    get:\n      x-darban-visibility: bogus\n    post:\n      x-darban-visibility: bogus\n"
	}
	reg := registration{serviceName: "alpha", openAPI: raw, rewrites: "[]"}
	seen := map[string]bool{}
	for range 50 {
		_, report := compile([]registration{reg}, bindings, nil)
		seen[report.services["alpha"].rejection] = true
	}
	if len(seen) != 1 {
		t.Fatalf("%d distinct messages: %v", len(seen), seen)
	}
}
