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
	"reflect"
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
// direct route with a selection and an extra route (suite), a routed service
// without a direct route and with rewrites (shop), a rejected contract on a
// direct route (bad), a routed direct route with no contract (hub), and a
// docs-only service with no contract that a rewrite targets (archive).
func reportFixture(t *testing.T, talkRoute bool) ([]registration, upstreamBindings) {
	t.Helper()
	authz := "http://authz.fixtures.svc.cluster.local:80"
	bindings := upstreamBindings{
		Hostname: "api.example.net", Authz: authz, Authorization: authorizationConfig{Path: "/authz"},
		OpenAPI: openAPIConfig{YAMLPath: "/openapi.yaml"},
		ServiceRoutes: map[string]serviceRoute{
			"/talk":  {Origin: "http://talk.fixtures.svc.cluster.local:80", PublicPaths: []string{"/public/*"}, DeniedPaths: []string{"/zrpc/*"}},
			"/suite": {Origin: "http://suite.fixtures.svc.cluster.local:80", AllowedPaths: []string{"/items/*", "/public/*", "/health"}},
			"/bad":   {Origin: "http://bad.fixtures.svc.cluster.local:80"},
			"/hub":   {Origin: "http://hub.fixtures.svc.cluster.local:80"},
		},
		Services: map[string]serviceBinding{
			"talk":    {Prefix: "/talk", Route: &talkRoute, Publish: new(false)},
			"suite":   {Prefix: "/suite", Operations: []operationSelection{{Method: "get", Path: "/items/{id}"}}},
			"shop":    {Prefix: "/shop", Origin: "http://shop.fixtures.svc.cluster.local:80"},
			"bad":     {Prefix: "/bad", Origin: "http://bad.fixtures.svc.cluster.local:80"},
			"hub":     {Prefix: "/hub"},
			"archive": {Prefix: "/archive", Route: new(false), Publish: new(false)},
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
			rewrites: `[{from: {method: GET, path: /shop/old}, to: {serviceName: shop, path: /hidden}},
				{from: {method: GET, path: /shop/archived}, to: {serviceName: archive, path: /items}}]`},
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
	// Without the rejected and missing contracts the report still fails, on
	// the rewrite into a service without a contract, as -print-spec does.
	regs, bindings := reportFixture(t, false)
	delete(bindings.Services, "bad")
	delete(bindings.Services, "hub")
	var out bytes.Buffer
	if ok, err := writeReport(&out, regs[:3], bindings); err != nil || ok || !strings.Contains(out.String(), "problem: service shop: rewrite GET /shop/archived") {
		t.Errorf("rewrite problem: ok=%v err=%v\n%s", ok, err, out.String())
	}
	if _, err := compileStrict(regs[:3], bindings); err == nil {
		t.Error("-print-spec accepts what -report refuses")
	}
	delete(bindings.Services, "archive")
	regs[2].rewrites = `[{from: {method: GET, path: /shop/old}, to: {serviceName: shop, path: /hidden}}]`
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
	other := gzipContract(t, "other", "http://other:3000", anonymousContract("/items", "listOther"))
	other["metadata"].(map[string]any)["namespace"] = "elsewhere"
	twice := gzipContract(t, "zipped", "http://zipped:3000", anonymousContract("/items", "listZipped"))
	for name, items := range map[string][]any{
		"two namespaces": {gzipContract(t, "zipped", "http://zipped:3000", anonymousContract("/items", "listZipped")), other},
		"listed twice":   {twice, twice},
	} {
		path := filepath.Join(t.TempDir(), "contracts.json")
		raw, _ := json.Marshal(map[string]any{"items": items})
		os.WriteFile(path, raw, 0o600)
		if _, err := loadContractList(path); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	plain := plainGatewayContract("plain", anonymousContract("/items", "listPlain"))
	plain.SetNamespace(testNamespace)
	plain.Object["spec"].(map[string]any)["upstream"] = "http://plain:3000"
	broken := plainGatewayContract("broken", "openapi: 3.1.0\n")
	broken.SetNamespace(testNamespace)
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

// shadowRig serves talk, a docs-only service on a direct route, with or
// without its contract, and records what the upstream receives.
type shadowRig struct {
	h        *skipHarness
	received []string
	mu       sync.Mutex
}

func newShadowRig(t *testing.T, withContract bool) *shadowRig {
	r := &shadowRig{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		r.mu.Lock()
		r.received = append(r.received, q.Method+" "+q.URL.RequestURI())
		r.mu.Unlock()
		w.Write([]byte("body " + q.URL.Path))
	}))
	authz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(upstream.Close)
	t.Cleanup(authz.Close)
	regs, bindings := reportFixture(t, false)
	route := bindings.ServiceRoutes["/talk"]
	route.Origin = upstream.URL
	bindings.ServiceRoutes["/talk"] = route
	bindings.Authz = authz.URL
	bindings.BrowserOrigins = []string{"https://app.example.net"}
	r.h = newSkipHarness(t, bindings)
	if withContract {
		r.h.apply(regs...)
	} else {
		r.h.apply(regs[1:]...)
	}
	return r
}

func (r *shadowRig) do(method, path string, headers map[string]string) (int, string) {
	req := httptest.NewRequest(method, path, nil)
	req.Host = "api.example.net"
	req.Header.Set("Authorization", "Bearer x")
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	res := httptest.NewRecorder()
	r.h.g.serve(r.h.active.Load(), res, req)
	return res.Code, res.Body.String()
}

var shadowRequests = []struct {
	method, path string
	headers      map[string]string
}{
	{"GET", "/talk/items/123e4567-e89b-12d3-a456-426614174000", nil},
	{"GET", "/talk/items/42", nil},
	{"GET", "/talk/public/7", nil},
	{"GET", "/talk/admin/stats", nil},
	{"POST", "/talk/zrpc/doThing", nil},
	{"GET", "/talk/undeclared/99/secret-token?key=abc", nil},
	{"GET", "/talk/users/jane.doe/items", nil},
	{"GET", "/talk/domains/acme-dental.com", nil},
	{"GET", "/talk/a/b/c/d/e/f/g/h", nil},
	{"BREW", "/talk/items/1", nil},
	{"OPTIONS", "/talk/items/1", map[string]string{"Origin": "https://app.example.net", "Access-Control-Request-Method": "SECRETVERB"}},
}

func TestShadowModeComparesTodayWithTheContract(t *testing.T) {
	r := newShadowRig(t, true)
	var wait sync.WaitGroup
	for range 20 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for _, request := range shadowRequests {
				r.do(request.method, request.path, request.headers)
			}
		}()
	}
	wait.Wait()
	shadow := r.h.status()["talk"].Shadow
	if shadow == nil {
		t.Fatal("no shadow status for a route: false service")
	}
	// Today zrpc is refused by deniedPaths. items/{id} needs authorization in
	// both, public/{id} is public today and anonymous in the contract, and the
	// internal admin/stats goes to the backend today.
	want := shadowStatus{RefusedToday: 20, Matched: 60, WouldDeny: 20, Unmatched: 100, WouldSkipAuth: 20, WouldAuthorize: 40}
	got := *shadow
	got.Samples, got.Overflow = nil, nil
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("shadow %+v, want %+v", got, want)
	}
	samples := map[string]uint64{}
	for kind, top := range shadow.Samples {
		for _, sample := range top {
			samples[kind+" "+sample.Sample] = sample.Count
		}
	}
	wantSamples := map[string]uint64{
		"wouldAuthorize GET /talk/items/{id}": 40, "wouldSkipAuth GET /talk/public/{id}": 20, "wouldDeny GET /talk/admin/stats": 20,
		"unmatched GET /talk/{}/{}/{}": 20, "unmatched GET /talk/{}/{}/items": 20, "unmatched GET /talk/{}/{}": 20,
		"unmatched GET /talk/{}/{}/{}/{}/{}/...": 20, "unmatched OTHER /talk/items/{}": 20,
	}
	if !reflect.DeepEqual(samples, wantSamples) {
		t.Fatalf("samples %v, want %v", samples, wantSamples)
	}
	for sample := range samples {
		for _, leak := range []string{"123e4567", "42", "99", "secret", "jane", "doe", "acme", "dental", "key", "BREW", "SECRETVERB"} {
			if strings.Contains(sample, leak) {
				t.Errorf("sample %q leaks %q", sample, leak)
			}
		}
	}
	if r.h.status()["suite"].Shadow != nil {
		t.Error("a routed service has a shadow status")
	}
}

func TestShadowModeLeavesTrafficUnchanged(t *testing.T) {
	with, without := newShadowRig(t, true), newShadowRig(t, false)
	if with.h.active.Load().shadow["/talk"] == nil || without.h.active.Load().shadow["/talk"] != nil {
		t.Fatal("unexpected shadow tables")
	}
	for _, request := range shadowRequests {
		with.received, without.received = nil, nil
		codeWith, bodyWith := with.do(request.method, request.path, request.headers)
		codeWithout, bodyWithout := without.do(request.method, request.path, request.headers)
		if codeWith != codeWithout || bodyWith != bodyWithout || !slices.Equal(with.received, without.received) {
			t.Errorf("%s %s: %d %q %v, without shadow %d %q %v", request.method, request.path,
				codeWith, bodyWith, with.received, codeWithout, bodyWithout, without.received)
		}
	}
}

func TestShadowCountsCountAuthorizationChangesAndReset(t *testing.T) {
	contract := shadowContract{digest: [32]byte{1}, operations: []shadowOperation{
		{operationKey{"GET", "/talk/open"}, false, false},
		{operationKey{"GET", "/talk/closed"}, true, false},
	}}
	registry := new(shadowRegistry)
	table := newShadowTable("talk", contract, registry.counters("talk", contract.digest))
	observe := func(path string, skipAuth bool) {
		table.observe(shadowRequest{method: "GET", raw: path, decoded: path, allowed: true, skipAuth: skipAuth})
	}
	observe("/talk/open", false)  // authorized today, anonymous in the contract
	observe("/talk/closed", true) // public today, protected in the contract
	observe("/talk/open", true)
	status := registry.status("talk")
	if status.NowAuthzWouldSkip != 1 || status.NowSkipWouldAuthorize != 1 || status.WouldSkipAuth != 2 || status.WouldAuthorize != 1 {
		t.Fatalf("status %+v", status)
	}
	// The same contract keeps its counts, a changed one starts over.
	if registry.counters("talk", contract.digest) != table.counters {
		t.Fatal("the same contract lost its counts")
	}
	if fresh := registry.counters("talk", [32]byte{2}); fresh == table.counters || registry.status("talk").Matched != 0 {
		t.Fatal("a changed contract kept the old counts")
	}
}

func TestShadowSamplesAreBounded(t *testing.T) {
	samples := &sampleCounts{}
	for i := range shadowSampleEntries + 50 {
		samples.add(fmt.Sprintf("GET /x/%d", i))
		samples.add("GET /hot")
	}
	if samples.size.Load() != shadowSampleEntries || samples.overflow.Load() != 51 {
		t.Fatalf("size %d overflow %d", samples.size.Load(), samples.overflow.Load())
	}
	if top := samples.top(3); top[0].Sample != "GET /hot" || top[0].Count != shadowSampleEntries+50 || len(top) != 3 {
		t.Fatalf("top %v", top)
	}
}

func TestShadowRedactionKeepsOnlyContractLiterals(t *testing.T) {
	table := newShadowTable("talk", shadowContract{operations: []shadowOperation{
		{operationKey{"GET", "/talk/items/{id}"}, true, false},
		{operationKey{"GET", "/talk/well-known/config.json"}, false, false},
	}}, newShadowCounters([32]byte{}))
	for raw, want := range map[string]string{
		"/talk/items/abc123":                     "/talk/items/{}",
		"/talk/users/jane.doe":                   "/talk/{}/{}",
		"/talk/domains/acme-dental.com":          "/talk/{}/{}",
		"/talk/grants/abcdefghij":                "/talk/{}/{}",
		"/talk/%69tems":                          "/talk/{}",
		"/talk/well-known/config.json/x":         "/talk/well-known/config.json/{}",
		"/talk/items/items/items/items/items/id": "/talk/items/items/items/items/items/...",
	} {
		if got := table.redact(raw, ""); got != want {
			t.Errorf("%s: %s, want %s", raw, got, want)
		}
	}
	if got := table.redact("/items/x", "/talk"); got != "/talk/items/{}" {
		t.Errorf("legacy host: %s", got)
	}
}

func BenchmarkShadowObserve(b *testing.B) {
	contract := shadowContract{operations: []shadowOperation{
		{operationKey{"GET", "/talk/items/{id}"}, true, false},
		{operationKey{"GET", "/talk/public/{id}"}, false, false},
		{operationKey{"POST", "/talk/zrpc/{method}"}, false, true},
	}}
	shadow := newShadowTable("talk", contract, new(shadowRegistry).counters("talk", contract.digest))
	request := shadowRequest{method: "GET", raw: "/talk/items/42", decoded: "/talk/items/42", allowed: true}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			shadow.observe(request)
		}
	})
}
