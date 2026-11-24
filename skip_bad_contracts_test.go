package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const badVisibility = "      x-darban-visibility: bogus\n"

type skipHarness struct {
	t      *testing.T
	g      *gateway
	active atomic.Pointer[snapshot]
	rec    *reconciler
}

func newSkipHarness(t *testing.T, bindings upstreamBindings) *skipHarness {
	h := &skipHarness{t: t, g: newGateway(bindings)}
	h.rec = &reconciler{gateway: h.g, active: &h.active}
	return h
}

func (h *skipHarness) apply(regs ...registration) {
	h.rec.apply(func() ([]registration, error) { return regs, nil })
}

func (h *skipHarness) get(path string) int {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = h.g.bindings.Hostname
	res := httptest.NewRecorder()
	h.g.serve(h.active.Load(), res, req)
	return res.Code
}

func (h *skipHarness) status() map[string]contractStatus {
	var draining atomic.Bool
	res := httptest.NewRecorder()
	h.g.statusHandler(&h.active, &draining).ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/status", nil))
	var report statusResponse
	if err := json.Unmarshal(res.Body.Bytes(), &report); err != nil {
		h.t.Fatal(err)
	}
	out := make(map[string]contractStatus)
	for _, entry := range report.Contracts {
		out[entry.Service] = entry
	}
	return out
}

func teapotUpstream(t *testing.T) string {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	t.Cleanup(upstream.Close)
	return upstream.URL
}

func originBindings(origin string, names ...string) upstreamBindings {
	bindings := upstreamBindings{Hostname: "api.example.net", Services: map[string]serviceBinding{}}
	for _, name := range names {
		bindings.Services[name] = serviceBinding{Prefix: "/" + name, Origin: origin}
	}
	return bindings
}

func TestBadFirstContractIsNotInstalledOthersServe(t *testing.T) {
	h := newSkipHarness(t, originBindings(teapotUpstream(t), "alpha", "beta"))
	h.apply(contractFor("alpha", "/items", "listAlpha", badVisibility), contractFor("beta", "/items", "listBeta"))
	if h.active.Load() == nil {
		t.Fatal("not ready")
	}
	if code := h.get("/alpha/items"); code != http.StatusNotFound {
		t.Errorf("bad first contract: %d, want 404", code)
	}
	if code := h.get("/beta/items"); code != http.StatusTeapot {
		t.Errorf("other service: %d, want 418", code)
	}
	got := h.status()
	if got["alpha"].State != stateNotInstalled || !got["alpha"].Rejected || !strings.Contains(got["alpha"].Reason, "x-darban-visibility") {
		t.Errorf("alpha status: %+v", got["alpha"])
	}
	if got["beta"].State != stateServing || got["beta"].Reason != "" {
		t.Errorf("beta status: %+v", got["beta"])
	}
}

func TestBadUpdateKeepsLastGoodUnit(t *testing.T) {
	h := newSkipHarness(t, originBindings(teapotUpstream(t), "alpha"))
	h.apply(contractFor("alpha", "/items", "listAlpha"))
	h.apply(contractFor("alpha", "/items", "listAlpha", badVisibility))
	if code := h.get("/alpha/items"); code != http.StatusTeapot {
		t.Fatalf("last good unit: %d, want 418", code)
	}
	alpha := h.status()["alpha"]
	if alpha.State != stateServingLastGood || !alpha.Rejected || !strings.Contains(alpha.Reason, "x-darban-visibility") {
		t.Fatalf("alpha status: %+v", alpha)
	}
}

func TestBoundServiceWithoutContractIs404(t *testing.T) {
	h := newSkipHarness(t, originBindings(teapotUpstream(t), "alpha", "beta"))
	h.apply(contractFor("beta", "/items", "listBeta"))
	if code := h.get("/alpha/items"); code != http.StatusNotFound {
		t.Fatalf("bound service without a contract: %d, want 404", code)
	}
	alpha := h.status()["alpha"]
	if alpha.State != stateNotInstalled || !alpha.Missing || alpha.Reason != "no GatewayContract" {
		t.Fatalf("alpha status: %+v", alpha)
	}
}

func TestDirectRouteWithoutGoodContractFailsClosedOnly(t *testing.T) {
	origin := teapotUpstream(t)
	bindings := directRouteBindings(origin)
	bindings.Services["other"] = serviceBinding{Prefix: "/other", Origin: origin}
	for name, regs := range map[string][]registration{
		"missing":  {contractFor("other", "/items", "listOther")},
		"rejected": {{serviceName: "catalog", rewrites: "[]", openAPI: strings.Replace(catalogGood, "x-gateway-policy: anonymous", "x-gateway-policy: bogus", 1)}, contractFor("other", "/items", "listOther")},
	} {
		h := newSkipHarness(t, bindings)
		h.apply(regs...)
		if code := h.get("/catalog/anything"); code != http.StatusServiceUnavailable {
			t.Errorf("%s: direct route %d, want 503", name, code)
		}
		if code := h.get("/other/items"); code != http.StatusTeapot {
			t.Errorf("%s: other service %d, want 418", name, code)
		}
		if code := h.get("/nothing/here"); code != http.StatusNotFound {
			t.Errorf("%s: unknown path %d, want 404", name, code)
		}
		catalog := h.status()["catalog"]
		if catalog.State != stateDirectRouteClosed || !strings.Contains(catalog.Reason, "503") {
			t.Errorf("%s: catalog status: %+v", name, catalog)
		}
	}
}

func TestDeletedContractTombstoneAndContractOnlyPrefix(t *testing.T) {
	origin := teapotUpstream(t)
	bindings := directRouteBindings(origin)
	bindings.Services["other"] = serviceBinding{Prefix: "/other", Origin: origin}
	h := newSkipHarness(t, bindings)
	catalog := registration{serviceName: "catalog", rewrites: "[]", openAPI: catalogGood}
	other := contractFor("other", "/items", "listOther")
	h.apply(catalog, other)
	if code := h.get("/catalog/prices"); code != http.StatusTeapot {
		t.Fatalf("served: %d", code)
	}
	h.apply(other)
	// Direct route keeps proxying; the deny list is retained.
	if code := h.get("/catalog/anything"); code != http.StatusTeapot {
		t.Errorf("tombstoned direct route: %d, want 418", code)
	}
	req := httptest.NewRequest(http.MethodPost, "/catalog/private/42", nil)
	req.Host = bindings.Hostname
	res := httptest.NewRecorder()
	h.g.serve(h.active.Load(), res, req)
	if res.Code != http.StatusNotFound {
		t.Errorf("internal operation after deletion: %d, want 404", res.Code)
	}
	if got := h.status()["catalog"]; got.State != stateNotInstalled || !strings.Contains(got.Reason, "retained deny list") {
		t.Errorf("catalog status: %+v", got)
	}
	// A deleted contract without a direct route simply stops serving its prefix.
	h.apply()
	if code := h.get("/other/items"); code != http.StatusNotFound {
		t.Errorf("deleted contract prefix: %d, want 404", code)
	}
}

func TestPodBecomesReadyWithBadOrNoContracts(t *testing.T) {
	bindings := originBindings(teapotUpstream(t), "alpha")
	bindings.ServiceRoutes = map[string]serviceRoute{"/alpha": {Origin: "http://alpha.fixtures.svc.cluster.local:80", BackendAuth: true}}
	for name, regs := range map[string][]registration{
		"bad contract": {contractFor("alpha", "/items", "listAlpha", badVisibility)},
		"zero":         nil,
	} {
		h := newSkipHarness(t, bindings)
		h.apply(regs...)
		snapshot := h.active.Load()
		if snapshot == nil {
			t.Fatalf("%s: pod did not become ready", name)
		}
		var draining atomic.Bool
		res := httptest.NewRecorder()
		h.g.statusHandler(&h.active, &draining).ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/status", nil))
		if res.Code != http.StatusOK {
			t.Errorf("%s: /status %d", name, res.Code)
		}
	}
}

func TestLocalManifestSkipsBrokenEntry(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "good.yaml", anonymousContract("/items", "listBeta"))
	writeTestFile(t, dir, "rewrites.yaml", "[]")
	manifest := writeTestFile(t, dir, "manifest.yaml", `contracts:
  - {serviceName: alpha, openapi.yaml: missing.yaml, rewrites.yaml: rewrites.yaml}
  - {serviceName: beta, openapi.yaml: good.yaml, rewrites.yaml: rewrites.yaml}
`)
	regs, err := loadLocal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	h := newSkipHarness(t, originBindings(teapotUpstream(t), "alpha", "beta"))
	h.rec.apply(func() ([]registration, error) { return regs, nil })
	if h.active.Load() == nil || h.get("/alpha/items") != http.StatusNotFound || h.get("/beta/items") != http.StatusTeapot {
		t.Fatal("broken local entry was not isolated")
	}
	if h.status()["alpha"].State != stateNotInstalled {
		t.Fatalf("alpha: %+v", h.status()["alpha"])
	}
}

func writeTestFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
