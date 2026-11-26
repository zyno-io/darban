package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func anonymousContract(path, operationID string, extra ...string) string {
	return "openapi: 3.1.0\npaths:\n  " + path + ":\n    get:\n      operationId: " + operationID +
		"\n      security: []\n      x-darban-policy: anonymous\n" + strings.Join(extra, "") +
		"      responses: {'200': {description: OK}}\n"
}

func isolationBindings(names ...string) upstreamBindings {
	bindings := upstreamBindings{Hostname: "api.example.net", Services: map[string]serviceBinding{}}
	for _, name := range names {
		bindings.Services[name] = serviceBinding{Prefix: "/" + name, Origin: "http://" + name + ".fixtures.svc.cluster.local:80"}
	}
	return bindings
}

func contractFor(service, path, operationID string, extra ...string) registration {
	return registration{serviceName: service, openAPI: anonymousContract(path, operationID, extra...), rewrites: "[]"}
}

func routePaths(c candidate) []string {
	var paths []string
	for _, route := range c.routes {
		paths = append(paths, route.key.path)
	}
	return paths
}

func wantPaths(t *testing.T, c candidate, want ...string) {
	t.Helper()
	got := routePaths(c)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("routes = %v, want %v", got, want)
	}
}

func TestContractWithoutUpstreamOrBindingIsRejected(t *testing.T) {
	bindings := isolationBindings("alpha")
	regs := []registration{contractFor("alpha", "/items", "listAlpha"), contractFor("ghost", "/items", "listGhost")}
	got, report := compile(regs, bindings, nil)
	wantPaths(t, got, "/alpha/items")
	ghost := report.services["ghost"]
	if !strings.Contains(ghost.rejection, "no upstream") || ghost.serving != servingNone {
		t.Fatalf("unexpected ghost outcome: %+v", ghost)
	}
	if report.services["alpha"].rejection != "" || report.services["alpha"].serving != servingCurrent {
		t.Fatalf("unexpected alpha outcome: %+v", report.services["alpha"])
	}
	if strings.Join(got.contractServices, ",") != "alpha" {
		t.Fatalf("contractServices = %v", got.contractServices)
	}
}

func TestMissingContractOmitsServiceOnly(t *testing.T) {
	bindings := isolationBindings("alpha", "beta")
	got, report := compile([]registration{contractFor("alpha", "/items", "listAlpha")}, bindings, nil)
	wantPaths(t, got, "/alpha/items")
	if outcome := report.services["beta"]; !outcome.missing || outcome.serving != servingNone || outcome.rejection != "" {
		t.Fatalf("unexpected beta outcome: %+v", outcome)
	}
	// A missing contract is not served from a last-good copy.
	_, again := compile(nil, bindings, report.accepted)
	if len(again.accepted) != 0 {
		t.Fatalf("a removed contract stayed active: %v", again.accepted)
	}
}

func TestBadContractOnFreshStartDoesNotBlockOthers(t *testing.T) {
	bindings := isolationBindings("alpha", "beta")
	regs := []registration{
		contractFor("alpha", "/items", "listAlpha", "      x-darban-visibility: bogus\n"),
		contractFor("beta", "/items", "listBeta"),
	}
	got, report := compile(regs, bindings, nil)
	wantPaths(t, got, "/beta/items")
	if outcome := report.services["alpha"]; outcome.serving != servingNone || !strings.Contains(outcome.rejection, "service alpha:") ||
		!strings.Contains(outcome.rejection, "x-darban-visibility") {
		t.Fatalf("unexpected alpha outcome: %+v", outcome)
	}
	if report.services["beta"].serving != servingCurrent {
		t.Fatalf("unexpected beta outcome: %+v", report.services["beta"])
	}
}

func TestBadContractKeepsLastGoodAndOthersUpdate(t *testing.T) {
	bindings := isolationBindings("alpha", "beta")
	_, first := compile([]registration{
		contractFor("alpha", "/items", "listAlpha"), contractFor("beta", "/items", "listBeta"),
	}, bindings, nil)
	got, report := compile([]registration{
		contractFor("alpha", "/new-items", "listAlpha", "      x-darban-visibility: bogus\n"),
		contractFor("beta", "/new-items", "listBeta"),
	}, bindings, first.accepted)
	wantPaths(t, got, "/alpha/items", "/beta/new-items")
	if outcome := report.services["alpha"]; outcome.serving != servingLastGood || outcome.rejection == "" {
		t.Fatalf("unexpected alpha outcome: %+v", outcome)
	}
	if outcome := report.services["beta"]; outcome.serving != servingCurrent || outcome.rejection != "" {
		t.Fatalf("unexpected beta outcome: %+v", outcome)
	}
	// Fixing alpha returns it to the current contract.
	got, report = compile([]registration{
		contractFor("alpha", "/new-items", "listAlpha"), contractFor("beta", "/new-items", "listBeta"),
	}, bindings, report.accepted)
	wantPaths(t, got, "/alpha/new-items", "/beta/new-items")
	if report.services["alpha"].serving != servingCurrent {
		t.Fatalf("unexpected alpha outcome: %+v", report.services["alpha"])
	}
}

func TestCrossServiceConflictRejectsTheChangedContract(t *testing.T) {
	bindings := isolationBindings("alpha", "beta")
	_, first := compile([]registration{
		contractFor("alpha", "/items", "listAlpha"), contractFor("beta", "/items", "listBeta"),
	}, bindings, nil)
	// Alpha sorts first but beta is the changed contract, so beta loses.
	got, report := compile([]registration{
		contractFor("alpha", "/items", "listAlpha"), contractFor("beta", "/other", "listAlpha"),
	}, bindings, first.accepted)
	wantPaths(t, got, "/alpha/items", "/beta/items")
	if outcome := report.services["beta"]; outcome.serving != servingLastGood || !strings.Contains(outcome.rejection, `duplicate operationId "listAlpha"`) {
		t.Fatalf("unexpected beta outcome: %+v", outcome)
	}
	if report.services["alpha"].rejection != "" {
		t.Fatalf("unexpected alpha outcome: %+v", report.services["alpha"])
	}
	// On a fresh start both are new, so the first service name wins.
	got, report = compile([]registration{
		contractFor("beta", "/other", "same"), contractFor("alpha", "/items", "same"),
	}, bindings, nil)
	wantPaths(t, got, "/alpha/items")
	if report.services["beta"].serving != servingNone || report.services["beta"].rejection == "" {
		t.Fatalf("unexpected beta outcome: %+v", report.services["beta"])
	}
}

func TestStatusReportsRejectionsAndServingState(t *testing.T) {
	bindings := isolationBindings("alpha", "beta", "gamma")
	g := newGateway(bindings)
	var active atomic.Pointer[snapshot]
	var draining atomic.Bool
	clock := time.Date(2026, 11, 23, 9, 30, 0, 0, time.FixedZone("test", 3600))
	reload := &reconciler{gateway: g, active: &active, now: func() time.Time { return clock }}
	gamma := registration{serviceName: "gamma", openAPI: "openapi: 3.1.0\npaths: {}\n", rewrites: "[]"}
	regs := []registration{
		contractFor("alpha", "/items", "listAlpha", "      x-darban-visibility: bogus\n"),
		contractFor("beta", "/items", "listBeta"),
		contractFor("ghost", "/items", "listGhost"),
	}
	apply := func() { reload.apply(func() ([]registration, error) { return regs, nil }) }
	read := func(code int) map[string]contractStatus {
		t.Helper()
		response := httptest.NewRecorder()
		g.statusHandler(&active, &draining).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/status", nil))
		if response.Code != code {
			t.Fatalf("status %d: %s", response.Code, response.Body.String())
		}
		var report statusResponse
		if err := json.Unmarshal(response.Body.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		byName := make(map[string]contractStatus)
		for _, entry := range report.Contracts {
			byName[entry.Service] = entry
		}
		return byName
	}
	// A fresh pod with a rejected and a missing contract is ready and reports why.
	apply()
	if active.Load() == nil {
		t.Fatal("a fresh pod stayed unready with a rejected and a missing contract")
	}
	got := read(http.StatusOK)
	if alpha := got["alpha"]; alpha.Serving != servingNone || !alpha.Rejected || alpha.LastRejection == nil ||
		!strings.Contains(alpha.LastRejection.Message, "x-darban-visibility") || alpha.LastRejection.Time != "2026-11-23T08:30:00Z" {
		t.Fatalf("unexpected alpha status: %+v", got["alpha"])
	}
	if beta := got["beta"]; beta.Serving != servingCurrent || beta.Rejected || beta.LastRejection != nil {
		t.Fatalf("unexpected beta status: %+v", beta)
	}
	if ghost := got["ghost"]; !ghost.Rejected || ghost.Serving != servingNone {
		t.Fatalf("unexpected ghost status: %+v", ghost)
	}
	if gamma := got["gamma"]; !gamma.Missing || gamma.Serving != servingNone || gamma.Rejected {
		t.Fatalf("unexpected gamma status: %+v", gamma)
	}

	// Once every bound service is served the pod stays ready.
	regs = []registration{contractFor("alpha", "/items", "listAlpha"), contractFor("beta", "/items", "listBeta"), gamma}
	apply()
	read(http.StatusOK)

	// Alpha turns bad: the ready pod keeps serving last-good and reports it.
	clock = clock.Add(time.Hour)
	regs[0] = contractFor("alpha", "/changed", "listAlpha", "      x-darban-visibility: bogus\n")
	apply()
	if alpha := read(http.StatusOK)["alpha"]; alpha.Serving != servingLastGood || !alpha.Rejected || alpha.LastRejection.Time != "2026-11-23T09:30:00Z" {
		t.Fatalf("unexpected alpha status: %+v", alpha)
	}
	if _, ok := active.Load().routes[operationKey{http.MethodGet, "/alpha/items"}]; !ok {
		t.Fatal("last-good route is not active")
	}
	// Re-applying the same rejection keeps the same time.
	clock = clock.Add(time.Hour)
	apply()
	if alpha := read(http.StatusOK)["alpha"]; alpha.LastRejection.Time != "2026-11-23T09:30:00Z" {
		t.Fatalf("rejection time churned: %+v", alpha)
	}
	regs[0] = contractFor("alpha", "/items", "listAlpha")
	apply()
	if alpha := read(http.StatusOK)["alpha"]; alpha.Serving != servingCurrent || alpha.Rejected || alpha.LastRejection == nil {
		t.Fatalf("a fixed contract should keep its last rejection but not be rejected: %+v", alpha)
	}
}
