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
		"\n      security: []\n      x-gateway-policy: anonymous\n" + strings.Join(extra, "") +
		"      responses: {'200': {description: OK}}\n"
}

func isolationBindings(names ...string) upstreamBindings {
	bindings := upstreamBindings{Hostname: "api.example.net", Services: map[string]serviceBinding{}}
	for _, name := range names {
		bindings.Services[name] = serviceBinding{Prefix: "/" + name}
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

func TestUnregisteredServiceContractIsIgnored(t *testing.T) {
	bindings := isolationBindings("alpha")
	regs := []registration{contractFor("alpha", "/items", "listAlpha"), contractFor("ghost", "/items", "listGhost")}
	got, report := compile(regs, bindings, nil)
	wantPaths(t, got, "/alpha/items")
	ghost := report.services["ghost"]
	if !strings.Contains(ghost.rejection, "not in bindings.services") || ghost.serving != servingNone {
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

func TestLegacySecurityAcceptsNativeTarget(t *testing.T) {
	allowed := fixtureAuthorization().Profiles
	legacy := &legacySecurity{
		Source:   securityRequirements{{"staffBearer": {}}},
		Profiles: []string{"sessionBearer", "clientBasic"},
	}
	newSource := func(schemes map[string]any) *sourceDoc {
		return &sourceDoc{Components: map[string]map[string]any{"securitySchemes": schemes}}
	}
	declared := map[string]any{
		"sessionBearer": map[string]any{"type": "http", "scheme": "bearer", "description": "native"},
		"clientBasic":   map[string]any{"type": "http", "scheme": "basic"},
	}

	// Target requirements in a different order are accepted unchanged.
	op := map[string]any{"security": []any{
		map[string]any{"clientBasic": []any{}}, map[string]any{"sessionBearer": []any{}},
	}}
	source := newSource(declared)
	before, _ := json.Marshal(op)
	if err := applyLegacySecurity(op, source, legacy, allowed); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(op)
	if string(before) != string(after) {
		t.Fatalf("native security was rewritten: %s", after)
	}
	if source.Components["securitySchemes"]["sessionBearer"].(map[string]any)["description"] != "native" {
		t.Fatal("a scheme declared by the service was overwritten")
	}

	// A scheme the service did not declare is filled in from the profile.
	source = newSource(map[string]any{})
	if err := applyLegacySecurity(op, source, legacy, allowed); err != nil {
		t.Fatal(err)
	}
	if scheme, _ := source.Components["securitySchemes"]["clientBasic"].(map[string]any); scheme["scheme"] != "basic" {
		t.Fatalf("missing scheme was not added: %v", source.Components)
	}

	// The legacy source still translates to the target.
	op = map[string]any{"security": []any{map[string]any{"staffBearer": []any{}}}}
	source = newSource(map[string]any{})
	if err := applyLegacySecurity(op, source, legacy, allowed); err != nil {
		t.Fatal(err)
	}
	if got := op["security"].(securityRequirements); len(got) != 2 {
		t.Fatalf("legacy source was not translated: %v", got)
	}

	// Anything else is still rejected, including a partial target.
	for name, security := range map[string]any{
		"unrelated":      []any{map[string]any{"otherBearer": []any{}}},
		"partial target": []any{map[string]any{"sessionBearer": []any{}}},
		"scoped target":  []any{map[string]any{"sessionBearer": []any{"x"}}, map[string]any{"clientBasic": []any{}}},
		"anonymous":      []any{},
	} {
		op = map[string]any{"security": security}
		err := applyLegacySecurity(op, newSource(declared), legacy, allowed)
		if err == nil || !strings.Contains(err.Error(), "legacy source security changed") {
			t.Errorf("%s: expected a legacy security error, got %v", name, err)
		}
	}
}

func TestNativeTargetSecurityCompilesThroughLegacyBinding(t *testing.T) {
	const raw = `openapi: 3.1.0
components:
  securitySchemes:
    sessionBearer: {type: http, scheme: bearer}
paths:
  /objects:
    get:
      security: [{sessionBearer: []}]
      responses: {'200': {description: OK}}
`
	bindings := upstreamBindings{
		Hostname: "api.example.net", Authorization: fixtureAuthorization(),
		Services: map[string]serviceBinding{"observatory": {Prefix: "/observatory", Operations: []operationSelection{{
			Method: "get", Path: "/objects",
			Legacy: &legacySecurity{Source: securityRequirements{{"staffBearer": {}}}, Profiles: []string{"sessionBearer"}},
		}}}},
	}
	got, err := compileStrict([]registration{{serviceName: "observatory", openAPI: raw, rewrites: "[]"}}, bindings)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.routes) != 1 || len(got.routes[0].credentials) != 1 || got.routes[0].credentials[0] != "sessionBearer" {
		t.Fatalf("unexpected routes: %+v", got.routes)
	}
	unrelated := strings.Replace(raw, "[{sessionBearer: []}]", "[{clientBasic: []}]", 1)
	if _, err := compileStrict([]registration{{serviceName: "observatory", openAPI: unrelated, rewrites: "[]"}}, bindings); err == nil ||
		!strings.Contains(err.Error(), "legacy source security changed") {
		t.Fatalf("unrelated security was accepted: %v", err)
	}
}

func TestStatusReportsRejectionsAndServingState(t *testing.T) {
	bindings := isolationBindings("alpha", "beta", "gamma")
	g := newGateway(bindings)
	var active atomic.Pointer[snapshot]
	var draining atomic.Bool
	clock := time.Date(2026, 11, 23, 9, 30, 0, 0, time.FixedZone("test", 3600))
	reload := &reconciler{gateway: g, active: &active, now: func() time.Time { return clock }}
	regs := []registration{
		contractFor("alpha", "/items", "listAlpha", "      x-darban-visibility: bogus\n"),
		contractFor("beta", "/items", "listBeta"),
		contractFor("ghost", "/items", "listGhost"),
	}
	reload.apply(func() ([]registration, error) { return regs, nil })
	// A bad contract does not stop a fresh pod from becoming ready.
	if active.Load() == nil {
		t.Fatal("no snapshot after a fresh start with one bad contract")
	}
	read := func() map[string]contractStatus {
		t.Helper()
		response := httptest.NewRecorder()
		g.statusHandler(&active, &draining).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/status", nil))
		if response.Code != http.StatusOK {
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
	got := read()
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

	// Alpha becomes good, then bad again: the later rejection reports last-good.
	regs[0] = contractFor("alpha", "/items", "listAlpha")
	reload.apply(func() ([]registration, error) { return regs, nil })
	clock = clock.Add(time.Hour)
	regs[0] = contractFor("alpha", "/changed", "listAlpha", "      x-darban-visibility: bogus\n")
	reload.apply(func() ([]registration, error) { return regs, nil })
	if alpha := read()["alpha"]; alpha.Serving != servingLastGood || !alpha.Rejected || alpha.LastRejection.Time != "2026-11-23T09:30:00Z" {
		t.Fatalf("unexpected alpha status: %+v", alpha)
	}
	if _, ok := active.Load().routes[operationKey{http.MethodGet, "/alpha/items"}]; !ok {
		t.Fatal("last-good route is not active")
	}
	regs[0] = contractFor("alpha", "/items", "listAlpha")
	reload.apply(func() ([]registration, error) { return regs, nil })
	if alpha := read()["alpha"]; alpha.Serving != servingCurrent || alpha.Rejected || alpha.LastRejection == nil {
		t.Fatalf("a fixed contract should keep its last rejection but not be rejected: %+v", alpha)
	}
}
