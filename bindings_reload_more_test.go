package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBindingsReloadReportsALostLastGoodContract(t *testing.T) {
	origin := teapotUpstream(t)
	r := newReloadRig(t, reloadBindingsJSON(origin, ""))
	r.setContracts(contractFor("alpha", "/items", "listAlpha", badVisibility), contractFor("beta", "/items", "listBeta"))
	if r.get("/alpha/items") != http.StatusTeapot {
		t.Fatal("alpha lost its last good contract")
	}
	// The new bindings select an operation alpha's last good contract lacks.
	r.files.write(reloadBindingsJSON(origin, `, "operations": [{"method": "get", "path": "/nope"}]`))
	r.waitFor("alpha closed", func() bool { return r.get("/alpha/items") == http.StatusServiceUnavailable })
	report := r.status()
	if len(report.BindingsWarnings) != 1 || !strings.Contains(report.BindingsWarnings[0], "last good contract no longer compiles") ||
		report.LastBindingsError != nil {
		t.Errorf("status: warnings %q error %+v", report.BindingsWarnings, report.LastBindingsError)
	}
	for _, entry := range report.Contracts {
		if entry.Service == "alpha" && (entry.State != stateClosed || !strings.Contains(entry.Reason, "last good contract no longer compiles")) {
			t.Errorf("alpha %+v", entry)
		}
	}
	// A later contract apply keeps the reason until alpha is accepted again.
	r.setContracts(contractFor("alpha", "/items", "listAlpha", badVisibility), contractFor("beta", "/items", "listBeta2"))
	for _, entry := range r.status().Contracts {
		if entry.Service == "alpha" && !strings.Contains(entry.Reason, "last good contract no longer compiles") {
			t.Errorf("alpha after another apply %+v", entry)
		}
	}
}

func TestBindingsReloadDoesNotRetryARejectedRevision(t *testing.T) {
	origin := teapotUpstream(t)
	r := newReloadRig(t, reloadBindingsJSON(origin, ""))
	bad := reloadBindingsJSON(origin, `, "prefix": "/Bad"`)
	r.files.write(bad)
	r.waitFor("error", func() bool { return r.status().LastBindingsError != nil })
	sum := sha256.Sum256([]byte(bad))
	if got := r.status().LastBindingsError; got.Revision != hex.EncodeToString(sum[:]) || got.Revision == r.status().BindingsRevision {
		t.Errorf("error %+v", got)
	}
	// The watcher keeps reading the file, but parses the rejected content
	// only once.
	parses := r.rec.bindingsParses.Load()
	time.Sleep(60 * time.Millisecond)
	if again := r.rec.bindingsParses.Load(); again != parses {
		t.Errorf("the rejected revision was parsed again: %d, then %d", parses, again)
	}
	// Back to the active content, the error clears.
	r.files.write(reloadBindingsJSON(origin, ""))
	r.waitFor("error cleared", func() bool { return r.status().LastBindingsError == nil })
	if r.rec.bindingsParses.Load() != parses {
		t.Error("the active content was parsed again")
	}
}

func TestBindingsReloadWarnsOnlyWhenAServiceLosesItsContract(t *testing.T) {
	origin := teapotUpstream(t)
	r := newReloadRig(t, reloadBindingsJSON(origin, ""))
	// C1 is last good; C2 is rejected because it selects nothing it declares.
	c2 := contractFor("alpha", "/other", "listOther")
	r.files.write(reloadBindingsJSON(origin, `, "operations": [{"method": "get", "path": "/items"}]`))
	r.waitFor("selection applied", func() bool {
		return len(r.active.Load().gateway.bindings.Services["alpha"].Operations) == 1
	})
	r.setContracts(c2, contractFor("beta", "/items", "listBeta"))
	if r.get("/alpha/items") != http.StatusTeapot {
		t.Fatal("alpha lost its last good contract")
	}
	// The new selection breaks C1 but makes C2 compile: alpha serves C2.
	r.files.write(reloadBindingsJSON(origin, `, "operations": [{"method": "get", "path": "/other"}]`))
	r.waitFor("alpha serves C2", func() bool { return r.get("/alpha/other") == http.StatusTeapot })
	if warnings := r.status().BindingsWarnings; len(warnings) != 0 {
		t.Errorf("warnings %q", warnings)
	}
	for _, entry := range r.status().Contracts {
		if entry.Service == "alpha" && strings.Contains(entry.Reason, "last good") {
			t.Errorf("alpha %+v", entry)
		}
	}
}

func TestDroppedReasonsArePrunedWithTheirContract(t *testing.T) {
	origin := teapotUpstream(t)
	r := newReloadRig(t, strings.Replace(reloadBindingsJSON(origin, ""), `"beta": {"origin"`, `"gamma": {"origin": "`+origin+`"}, "beta": {"origin"`, 1))
	r.setContracts(contractFor("alpha", "/items", "listAlpha"), contractFor("beta", "/items", "listBeta"), contractFor("gamma", "/items", "listGamma"))
	r.setContracts(contractFor("alpha", "/items", "listAlpha"), contractFor("beta", "/items", "listBeta"), contractFor("gamma", "/items", "listGamma", badVisibility))
	// gamma loses its last good contract to a reload, then its contract goes.
	r.files.write(strings.Replace(reloadBindingsJSON(origin, ""), `"beta": {"origin"`,
		`"gamma": {"origin": "`+origin+`", "operations": [{"method": "get", "path": "/nope"}]}, "beta": {"origin"`, 1))
	r.waitFor("gamma dropped", func() bool {
		r.rec.mu.Lock()
		defer r.rec.mu.Unlock()
		return r.rec.dropped["gamma"] != ""
	})
	r.setContracts(contractFor("alpha", "/items", "listAlpha"), contractFor("beta", "/items", "listBeta"))
	r.rec.mu.Lock()
	defer r.rec.mu.Unlock()
	if reason := r.rec.dropped["gamma"]; reason != "" {
		t.Errorf("kept %q for a deleted contract", reason)
	}
}

func TestBindingsReloadRecoversFromAMissingFile(t *testing.T) {
	origin := teapotUpstream(t)
	r := newReloadRig(t, reloadBindingsJSON(origin, ""))
	if err := os.Remove(r.files.path()); err != nil {
		t.Fatal(err)
	}
	r.waitFor("read error", func() bool {
		got := r.status().LastBindingsError
		return got != nil && got.Revision == ""
	})
	if r.get("/alpha/items") != http.StatusTeapot {
		t.Fatal("the active bindings stopped serving")
	}
	r.files.write(reloadBindingsJSON(origin, `, "enabled": false`))
	if err := os.Symlink(filepath.Join("..data", "bindings.json"), r.files.path()); err != nil {
		t.Fatal(err)
	}
	r.waitFor("recovered", func() bool { return r.get("/alpha/items") == http.StatusServiceUnavailable })
}

func TestBindingsReloadDoesNotReadTheCAFile(t *testing.T) {
	origin := teapotUpstream(t)
	caFile := writeCA(t, newTestCA(t, "reload-ca").pem)
	withCA := func(extra, file string) string {
		return strings.Replace(reloadBindingsJSON(origin, extra), `"hostname"`, fmt.Sprintf(`"upstreamTLS": {"caFile": %q}, "hostname"`, file), 1)
	}
	r := newReloadRig(t, withCA("", caFile))
	// The verifier re-reads the CA itself; an unreadable one does not block
	// an unrelated change.
	if err := os.Remove(caFile); err != nil {
		t.Fatal(err)
	}
	r.files.write(withCA(`, "enabled": false`, caFile))
	r.waitFor("alpha disabled", func() bool { return r.get("/alpha/items") == http.StatusServiceUnavailable })
	// A new caFile cannot apply at runtime, and says so.
	r.files.write(withCA(`, "enabled": false`, filepath.Join(t.TempDir(), "missing.crt")))
	r.waitFor("restart error", func() bool {
		got := r.status().LastBindingsError
		return got != nil && strings.Contains(got.Message, "restart")
	})
}

func TestBindingsReloadRejectsNewExternalServices(t *testing.T) {
	origin := teapotUpstream(t)
	r := newReloadRig(t, reloadBindingsJSON(origin, ""))
	r.rec.mu.Lock()
	r.rec.watched = "fixtures"
	r.rec.mu.Unlock()
	withService := func(name, origin string) string {
		return strings.Replace(reloadBindingsJSON(teapotOrigin(r), ""), `"services": {`, fmt.Sprintf(`"services": {%q: {"origin": %q}, `, name, origin), 1)
	}
	r.files.write(withService("gamma", "http://gamma.other.svc.cluster.local:80"))
	r.waitFor("external error", func() bool {
		got := r.status().LastBindingsError
		return got != nil && strings.Contains(got.Message, "outside namespace fixtures")
	})
	// A Service in the watched namespace is watched already, so it applies.
	r.files.write(withService("delta", "http://delta.fixtures.svc.cluster.local:80"))
	r.waitFor("delta bound", func() bool {
		_, bound := r.active.Load().gateway.bindings.Services["delta"]
		return bound
	})
}

// teapotOrigin is the origin the rig's bindings use.
func teapotOrigin(r *reloadRig) string {
	return r.first.bindings.Services["alpha"].Origin
}

func TestBindingsReloadAppliesRequestSettings(t *testing.T) {
	var mu sync.Mutex
	var seen http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		mu.Lock()
		seen = q.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusTeapot)
	}))
	defer upstream.Close()
	authz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Id", "verified")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer authz.Close()
	body := func(extra, response, strip string) string {
		return fmt.Sprintf(`{"hostname": "api.example.net", "authz": %q, %s
			"authorization": {"path": "/authz", "responseHeaders": [%s], "stripHeaderPrefixes": [%q]},
			"services": {"alpha": {"origin": %q}}}`, authz.URL, extra, response, strip, upstream.URL)
	}
	files := newConfigMapDir(t, body("", "", "X-A-"))
	bindings, revision, err := readBindings(files.path(), true, true)
	if err != nil {
		t.Fatal(err)
	}
	g := newGateway(bindings)
	g.bindingsRevision = revision
	var active atomic.Pointer[snapshot]
	rec := &reconciler{gateway: g, active: &active}
	contract := "openapi: 3.1.0\npaths:\n  /items:\n    get:\n      operationId: listItems\n      security: [{account: []}]\n" +
		"      responses: {'200': {description: OK}}\ncomponents:\n  securitySchemes:\n    account: {type: http, scheme: bearer}\n"
	rec.apply(func() ([]registration, error) {
		return []registration{{serviceName: "alpha", rewrites: "[]", openAPI: contract}}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		rec.watchBindings(ctx, files.path(), true, revision, 5*time.Millisecond)
	}()
	defer func() {
		cancel()
		<-done
	}()
	do := func() (*httptest.ResponseRecorder, http.Header) {
		req := httptest.NewRequest(http.MethodGet, "/alpha/items", nil)
		req.Host, req.RemoteAddr = "api.example.net", "192.0.2.10:4444"
		for name, value := range map[string]string{"Authorization": "Bearer x", "Origin": "https://app.example.net",
			"X-Real-Ip": "203.0.113.9", "X-A-Foo": "a", "X-B-Foo": "b"} {
			req.Header.Set(name, value)
		}
		res := httptest.NewRecorder()
		current := active.Load()
		current.gateway.serve(current, res, req)
		mu.Lock()
		defer mu.Unlock()
		return res, seen
	}
	check := func(label string, res *httptest.ResponseRecorder, got http.Header, want map[string]string) {
		t.Helper()
		values := map[string]string{"ACAO": res.Header().Get("Access-Control-Allow-Origin")}
		for _, name := range []string{"X-Real-Ip", "X-A-Foo", "X-B-Foo", "X-Id"} {
			values[name] = got.Get(name)
		}
		for name, value := range want {
			if values[name] != value {
				t.Errorf("%s: %s = %q, want %q (all %v)", label, name, values[name], value, values)
			}
		}
	}
	res, got := do()
	check("before", res, got, map[string]string{"ACAO": "", "X-Real-Ip": "192.0.2.10", "X-A-Foo": "", "X-B-Foo": "b", "X-Id": ""})

	files.write(body(`"browserOrigins": ["https://app.example.net"], "clientIP": {"trustedProxies": ["192.0.2.0/24"]},`, `"X-Id"`, "X-B-"))
	deadline := time.Now().Add(5 * time.Second)
	for len(active.Load().gateway.bindings.BrowserOrigins) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the reload did not apply")
		}
		time.Sleep(2 * time.Millisecond)
	}
	res, got = do()
	check("after", res, got, map[string]string{"ACAO": "https://app.example.net", "X-Real-Ip": "203.0.113.9", "X-A-Foo": "a", "X-B-Foo": "", "X-Id": "verified"})
}
