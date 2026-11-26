package main

import (
	"context"
	"encoding/json"
	"errors"
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

// configMapDir lays a bindings file out as a ConfigMap volume does: the file
// is a symlink into ..data, which is itself a symlink swapped atomically.
type configMapDir struct {
	t       *testing.T
	dir     string
	version int
}

func newConfigMapDir(t *testing.T, body string) *configMapDir {
	c := &configMapDir{t: t, dir: t.TempDir()}
	c.write(body)
	if err := os.Symlink(filepath.Join("..data", "bindings.json"), c.path()); err != nil {
		t.Fatal(err)
	}
	return c
}

func (c *configMapDir) path() string { return filepath.Join(c.dir, "bindings.json") }

func (c *configMapDir) write(body string) {
	c.version++
	version := fmt.Sprintf("..v%d", c.version)
	if err := os.Mkdir(filepath.Join(c.dir, version), 0o755); err != nil {
		c.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.dir, version, "bindings.json"), []byte(body), 0o644); err != nil {
		c.t.Fatal(err)
	}
	staged := filepath.Join(c.dir, "..data_tmp")
	if err := os.Symlink(version, staged); err != nil {
		c.t.Fatal(err)
	}
	if err := os.Rename(staged, filepath.Join(c.dir, "..data")); err != nil {
		c.t.Fatal(err)
	}
}

// reloadRig serves alpha and beta from a bindings file it watches.
type reloadRig struct {
	t      *testing.T
	files  *configMapDir
	first  *gateway
	rec    *reconciler
	active atomic.Pointer[snapshot]
	regs   atomic.Pointer[[]registration]
	// unreadable makes the contracts fail to load.
	unreadable atomic.Bool
	stop       context.CancelFunc
	done       chan struct{}
}

func reloadBindingsJSON(origin, extra string) string {
	return fmt.Sprintf(`{"hostname": "api.example.net", "services": {"alpha": {"origin": %q%s}, "beta": {"origin": %q}}}`, origin, extra, origin)
}

func newReloadRig(t *testing.T, body string) *reloadRig {
	r := &reloadRig{t: t, files: newConfigMapDir(t, body), done: make(chan struct{})}
	bindings, revision, err := readBindings(r.files.path(), true)
	if err != nil {
		t.Fatal(err)
	}
	g := newGateway(bindings)
	g.bindingsRevision, g.bindingsLoadedAt = revision, time.Now()
	r.first = g
	r.rec = &reconciler{gateway: g, active: &r.active}
	r.setContracts(contractFor("alpha", "/items", "listAlpha"), contractFor("beta", "/items", "listBeta"))
	ctx, cancel := context.WithCancel(context.Background())
	r.stop = cancel
	go func() {
		defer close(r.done)
		r.rec.watchBindings(ctx, r.files.path(), true, revision, 5*time.Millisecond)
	}()
	t.Cleanup(func() {
		cancel()
		<-r.done
	})
	return r
}

func (r *reloadRig) setContracts(regs ...registration) {
	r.regs.Store(&regs)
	r.rec.apply(func() ([]registration, error) {
		if r.unreadable.Load() {
			return nil, errors.New("contracts unreadable")
		}
		return *r.regs.Load(), nil
	})
}

func (r *reloadRig) get(path string) int {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "api.example.net"
	res := httptest.NewRecorder()
	active := r.active.Load()
	active.gateway.serve(active, res, req)
	return res.Code
}

func (r *reloadRig) status() statusResponse {
	var draining atomic.Bool
	res := httptest.NewRecorder()
	// The handler reads the bindings of the active snapshot's gateway.
	r.first.statusHandler(&r.active, &draining).ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/status", nil))
	var report statusResponse
	if err := json.Unmarshal(res.Body.Bytes(), &report); err != nil {
		r.t.Fatal(err)
	}
	return report
}

func (r *reloadRig) waitFor(what string, predicate func() bool) {
	r.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !predicate() {
		if time.Now().After(deadline) {
			r.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestBindingsReloadAppliesAValidChange(t *testing.T) {
	origin := teapotUpstream(t)
	r := newReloadRig(t, reloadBindingsJSON(origin, ""))
	before := r.status()
	if r.get("/alpha/items") != http.StatusTeapot || before.BindingsRevision == "" || before.BindingsLoadedAt == "" {
		t.Fatalf("before: %d %+v", r.get("/alpha/items"), before)
	}
	// Readiness never flaps: a snapshot is active throughout.
	var unready atomic.Bool
	stop := make(chan struct{})
	var watching sync.WaitGroup
	watching.Add(1)
	go func() {
		defer watching.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if r.active.Load() == nil {
				unready.Store(true)
			}
		}
	}()
	r.files.write(reloadBindingsJSON(origin, `, "enabled": false`))
	r.waitFor("alpha disabled", func() bool { return r.get("/alpha/items") == http.StatusServiceUnavailable })
	close(stop)
	watching.Wait()
	if unready.Load() {
		t.Error("the gateway had no snapshot during the reload")
	}
	if r.get("/beta/items") != http.StatusTeapot {
		t.Error("beta stopped serving")
	}
	after := r.status()
	if after.BindingsRevision == before.BindingsRevision || after.LastBindingsError != nil {
		t.Errorf("after: %+v", after)
	}
	var alpha contractStatus
	for _, entry := range after.Contracts {
		if entry.Service == "alpha" {
			alpha = entry
		}
	}
	if alpha.State != stateDisabled {
		t.Errorf("alpha status %+v", alpha)
	}
	// A change that only touches global settings swaps the gateway too.
	r.files.write(strings.Replace(reloadBindingsJSON(origin, ""), `"hostname": "api.example.net"`,
		`"hostname": "api.example.net", "browserOrigins": ["https://app.example.net"]`, 1))
	r.waitFor("browser origins", func() bool {
		return len(r.active.Load().gateway.bindings.BrowserOrigins) == 1 && r.get("/alpha/items") == http.StatusTeapot
	})
}

func TestBindingsReloadKeepsTheActiveBindingsOnError(t *testing.T) {
	origin := teapotUpstream(t)
	r := newReloadRig(t, reloadBindingsJSON(origin, ""))
	active := r.active.Load()
	revision := r.status().BindingsRevision
	for name, body := range map[string]string{
		"syntax":       `{"hostname": `,
		"unknown key":  strings.Replace(reloadBindingsJSON(origin, ""), `"hostname"`, `"bogus": 1, "hostname"`, 1),
		"invalid":      reloadBindingsJSON(origin, `, "prefix": "/Bad"`),
		"API group":    strings.Replace(reloadBindingsJSON(origin, ""), `"hostname"`, `"contractAPIGroup": "other.example.net", "hostname"`, 1),
		"upstream TLS": strings.Replace(reloadBindingsJSON(origin, ""), `"hostname"`, `"upstreamTLS": {"insecureSkipVerify": true}, "hostname"`, 1),
	} {
		r.files.write(body)
		r.waitFor(name+" error", func() bool {
			report := r.status()
			return report.LastBindingsError != nil && report.LastBindingsError.Time != ""
		})
		report := r.status()
		if r.active.Load() != active || report.BindingsRevision != revision || r.get("/alpha/items") != http.StatusTeapot {
			t.Errorf("%s: the active bindings changed: %+v", name, report)
		}
		if (name == "API group" || name == "upstream TLS") && !strings.Contains(report.LastBindingsError.Message, "restart") {
			t.Errorf("%s: %q", name, report.LastBindingsError.Message)
		}
		r.first.bindingsStatus.mu.Lock()
		r.first.bindingsStatus.err = nil
		r.first.bindingsStatus.mu.Unlock()
	}
	// The next valid file applies, and the error stays as the last one seen.
	r.files.write(reloadBindingsJSON(origin, `, "enabled": false`))
	r.waitFor("valid change", func() bool { return r.get("/alpha/items") == http.StatusServiceUnavailable })
}

func TestBindingsReloadFollowsALastGoodContract(t *testing.T) {
	origin := teapotUpstream(t)
	r := newReloadRig(t, reloadBindingsJSON(origin, ""))
	// alpha's update is rejected, so it serves its last good contract.
	r.setContracts(contractFor("alpha", "/items", "listAlpha", badVisibility), contractFor("beta", "/items", "listBeta"))
	if r.get("/alpha/items") != http.StatusTeapot {
		t.Fatal("alpha lost its last good contract")
	}
	// New bindings move alpha; the last good contract moves with it.
	r.files.write(reloadBindingsJSON(origin, `, "prefix": "/moved"`))
	r.waitFor("alpha moved", func() bool { return r.get("/moved/items") == http.StatusTeapot })
	if r.get("/alpha/items") != http.StatusNotFound {
		t.Errorf("old prefix = %d", r.get("/alpha/items"))
	}
}

func TestBindingsReloadRacesWithContractUpdates(t *testing.T) {
	origin := teapotUpstream(t)
	r := newReloadRig(t, reloadBindingsJSON(origin, ""))
	ctx, cancel := context.WithCancel(context.Background())
	var updates sync.WaitGroup
	updates.Add(2)
	go func() {
		defer updates.Done()
		for i := 0; ctx.Err() == nil; i++ {
			r.setContracts(contractFor("alpha", "/items", fmt.Sprintf("listAlpha%d", i)), contractFor("beta", "/items", "listBeta"))
		}
	}()
	go func() {
		defer updates.Done()
		for ctx.Err() == nil {
			if active := r.active.Load(); active == nil || active.gateway == nil {
				t.Error("no active snapshot")
				return
			}
			r.get("/beta/items")
		}
	}()
	for i := 0; i < 10; i++ {
		extra := ""
		if i%2 == 0 {
			extra = `, "enabled": false`
		}
		r.files.write(reloadBindingsJSON(origin, extra))
		want := http.StatusTeapot
		if extra != "" {
			want = http.StatusServiceUnavailable
		}
		r.waitFor(fmt.Sprintf("reload %d", i), func() bool { return r.get("/alpha/items") == want })
	}
	cancel()
	updates.Wait()
	// The active snapshot was built by the current gateway, from the current
	// contracts and bindings.
	r.rec.mu.Lock()
	defer r.rec.mu.Unlock()
	if active := r.active.Load(); active.gateway != r.rec.gateway {
		t.Error("the active snapshot is from an older gateway")
	}
}

func TestBindingsReloadKeepsServingWhenARewriteTargetGoes(t *testing.T) {
	origin := teapotUpstream(t)
	withLegacy := fmt.Sprintf(`{"hostname": "api.example.net", "services": {"alpha": {"origin": %q}, "beta": {"origin": %q}, "legacy": {"origin": %q}}}`, origin, origin, origin)
	r := newReloadRig(t, withLegacy)
	alpha := contractFor("alpha", "/items", "listAlpha")
	alpha.rewrites = `[{from: {method: GET, path: /alpha/old}, to: {serviceName: legacy, path: /items}}]`
	r.setContracts(alpha, contractFor("beta", "/items", "listBeta"))
	if r.get("/alpha/items") != http.StatusTeapot {
		t.Fatal("alpha not served")
	}
	// Without legacy in the bindings, only the rewrite into it is denied:
	// alpha keeps serving, as on a fresh pod.
	r.files.write(reloadBindingsJSON(origin, ""))
	r.waitFor("legacy removed", func() bool {
		_, bound := r.active.Load().gateway.bindings.Services["legacy"]
		return !bound
	})
	if r.get("/alpha/items") != http.StatusTeapot || r.get("/alpha/old") != http.StatusNotFound || r.get("/beta/items") != http.StatusTeapot {
		t.Errorf("alpha %d, alpha/old %d, beta %d", r.get("/alpha/items"), r.get("/alpha/old"), r.get("/beta/items"))
	}
	// A fresh compile agrees.
	bindings, _, err := readBindings(r.files.path(), true)
	if err != nil {
		t.Fatal(err)
	}
	if _, report := compile([]registration{alpha}, bindings, nil); report.services["alpha"].rejection != "" {
		t.Errorf("fresh alpha %+v", report.services["alpha"])
	}
}

func TestBindingsReloadRetriesWhenTheContractsCannotBeRead(t *testing.T) {
	origin := teapotUpstream(t)
	r := newReloadRig(t, reloadBindingsJSON(origin, ""))
	r.unreadable.Store(true)
	r.files.write(reloadBindingsJSON(origin, `, "enabled": false`))
	r.waitFor("reload error", func() bool { return r.status().LastBindingsError != nil })
	if r.get("/alpha/items") != http.StatusTeapot {
		t.Fatal("the old bindings stopped serving")
	}
	// The same file applies once the contracts can be read again.
	r.unreadable.Store(false)
	r.waitFor("retried reload", func() bool { return r.get("/alpha/items") == http.StatusServiceUnavailable })
}
