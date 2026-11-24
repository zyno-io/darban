package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const testNamespace = "zyno-alpha"

func TestParseContractUpstream(t *testing.T) {
	const full = "svc." + testNamespace + ".svc.cluster.local"
	accepted := []struct {
		raw, origin, mount string
	}{
		{"http://svc", "http://" + full + ":80", ""},
		{"https://svc", "https://" + full + ":443", ""},
		{"http://svc." + testNamespace, "http://" + full + ":80", ""},
		{"http://svc." + testNamespace + ".svc", "http://" + full + ":80", ""},
		{"http://" + full, "http://" + full + ":80", ""},
		{"https://" + full + ":3000", "https://" + full + ":3000", ""},
		{"http://SVC." + testNamespace + ":8080", "http://" + full + ":8080", ""},
		{"http://svc/hosting", "http://" + full + ":80", "/hosting"},
		{"https://" + full + ":3000/hosting/v1", "https://" + full + ":3000", "/hosting/v1"},
	}
	for _, test := range accepted {
		origin, mount, err := parseContractUpstream(test.raw, testNamespace, false)
		if err != nil || origin != test.origin || mount != test.mount {
			t.Errorf("%s = %q %q %v, want %q %q", test.raw, origin, mount, err, test.origin, test.mount)
		}
	}
	rejected := map[string]string{
		"other namespace":       "http://svc.other.svc.cluster.local:80",
		"other namespace short": "http://svc.other",
		"query":                 "http://svc?x=1",
		"empty query":           "http://svc?",
		"fragment":              "http://svc#top",
		"userinfo":              "http://user:pw@svc",
		"user only":             "http://user@svc",
		"bad scheme":            "ftp://svc",
		"no scheme":             "svc",
		"trailing slash":        "http://svc/hosting/",
		"bare slash":            "http://svc/",
		"non-literal path":      "http://svc/Hosting",
		"escaped path":          "http://svc/a%2Fb",
		"external host":         "http://example.com",
		"four labels":           "http://svc.zyno-alpha.svc.cluster",
		"bad svc name":          "http://1svc.zyno-alpha",
		"underscore name":       "http://s_vc",
		"loopback":              "http://127.0.0.1:8080",
		"port zero":             "http://svc:0",
		"port too big":          "http://svc:70000",
		"empty":                 "",
	}
	for name, raw := range rejected {
		if origin, mount, err := parseContractUpstream(raw, testNamespace, false); err == nil {
			t.Errorf("%s: %q was accepted as %q %q", name, raw, origin, mount)
		}
	}
}

func TestParseContractUpstreamLocal(t *testing.T) {
	origin, mount, err := parseContractUpstream("http://127.0.0.1:9000/mnt", "", true)
	if err != nil || origin != "http://127.0.0.1:9000" || mount != "/mnt" {
		t.Fatalf("loopback = %q %q %v", origin, mount, err)
	}
	if origin, _, err = parseContractUpstream("https://localhost", "", true); err != nil || origin != "https://localhost:443" {
		t.Fatalf("localhost = %q %v", origin, err)
	}
	// There is no namespace check locally, but a bare name has no namespace.
	if origin, _, err = parseContractUpstream("http://svc.elsewhere.svc.cluster.local:80", "", true); err != nil ||
		origin != "http://svc.elsewhere.svc.cluster.local:80" {
		t.Fatalf("local Service = %q %v", origin, err)
	}
	if _, _, err = parseContractUpstream("http://svc", "", true); err == nil {
		t.Fatal("a bare Service name was accepted without a namespace")
	}
	// Loopback is still refused in Kubernetes mode.
	if _, _, err = parseContractUpstream("http://127.0.0.1:80", testNamespace, false); err == nil {
		t.Fatal("loopback was accepted in Kubernetes mode")
	}
}

// clusterContract is a GatewayContract in testNamespace.
func clusterContract(service, path, operationID, upstream, prefix string) registration {
	reg := contractFor(service, path, operationID)
	reg.namespace, reg.upstream, reg.prefix = testNamespace, upstream, prefix
	return reg
}

func contractOnlyBindings() upstreamBindings {
	return upstreamBindings{Hostname: "api.example.net", Services: map[string]serviceBinding{}}
}

func TestContractWithoutBindingEntryIsAdmitted(t *testing.T) {
	bindings := contractOnlyBindings()
	got, report := compile([]registration{
		clusterContract("hosting", "/hosting/sites", "listSites", "http://hosting-manager."+testNamespace+".svc.cluster.local/hosting", ""),
		clusterContract("suite", "/things", "listThings", "https://suite-api."+testNamespace+":3000", "/suite-api"),
	}, bindings, nil)
	wantPaths(t, got, "/hosting/sites", "/suite-api/things")
	if report.services["hosting"].rejection != "" || report.services["suite"].rejection != "" {
		t.Fatalf("unexpected outcomes: %+v", report.services)
	}
	hosting := got.services["hosting"]
	if hosting.Origin != "http://hosting-manager.zyno-alpha.svc.cluster.local:80" || hosting.Mount != "/hosting" || hosting.Prefix != "/hosting" {
		t.Fatalf("hosting binding = %+v", hosting)
	}
	suite := got.services["suite"]
	if suite.Origin != "https://suite-api.zyno-alpha.svc.cluster.local:3000" || suite.Mount != "" || suite.Prefix != "/suite-api" {
		t.Fatalf("suite binding = %+v", suite)
	}
	for _, route := range got.routes {
		if route.key.path == "/hosting/sites" && route.path != "/hosting/sites" {
			t.Fatalf("upstream path = %q", route.path)
		}
	}
	// Contract-only services are not reported missing or unserved.
	for name, outcome := range report.services {
		if outcome.missing {
			t.Fatalf("%s reported missing", name)
		}
	}
	if len(got.unserved) != 0 {
		t.Fatalf("unserved = %v", got.unserved)
	}
}

func TestContractOnlyServiceServesThroughItsUpstream(t *testing.T) {
	var seen atomic.Value
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.Host + " " + r.URL.Path)
		io.WriteString(w, "from backend")
	}))
	defer backend.Close()
	bindings := contractOnlyBindings()
	g := newGateway(bindings)
	g.transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, backend.Listener.Addr().String())
	}
	compiled, _ := compile([]registration{
		clusterContract("hosting", "/hosting/sites", "listSites", "http://hosting-manager."+testNamespace+".svc.cluster.local/hosting", ""),
	}, bindings, nil)
	active := g.build(compiled)
	request := httptest.NewRequest(http.MethodGet, "/hosting/sites", nil)
	request.Host = bindings.Hostname
	response := httptest.NewRecorder()
	g.serve(active, response, request)
	if response.Code != http.StatusOK || response.Body.String() != "from backend" || seen.Load() != "hosting-manager.zyno-alpha.svc.cluster.local:80 /hosting/sites" {
		t.Fatalf("response %d %q, backend saw %v", response.Code, response.Body.String(), seen.Load())
	}
}

func TestContractOnlyServiceServesOverHTTPS(t *testing.T) {
	ca := newTestCA(t, "contract-ca")
	backend := tlsUpstream(t, ca)
	address, _ := url.Parse(backend.URL)
	bindings := contractOnlyBindings()
	bindings.UpstreamTLS = upstreamTLSConfig{CAFile: writeCA(t, ca.pem)}
	g := newGateway(bindings)
	reg := clusterContract("secure", "/items", "listItems", "https://"+address.Host, "")
	reg.namespace, reg.local = "", true
	compiled, report := compile([]registration{reg}, bindings, nil)
	if report.services["secure"].rejection != "" {
		t.Fatalf("rejected: %+v", report.services["secure"])
	}
	request := httptest.NewRequest(http.MethodGet, "/secure/items", nil)
	request.Host = bindings.Hostname
	response := httptest.NewRecorder()
	g.serve(g.build(compiled), response, request)
	if response.Code != http.StatusOK || response.Body.String() != "ok" {
		t.Fatalf("https upstream returned %d %q", response.Code, response.Body.String())
	}
	// Without the CA, verification fails closed.
	untrusted := newGateway(contractOnlyBindings())
	response = httptest.NewRecorder()
	untrusted.serve(untrusted.build(compiled), response, request)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("an unverified upstream returned %d", response.Code)
	}
}

func TestBindingFallbackWithoutUpstream(t *testing.T) {
	bindings := contractOnlyBindings()
	bindings.Services["alpha"] = serviceBinding{Origin: "http://alpha.zyno-alpha.svc.cluster.local:8080", Prefix: "/a", Mount: "/m"}
	got, report := compile([]registration{contractFor("alpha", "/m/items", "listAlpha")}, bindings, nil)
	wantPaths(t, got, "/a/items")
	if report.services["alpha"].rejection != "" || len(report.overrides) != 0 {
		t.Fatalf("outcome %+v overrides %v", report.services["alpha"], report.overrides)
	}
	if binding := got.services["alpha"]; !reflect.DeepEqual(binding, bindings.Services["alpha"]) {
		t.Fatalf("effective binding = %+v", binding)
	}
	// A bindings entry may leave the prefix to the contract.
	bindings.Services["alpha"] = serviceBinding{Origin: "http://alpha.zyno-alpha.svc.cluster.local:8080"}
	reg := contractFor("alpha", "/items", "listAlpha")
	reg.prefix = "/custom"
	got, _ = compile([]registration{reg}, bindings, nil)
	wantPaths(t, got, "/custom/items")
	got, _ = compile([]registration{contractFor("alpha", "/items", "listAlpha")}, bindings, nil)
	wantPaths(t, got, "/alpha/items")
}

func TestContractOverridesBinding(t *testing.T) {
	bindings := contractOnlyBindings()
	bindings.Services["alpha"] = serviceBinding{
		Origin: "http://old.zyno-alpha.svc.cluster.local:8080", Prefix: "/old", Mount: "/old-mount",
		DebugOrigin: "http://debug.zyno-alpha.svc.cluster.local:8080",
	}
	bindings.Debug = debugConfig{RequestHeader: "X-Debug", RequiredHeader: "X-Ok", RequiredValue: "1"}
	reg := clusterContract("alpha", "/items", "listAlpha", "https://new."+testNamespace+".svc.cluster.local:9000", "/fresh")
	got, report := compile([]registration{reg}, bindings, nil)
	wantPaths(t, got, "/fresh/items")
	binding := got.services["alpha"]
	if binding.Origin != "https://new.zyno-alpha.svc.cluster.local:9000" || binding.Prefix != "/fresh" || binding.Mount != "" ||
		binding.DebugOrigin != bindings.Services["alpha"].DebugOrigin {
		t.Fatalf("effective binding = %+v", binding)
	}
	note := report.overrides["alpha"]
	for _, want := range []string{"upstream https://new", "prefix /fresh", `mount ""`} {
		if !strings.Contains(note, want) {
			t.Fatalf("override note %q lacks %q", note, want)
		}
	}

	// The disagreement is logged once per distinct value.
	var output bytes.Buffer
	log.SetOutput(&output)
	defer log.SetOutput(os.Stderr)
	var active atomic.Pointer[snapshot]
	r := &reconciler{gateway: newGateway(bindings), active: &active}
	load := func() ([]registration, error) { return []registration{reg}, nil }
	r.apply(load)
	r.apply(load)
	if count := strings.Count(output.String(), "contract overrides bindings"); count != 1 {
		t.Fatalf("override logged %d times:\n%s", count, output.String())
	}
	reg.upstream = "https://newer." + testNamespace + ".svc.cluster.local:9000"
	r.apply(load)
	if count := strings.Count(output.String(), "contract overrides bindings"); count != 2 {
		t.Fatalf("a new value was not logged:\n%s", output.String())
	}
}

func TestContractNeedsAnUpstreamFromSomewhere(t *testing.T) {
	bindings := contractOnlyBindings()
	bindings.Services["empty"] = serviceBinding{Prefix: "/empty"}
	regs := []registration{contractFor("ghost", "/items", "listGhost"), contractFor("empty", "/items", "listEmpty"),
		clusterContract("fine", "/items", "listFine", "http://fine", "")}
	got, report := compile(regs, bindings, nil)
	wantPaths(t, got, "/fine/items")
	for _, name := range []string{"ghost", "empty"} {
		outcome := report.services[name]
		if outcome.serving != servingNone || !strings.Contains(outcome.rejection, "no upstream") {
			t.Fatalf("%s outcome = %+v", name, outcome)
		}
	}
}

func TestInvalidUpstreamRejectsOnlyThatContract(t *testing.T) {
	bindings := contractOnlyBindings()
	regs := []registration{
		clusterContract("foreign", "/items", "listForeign", "http://svc.other.svc.cluster.local", ""),
		clusterContract("query", "/items", "listQuery", "http://svc?x=1", ""),
		clusterContract("badprefix", "/items", "listBad", "http://svc", "/Bad"),
		clusterContract("fine", "/items", "listFine", "http://fine", ""),
	}
	got, report := compile(regs, bindings, nil)
	wantPaths(t, got, "/fine/items")
	for _, name := range []string{"foreign", "query", "badprefix"} {
		if report.services[name].rejection == "" || report.services[name].serving != servingNone {
			t.Fatalf("%s outcome = %+v", name, report.services[name])
		}
	}
	if !strings.Contains(report.services["foreign"].rejection, "namespace") {
		t.Fatalf("foreign rejection = %q", report.services["foreign"].rejection)
	}
	// A contract that goes bad keeps serving its last good version.
	_, first := compile([]registration{clusterContract("fine", "/items", "listFine", "http://fine", "")}, bindings, nil)
	got, report = compile([]registration{clusterContract("fine", "/items", "listFine", "http://fine.other", "")}, bindings, first.accepted)
	wantPaths(t, got, "/fine/items")
	if outcome := report.services["fine"]; outcome.serving != servingLastGood || outcome.rejection == "" {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestContractPrefixCollisions(t *testing.T) {
	older, newer := time.Unix(1000, 0), time.Unix(2000, 0)
	mk := func(service string, created time.Time) registration {
		reg := clusterContract(service, "/items", "list"+service, "http://"+service, "/shared")
		reg.created = created
		return reg
	}
	bindings := contractOnlyBindings()
	// Fresh start, in either order: the older contract wins even when its name sorts last.
	for _, regs := range [][]registration{{mk("zeta", older), mk("alpha", newer)}, {mk("alpha", newer), mk("zeta", older)}} {
		got, report := compile(regs, bindings, nil)
		wantPaths(t, got, "/shared/items")
		if got.services["zeta"].Prefix != "/shared" || report.services["zeta"].serving != servingCurrent {
			t.Fatalf("zeta outcome = %+v", report.services["zeta"])
		}
		if outcome := report.services["alpha"]; outcome.serving != servingNone || !strings.Contains(outcome.rejection, "prefix /shared is already used by service zeta") {
			t.Fatalf("alpha outcome = %+v", outcome)
		}
	}
	// Equal timestamps fall back to the service name.
	got, _ := compile([]registration{mk("zeta", older), mk("alpha", older)}, bindings, nil)
	if _, ok := got.services["alpha"]; !ok || len(got.services) != 1 {
		t.Fatalf("services = %v", got.services)
	}
	// A new colliding contract never displaces the one that is serving.
	_, first := compile([]registration{mk("zeta", older)}, bindings, nil)
	got, report := compile([]registration{mk("zeta", older), mk("alpha", newer)}, bindings, first.accepted)
	wantPaths(t, got, "/shared/items")
	if _, ok := got.services["zeta"]; !ok || report.services["alpha"].rejection == "" || report.services["alpha"].serving != servingNone {
		t.Fatalf("unexpected outcome: %+v", report.services)
	}
	// Other services are unaffected.
	other := clusterContract("other", "/items", "listOther", "http://other", "")
	got, _ = compile([]registration{mk("zeta", older), mk("alpha", newer), other}, bindings, first.accepted)
	wantPaths(t, got, "/other/items", "/shared/items")
}

func TestContractPrefixCollidesWithBindingService(t *testing.T) {
	bindings := contractOnlyBindings()
	bindings.Services["static"] = serviceBinding{Origin: "http://static.zyno-alpha.svc.cluster.local:80", Prefix: "/taken"}
	older, newer := time.Unix(1000, 0), time.Unix(2000, 0)
	static := contractFor("static", "/items", "listStatic")
	static.created = older
	dynamic := clusterContract("dynamic", "/items", "listDynamic", "http://dynamic", "/taken")
	dynamic.created = newer
	got, report := compile([]registration{static, dynamic}, bindings, nil)
	wantPaths(t, got, "/taken/items")
	if report.services["dynamic"].rejection == "" || report.services["static"].serving != servingCurrent {
		t.Fatalf("outcomes = %+v", report.services)
	}
}

func TestContractPrefixCollidesWithServiceRoutes(t *testing.T) {
	bindings := contractOnlyBindings()
	bindings.ServiceRoutes = map[string]serviceRoute{"/legacy": {Origin: "http://legacy.zyno-alpha.svc.cluster.local:80"}, "/owned": {Origin: "http://owned.zyno-alpha.svc.cluster.local:80"}}
	bindings.Services["owner"] = serviceBinding{Origin: "http://owner.zyno-alpha.svc.cluster.local:80", Prefix: "/owned"}
	regs := []registration{
		clusterContract("intruder", "/items", "listIntruder", "http://intruder", "/legacy"),
		clusterContract("owner", "/items", "listOwner", "http://owner", "/owned"),
	}
	got, report := compile(regs, bindings, nil)
	wantPaths(t, got, "/owned/items")
	if outcome := report.services["intruder"]; outcome.serving != servingNone || !strings.Contains(outcome.rejection, "serviceRoutes") {
		t.Fatalf("intruder outcome = %+v", outcome)
	}
	if report.services["owner"].rejection != "" {
		t.Fatalf("owner outcome = %+v", report.services["owner"])
	}
	// The owner cannot move off the prefix of its direct route, which would
	// lose that route's deny list.
	moved := clusterContract("owner", "/items", "listOwner", "http://owner", "")
	if _, report = compile([]registration{moved}, bindings, nil); !strings.Contains(report.services["owner"].rejection, "owns the serviceRoutes prefix") {
		t.Fatalf("owner outcome = %+v", report.services["owner"])
	}
}

func TestContractPrefixCollidesWithDarbanPaths(t *testing.T) {
	bindings := contractOnlyBindings()
	bindings.OpenAPI = openAPIConfig{YAMLPath: "/openapi.yaml", JSONPath: "/docs/openapi.json"}
	bindings.Authz = "http://authz.zyno-alpha.svc.cluster.local:80"
	bindings.Authorization = authorizationConfig{Path: "/authorize"}
	reserved := map[string]string{"docs": "/docs", "authorize": "/authorize"}
	var regs []registration
	for name, prefix := range reserved {
		regs = append(regs, clusterContract(name, "/items", "list"+name, "http://"+name, prefix))
	}
	// /openapi is not reserved: only the exact document path is.
	regs = append(regs, clusterContract("openapi", "/items", "listOpenapi", "http://openapi", ""))
	got, report := compile(regs, bindings, nil)
	wantPaths(t, got, "/openapi/items")
	for name := range reserved {
		if outcome := report.services[name]; outcome.serving != servingNone || !strings.Contains(outcome.rejection, "collides with") {
			t.Fatalf("%s outcome = %+v", name, outcome)
		}
	}
	reserved = reservedPrefixes(bindings)
	// The YAML path's first segment has a dot, which no prefix can contain.
	if len(reserved) != 3 || reserved["/docs"] == "" || reserved["/authorize"] == "" {
		t.Fatalf("reserved = %v", reserved)
	}
}

func TestUpstreamChangeTakesEffectWithoutRestart(t *testing.T) {
	servers := make([]*httptest.Server, 2)
	for i := range servers {
		body := []string{"first", "second"}[i]
		servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, body+" "+r.URL.Path)
		}))
		defer servers[i].Close()
	}
	bindings := contractOnlyBindings()
	g := newGateway(bindings)
	var active atomic.Pointer[snapshot]
	r := &reconciler{gateway: g, active: &active}
	upstream := servers[0].URL
	path, opID := "/items", "list"
	load := func() ([]registration, error) {
		reg := clusterContract("moving", path, opID, upstream, "")
		reg.namespace, reg.local = "", true
		return []registration{reg}, nil
	}
	get := func() string {
		request := httptest.NewRequest(http.MethodGet, "/moving/items", nil)
		request.Host = bindings.Hostname
		response := httptest.NewRecorder()
		g.serve(active.Load(), response, request)
		return response.Body.String()
	}
	r.apply(load)
	if got := get(); got != "first /items" {
		t.Fatalf("got %q", got)
	}
	revision := active.Load().revision
	upstream = servers[1].URL
	r.apply(load)
	if active.Load().revision == revision {
		t.Fatal("an upstream change did not produce a new snapshot")
	}
	if got := get(); got != "second /items" {
		t.Fatalf("got %q after the upstream changed", got)
	}
	// A mount change moves the upstream path as well.
	upstream, path = servers[1].URL+"/mnt", "/mnt/items"
	r.apply(load)
	if got := get(); got != "second /mnt/items" {
		t.Fatalf("got %q after the mount changed", got)
	}
}

func TestStatusReportsUpstreamsAddedByContracts(t *testing.T) {
	stream := watch.NewRaceFreeFake()
	t.Cleanup(stream.Stop)
	ready := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Name: "fresh-1", Namespace: testNamespace, Labels: map[string]string{discoveryv1.LabelServiceName: "fresh"}},
		Endpoints:  []discoveryv1.Endpoint{{Addresses: []string{"192.0.2.10"}}},
	}
	informer := newEndpointInformer(&cache.ListWatch{
		ListWithContextFunc: func(context.Context, metav1.ListOptions) (runtime.Object, error) {
			return &discoveryv1.EndpointSliceList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}, Items: []discoveryv1.EndpointSlice{*ready}}, nil
		},
		WatchFuncWithContext: func(_ context.Context, options metav1.ListOptions) (watch.Interface, error) {
			if options.SendInitialEvents != nil && *options.SendInitialEvents {
				stream.Action(watch.Added, ready)
				stream.Action(watch.Bookmark, &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{
					ResourceVersion: "1", Annotations: map[string]string{"k8s.io/initial-events-end": "true"},
				}})
			}
			return stream, nil
		},
	})
	g := newGateway(contractOnlyBindings())
	g.endpoints = endpointCatalog{testNamespace: informer}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	g.endpoints.run(ctx)
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		t.Fatal("EndpointSlice cache did not sync")
	}

	compiled, _ := compile([]registration{
		clusterContract("fresh", "/items", "listFresh", "https://fresh", ""),
		clusterContract("idle", "/items", "listIdle", "http://idle", ""),
	}, contractOnlyBindings(), nil)
	var active atomic.Pointer[snapshot]
	var draining atomic.Bool
	read := func() map[string]endpointState {
		response := httptest.NewRecorder()
		g.statusHandler(&active, &draining).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/status", nil))
		var report statusResponse
		if err := json.Unmarshal(response.Body.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		states := make(map[string]endpointState)
		for _, upstream := range report.Upstreams {
			states[upstream.Service+"/"+upstream.Role] = upstream.State
		}
		return states
	}
	if states := read(); len(states) != 1 {
		t.Fatalf("before the contracts were served: %v", states)
	}
	active.Store(g.build(compiled))
	states := read()
	if states["fresh/primary"] != endpointReady || states["idle/primary"] != endpointEmpty || states["fresh/debug"] != endpointNotConfigured {
		t.Fatalf("states = %v", states)
	}
}

func TestEndpointCatalogWatchesTheContractNamespace(t *testing.T) {
	bindings := upstreamBindings{
		Authz:    "http://authz.auth-ns.svc.cluster.local:80",
		Services: map[string]serviceBinding{"s": {Origin: "http://s." + testNamespace + ".svc.cluster.local:80"}},
	}
	catalog, err := newEndpointCatalog(&rest.Config{Host: "http://127.0.0.1:1"}, bindings, testNamespace)
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog) != 2 || catalog[testNamespace] == nil || catalog["auth-ns"] == nil {
		t.Fatalf("catalog = %v", catalog)
	}
	catalog, err = newEndpointCatalog(&rest.Config{Host: "http://127.0.0.1:1"}, upstreamBindings{}, testNamespace)
	if err != nil || len(catalog) != 1 || catalog[testNamespace] == nil {
		t.Fatalf("catalog = %v, %v", catalog, err)
	}
}

func TestLocalManifestContractWithUpstream(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("openapi.yaml", anonymousContract("/api/items", "listItems"))
	write("rewrites.yaml", "[]")
	write("manifest.yaml", `contracts:
- serviceName: local-only
  upstream: http://127.0.0.1:9100/api
  prefix: /localonly
  openapi.yaml: openapi.yaml
  rewrites.yaml: rewrites.yaml
`)
	regs, err := loadLocal(filepath.Join(dir, "manifest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	got, report := compile(regs, contractOnlyBindings(), nil)
	wantPaths(t, got, "/localonly/items")
	if binding := got.services["local-only"]; report.services["local-only"].rejection != "" ||
		binding.Origin != "http://127.0.0.1:9100" || binding.Mount != "/api" {
		t.Fatalf("binding %+v outcome %+v", binding, report.services["local-only"])
	}
	if _, err := compileStrict(regs, contractOnlyBindings()); err != nil {
		t.Fatal(err)
	}
}

func TestLoadBindingsAllowsPartialServiceEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bindings.json")
	write := func(body string) error {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := loadBindings(path, true)
		return err
	}
	if err := write(`{"hostname": "api.example.net"}`); err != nil {
		t.Fatalf("no services: %v", err)
	}
	if err := write(`{"hostname": "api.example.net", "services": {"a": {"registrationOnly": true}, "b": {"mount": "/b"}}}`); err != nil {
		t.Fatalf("partial entries: %v", err)
	}
	for name, body := range map[string]string{
		"bad prefix":    `{"hostname": "api.example.net", "services": {"a": {"prefix": "/A"}}}`,
		"bad origin":    `{"hostname": "api.example.net", "services": {"a": {"origin": "http://example.com:80"}}}`,
		"bad mount":     `{"hostname": "api.example.net", "services": {"a": {"mount": "/A/"}}}`,
		"debug no pol.": `{"hostname": "api.example.net", "services": {"a": {"debugOrigin": "http://d.ns.svc.cluster.local:80"}}}`,
		"reg-only ops":  `{"hostname": "api.example.net", "services": {"a": {"registrationOnly": true, "operations": [{"method": "GET", "path": "/x"}]}}}`,
		"collision":     `{"hostname": "api.example.net", "services": {"a": {"prefix": "/x"}, "b": {"prefix": "/x"}}}`,
	} {
		if err := write(body); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
