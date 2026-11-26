package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/yaml"
)

func fixtureAuthorization() authorizationConfig {
	return authorizationConfig{
		Path:                "/authorize",
		ResponseHeaders:     []string{"X-Auth-Subject", "X-Auth-Account", "X-Auth-Debug-Allowed"},
		StripHeaderPrefixes: []string{"X-Auth-"},
	}
}

func TestUnlistedOperationsRetainRoutingAndSecurity(t *testing.T) {
	const raw = `openapi: 3.1.0
paths:
  /objects:
    get:
      x-darban-visibility: public
      security: [{clientBasic: []}]
      responses:
        '200': {description: Public}
    post:
      x-darban-visibility: unlisted
      security: [{sessionBearer: []}]
      responses:
        '200':
          description: Hidden operation
          content:
            application/json:
              schema: {$ref: '#/components/schemas/HiddenResponse'}
  /legacy-objects:
    get:
      x-darban-visibility: unlisted
      security: [{sessionBearer: []}]
      responses:
        '200': {description: Legacy}
  /internal:
    get:
      x-darban-visibility: internal
components:
  securitySchemes:
    sessionBearer: {type: http, scheme: bearer}
    clientBasic: {type: http, scheme: basic}
  schemas:
    HiddenResponse: {type: string}
`
	const rewrites = `
- from: {method: POST, path: /observatory/alias}
  to: {serviceName: observatory, path: /objects}
- from: {method: GET, path: /observatory/legacy-objects}
  to: {serviceName: observatory, path: /objects}
`
	authz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/authorize" || r.Header.Get("X-Auth-Subject") != "" {
			t.Error("authorizer received an unexpected path or untrusted identity")
		}
		w.Header().Set("X-Auth-Subject", "fixture-tenant")
		if r.Header.Get("Authorization") != "Bearer incomplete" {
			w.Header().Set("X-Auth-Account", "fixture-account")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer authz.Close()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/objects" || r.Header.Get("X-Auth-Subject") != "fixture-tenant" || r.Header.Get("X-Auth-Forged") != "" {
			t.Errorf("unexpected upstream request: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	bindings := upstreamBindings{
		Hostname: "api.example.net", Authorization: fixtureAuthorization(),
		Authz:    authz.URL,
		Services: map[string]serviceBinding{"observatory": {Prefix: "/observatory", Origin: backend.URL}},
	}
	reg := registration{serviceName: "observatory", openAPI: raw, rewrites: rewrites}
	compiled, err := compileStrict([]registration{reg}, bindings)
	if err != nil {
		t.Fatal(err)
	}
	for _, hidden := range []string{"post:", "/observatory/alias", "/observatory/legacy-objects", "/observatory/internal", "HiddenResponse", "sessionBearer", "x-darban-visibility", "x-darban-policy", "operationId:"} {
		if strings.Contains(string(compiled.specYAML), hidden) {
			t.Fatalf("combined OpenAPI exposed %s", hidden)
		}
	}
	if !strings.Contains(string(compiled.specYAML), "/observatory/objects:") {
		t.Fatal("listed operation on the same path disappeared")
	}

	g := newGateway(bindings)
	snapshot := g.build(compiled)
	for _, request := range []struct {
		method, path, authorization string
		status                      int
	}{
		{"POST", "/observatory/objects", "", 401},
		{"POST", "/observatory/objects", "Bearer fixture", 200},
		// The authorizer's identity is trusted as returned.
		{"POST", "/observatory/objects", "Bearer incomplete", 200},
		{"POST", "/observatory/alias", "", 401},
		{"POST", "/observatory/alias", "Bearer fixture", 200},
		// Any scheme goes to the authorizer: the contract's schemes are
		// documentation only.
		{"GET", "/observatory/legacy-objects", "Bearer fixture", 200},
		{"GET", "/observatory/legacy-objects", "Basic fixture", 200},
		{"GET", "/observatory/internal", "Bearer fixture", 404},
	} {
		req := httptest.NewRequest(request.method, request.path, nil)
		req.Host = bindings.Hostname
		req.Header.Set("X-Auth-Subject", "untrusted")
		req.Header.Set("X-Auth-Forged", "untrusted")
		if request.authorization != "" {
			req.Header.Set("Authorization", request.authorization)
		}
		response := httptest.NewRecorder()
		g.serve(snapshot, response, req)
		if response.Code != request.status {
			t.Errorf("%s %s returned %d, want %d", request.method, request.path, response.Code, request.status)
		}
	}
	reg.openAPI = strings.Replace(raw, "security: [{sessionBearer: []}]", "security: [{clientBasic: []}]", 1)
	changed, err := compileStrict([]registration{reg}, bindings)
	if err != nil {
		t.Fatal(err)
	}
	if string(changed.specYAML) != string(compiled.specYAML) || changed.revision != compiled.revision {
		t.Fatal("an unlisted route's scheme is documentation only")
	}
	reg.openAPI = strings.Replace(raw, "security: [{sessionBearer: []}]", "security: []\n      x-darban-policy: anonymous", 1)
	changed, err = compileStrict([]registration{reg}, bindings)
	if err != nil {
		t.Fatal(err)
	}
	if string(changed.specYAML) != string(compiled.specYAML) || changed.revision == compiled.revision {
		t.Fatal("changing only an unlisted route's auth policy should change the active revision")
	}
	reg.openAPI = strings.Replace(raw, "x-darban-visibility: unlisted", "x-darban-visibility: true", 1)
	if _, err := compileStrict([]registration{reg}, bindings); err == nil {
		t.Fatal("accepted a boolean visibility")
	}
}

func TestSelectsOperationsFromFullServiceContract(t *testing.T) {
	const raw = `openapi: 3.1.0
paths:
  /sky/objects:
    get:
      security: [{sessionBearer: []}]
      responses:
        '200': {description: OK}
    post:
      responses:
        '201': {description: Created}
  /sky/objects/{id}:
    get:
      responses:
        '200': {description: OK}
components:
  securitySchemes:
    sessionBearer: {type: http, scheme: bearer}
`
	binding := serviceBinding{
		Prefix: "/observatory", Origin: "http://observatory.fixtures.svc.cluster.local:80",
		Operations: []operationSelection{{Method: "get", Path: "/sky/objects"}},
	}
	bindings := upstreamBindings{
		Hostname: "api.example.net", Authorization: fixtureAuthorization(),
		Services: map[string]serviceBinding{"observatory": binding},
	}
	reg := registration{serviceName: "observatory", openAPI: raw, rewrites: "[]"}
	got, err := compileStrict([]registration{reg}, bindings)
	if err != nil {
		t.Fatal(err)
	}
	want := compiledOperation{operationKey{"GET", "/observatory/sky/objects"}, "observatory", "/sky/objects", true}
	if !reflect.DeepEqual(got.routes, []compiledOperation{want}) {
		t.Fatalf("unexpected routes: %+v", got.routes)
	}

	reg.openAPI = strings.Replace(raw, "      security: [{sessionBearer: []}]\n", "      security: []\n", 1)
	if _, err := compileStrict([]registration{reg}, bindings); err == nil {
		t.Fatal("selected operation accepted without a credential policy")
	}
	reg.openAPI = strings.Replace(raw, "    get:\n", "    get:\n      x-darban-visibility: internal\n", 1)
	got, err = compileStrict([]registration{reg}, bindings)
	if err != nil || len(got.routes) != 0 || strings.Contains(string(got.specYAML), "/sky/objects") {
		t.Fatalf("selected internal operation must be removed from the active snapshot: %v", err)
	}
}

func TestLocalAndGatewayContractCandidatesMatch(t *testing.T) {
	bindings, err := loadBindings(filepath.Join("testdata", "bindings.json"), true)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := filepath.Abs(filepath.Join("testdata", "local.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	local, err := loadLocal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	store := cache.NewStore(cache.MetaNamespaceKeyFunc)
	for _, reg := range local {
		var rewrites []any
		if err := yaml.Unmarshal([]byte(reg.rewrites), &rewrites); err != nil {
			t.Fatal(err)
		}
		object := plainGatewayContract(reg.serviceName, reg.openAPI)
		if err := unstructured.SetNestedSlice(object.Object, rewrites, "spec", "rewrites"); err != nil {
			t.Fatal(err)
		}
		if reg.defaultVisibility != nil {
			if err := unstructured.SetNestedField(object.Object, string(*reg.defaultVisibility), "spec", "defaultVisibility"); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.Add(object); err != nil {
			t.Fatal(err)
		}
	}
	watched, err := loadClusterRegistrations(store)
	if err != nil {
		t.Fatal(err)
	}
	want, err := compileStrict(local, bindings)
	if err != nil {
		t.Fatal(err)
	}
	got, err := compileStrict(watched, bindings)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("route table, OpenAPI or active revision differ across sources")
	}
}

func TestLocalWatchReloadsReferencedRewrite(t *testing.T) {
	bindings, err := loadBindings(filepath.Join("testdata", "bindings.json"), true)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, file := range []string{
		"local.yaml", "contracts/herbarium/openapi.yaml", "contracts/herbarium/rewrites.yaml",
		"contracts/observatory/openapi.yaml", "contracts/observatory/rewrites.yaml",
		"contracts/discovery/openapi.yaml", "contracts/discovery/rewrites.yaml",
	} {
		data, err := os.ReadFile(filepath.Join("testdata", file))
		if err != nil {
			t.Fatal(err)
		}
		dest := filepath.Join(dir, file)
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var active atomic.Pointer[snapshot]
	reload := &reconciler{gateway: newGateway(bindings), active: &active}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		reload.watchLocal(ctx, filepath.Join(dir, "local.yaml"))
	}()
	defer func() {
		cancel()
		<-done
	}()
	path := operationKey{"GET", "/herbarium/specimens/leaves"}
	// The route is herbarium's own operation until the rewrite sends it to
	// observatory.
	waitPolicy := func(service string) {
		t.Helper()
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			if current := active.Load(); current != nil {
				if route, ok := current.routes[path]; ok && route.protected && route.service == service {
					return
				}
			}
			select {
			case <-timer.C:
				t.Fatalf("local watcher did not activate %s", service)
			case <-ticker.C:
			}
		}
	}
	waitPolicy("herbarium")
	initial := active.Load()
	if !strings.Contains(string(initial.specYAML), "/observatory/sky/v2/objects:") {
		t.Fatal("the upstream version segment disappeared")
	}
	old := initial.revision
	updated, err := os.ReadFile(filepath.Join("testdata", "rewrite.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "contracts/herbarium/rewrites.yaml")
	if err := os.WriteFile(target+".new", updated, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(target+".new", target); err != nil {
		t.Fatal(err)
	}
	waitPolicy("observatory")
	updatedSnapshot := active.Load()
	if updatedSnapshot.revision == old {
		t.Fatal("policy changed without a new snapshot")
	}
	if !strings.Contains(string(updatedSnapshot.specYAML), "operationId: readLeafSpecimens") {
		t.Fatal("rewrite changed the source SDK name")
	}
}

func TestVisibilityDefaultsAndStaticOpenAPI(t *testing.T) {
	const raw = `openapi: 3.1.0
security: [{sessionBearer: []}]
paths:
  /inherited:
    get:
      responses: {'200': {description: Inherited}}
  /listed:
    get:
      operationId: readListed
      tags: [catalog, secondary]
      x-darban-visibility: public
      x-publisher-private: hidden-metadata
      x-documentation-note: public-metadata
      responses: {'200': {description: Listed}}
  /private:
    get:
      x-darban-visibility: internal
  /private-alias:
    get:
      x-darban-visibility: internal
  /old-private:
    get:
      responses: {'200': {description: Old private}}
components:
  securitySchemes:
    sessionBearer: {type: http, scheme: bearer}
`
	const rewrites = `
- from: {method: GET, path: /observatory/private-alias}
  to: {serviceName: observatory, path: /listed}
- from: {method: GET, path: /observatory/old-private}
  to: {serviceName: observatory, path: /private}
`
	internal, unlisted := visibilityInternal, visibilityUnlisted
	bindings := upstreamBindings{
		Hostname: "api.example.net", Authorization: fixtureAuthorization(), DefaultVisibility: &internal,
		Services: map[string]serviceBinding{
			"observatory": {Prefix: "/observatory", Origin: "http://observatory.fixtures.svc.cluster.local:80"},
			"herbarium":   {Prefix: "/herbarium", Origin: "http://herbarium.fixtures.svc.cluster.local:80"},
		},
	}
	regs := []registration{
		{serviceName: "observatory", openAPI: raw, rewrites: rewrites, defaultVisibility: &unlisted},
		{serviceName: "herbarium", openAPI: strings.Replace(raw, "readListed", "ReadHerbarium", 1), rewrites: "[]"},
	}
	withoutDocs, err := compileStrict(regs, bindings)
	if err != nil {
		t.Fatal(err)
	}
	disabled := newGateway(bindings)
	request := httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil)
	request.Host = bindings.Hostname
	response := httptest.NewRecorder()
	disabled.serve(disabled.build(withoutDocs), response, request)
	if response.Code != http.StatusNotFound || withoutDocs.specJSON != nil {
		t.Fatal("OpenAPI endpoints should be disabled by default")
	}

	bindings.OpenAPI = openAPIConfig{YAMLPath: "/docs/openapi.yaml", JSONPath: "/docs/openapi.json", OmitOperationExtensionPrefixes: []string{"x-publisher-"}}
	compiled, err := compileStrict(regs, bindings)
	if err != nil {
		t.Fatal(err)
	}
	g := newGateway(bindings)
	snapshot := g.build(compiled)
	var yamlDoc, jsonDoc map[string]any
	if err := yaml.Unmarshal(compiled.specYAML, &yamlDoc); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(compiled.specJSON, &jsonDoc); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(yamlDoc, jsonDoc) || len(jsonDoc["paths"].(map[string]any)) != 2 {
		t.Fatal("expected two listed operations in equivalent YAML and JSON documents")
	}
	for _, expected := range []string{"readListed", "ReadHerbarium"} {
		if !strings.Contains(string(compiled.specYAML), "operationId: "+expected) {
			t.Errorf("missing operationId %s", expected)
		}
	}
	for _, expected := range []string{"observatoryCatalog", "observatorySecondary", "herbariumCatalog", "herbariumSecondary"} {
		if !strings.Contains(string(compiled.specJSON), expected) {
			t.Errorf("missing tag %s", expected)
		}
	}
	if strings.Contains(string(compiled.specJSON), "hidden-metadata") || !strings.Contains(string(compiled.specJSON), "public-metadata") {
		t.Fatal("expected only configured extension prefixes to be omitted")
	}
	for path, want := range map[string]int{
		"/observatory/listed": 401, "/herbarium/listed": 401, "/observatory/inherited": 401,
		"/herbarium/inherited": 404, "/observatory/private": 404, "/observatory/private-alias": 404,
		"/observatory/old-private": 404, "/openapi.yaml": 404,
	} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Host = bindings.Hostname
		w := httptest.NewRecorder()
		g.serve(snapshot, w, r)
		if w.Code != want {
			t.Errorf("GET %s returned %d, want %d", path, w.Code, want)
		}
	}
	for _, doc := range []struct {
		path, contentType string
		body              []byte
	}{
		{bindings.OpenAPI.YAMLPath, "application/yaml", compiled.specYAML},
		{bindings.OpenAPI.JSONPath, "application/json", compiled.specJSON},
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			r := httptest.NewRequest(method, doc.path, nil)
			r.Host = bindings.Hostname
			w := httptest.NewRecorder()
			g.serve(snapshot, w, r)
			want := string(doc.body)
			if method == http.MethodHead {
				want = ""
			}
			if w.Code != http.StatusOK || w.Header().Get("Content-Type") != doc.contentType || w.Body.String() != want {
				t.Errorf("unexpected %s response for %s", method, doc.path)
			}
		}
	}
	bindings.OpenAPI.YAMLPath = "/observatory/listed"
	if _, err := compileStrict(regs, bindings); err == nil {
		t.Fatal("accepted an OpenAPI endpoint that would hide an operation")
	}
}

func TestRejectsDuplicatePublishedOperationIDs(t *testing.T) {
	const raw = `openapi: 3.1.0
paths:
  /objects:
    get:
      operationId: listObjects
      security: []
      x-darban-policy: anonymous
      responses: {'200': {description: OK}}
`
	regs := []registration{
		{serviceName: "night-sky", openAPI: raw, rewrites: "[]"},
		{serviceName: "catalog", openAPI: raw, rewrites: "[]"},
	}
	bindings := upstreamBindings{Services: map[string]serviceBinding{
		"night-sky": {Prefix: "/night-sky", Origin: "http://night-sky.fixtures.svc.cluster.local:80"},
		"catalog":   {Prefix: "/catalog", Origin: "http://catalog.fixtures.svc.cluster.local:80"},
	}}
	_, err := compileStrict(regs, bindings)
	if err == nil || !strings.Contains(err.Error(), `duplicate operationId "listObjects"`) {
		t.Fatalf("expected duplicate upstream operationId to be rejected, got %v", err)
	}
}

func TestAnonymousPolicyUsesDarbanExtension(t *testing.T) {
	contract := func(extension string) string {
		return "openapi: 3.1.0\npaths:\n  /objects:\n    get:\n      operationId: listObjects\n      security: []\n      " +
			extension + ": anonymous\n      responses: {'200': {description: OK}}\n"
	}
	bindings := upstreamBindings{Services: map[string]serviceBinding{
		"catalog": {Prefix: "/catalog", Origin: "http://catalog.fixtures.svc.cluster.local:80"},
	}}
	compiled, err := compileStrict([]registration{{serviceName: "catalog", openAPI: contract("x-darban-policy"), rewrites: "[]"}}, bindings)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(compiled.specYAML), "x-darban-policy") {
		t.Fatal("combined OpenAPI exposed x-darban-policy")
	}
	_, err = compileStrict([]registration{{serviceName: "catalog", openAPI: contract("x-other-policy"), rewrites: "[]"}}, bindings)
	if err == nil || !strings.Contains(err.Error(), "explicit credential policy required") {
		t.Fatalf("expected only x-darban-policy to make an operation anonymous, got %v", err)
	}
}

func TestTagOptions(t *testing.T) {
	for _, test := range []struct {
		name     string
		settings openAPIConfig
		tags     any
		want     any
	}{
		{"default prefixes all", openAPIConfig{}, []any{"objects", "DeepSky"}, []any{"nightSkyObjects", "nightSkyDeepSky"}},
		{"first only", openAPIConfig{PrefixTags: firstTagOnly}, []any{"objects", "DeepSky"}, []any{"nightSkyObjects", "DeepSky"}},
		{"preserve absent tags", openAPIConfig{}, nil, nil},
		{"populate absent tags", openAPIConfig{PopulateEmptyTags: true}, nil, []string{"night-sky"}},
		{"populate empty tags", openAPIConfig{PopulateEmptyTags: true}, []any{}, []string{"night-sky"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			operation := make(map[string]any)
			if test.tags != nil {
				operation["tags"] = test.tags
			}
			if err := applyTagOptions(operation, "night-sky", test.settings); err != nil {
				t.Fatal(err)
			}
			if actual := operation["tags"]; !reflect.DeepEqual(actual, test.want) {
				t.Errorf("expected tags %#v, got %#v", test.want, actual)
			}
		})
	}
}

func TestUnpublishedContractRoutesWithoutChangingTheDocument(t *testing.T) {
	bindings, err := loadBindings("testdata/bindings.json", true)
	if err != nil {
		t.Fatal(err)
	}
	registrations, err := loadLocal("testdata/local.yaml")
	if err != nil {
		t.Fatal(err)
	}
	bindings.Services["archive"] = serviceBinding{Origin: "http://localhost:9000", Prefix: "/archive", Publish: new(false)}
	// A bound service without a contract fails closed; the document and the
	// other routes do not depend on it.
	before, err := compileStrict(registrations, bindings)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(before.unserved, "/archive") {
		t.Fatalf("unserved = %v", before.unserved)
	}
	catalog := registration{
		serviceName: "archive",
		openAPI: `openapi: 3.1.0
paths:
  /private/{id}:
    get:
      x-darban-visibility: internal
  /items/{id}:
    get:
      x-darban-visibility: public
      security: []
      x-darban-policy: anonymous
      responses: {'200': {description: OK}}
`,
		rewrites: "[]",
	}
	after, err := compileStrict(append(registrations, catalog), bindings)
	if err != nil {
		t.Fatal(err)
	}
	if string(before.specYAML) != string(after.specYAML) || !slices.Contains(routePaths(after), "/archive/items/{id}") ||
		!slices.Contains(after.denied, operationKey{"GET", "/archive/private/{id}"}) || slices.Contains(after.unserved, "/archive") {
		t.Fatalf("routes %v denied %v unserved %v", routePaths(after), after.denied, after.unserved)
	}
	catalog.openAPI = strings.Replace(catalog.openAPI, "      x-darban-policy: anonymous\n", "", 1)
	if _, err := compileStrict(append(registrations, catalog), bindings); err == nil {
		t.Fatal("an unpublished operation without a credential policy was accepted")
	}
}
