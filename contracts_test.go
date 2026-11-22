package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/yaml"
)

func fixtureAuthorization() authorizationConfig {
	return authorizationConfig{
		Path:                "/authorize",
		ResponseHeaders:     []string{"X-Auth-Subject", "X-Auth-Account", "X-Auth-Debug-Allowed"},
		StripHeaderPrefixes: []string{"X-Auth-"},
		Profiles: map[string]credentialProfile{
			"sessionBearer": {Scheme: "bearer", RequiredHeaders: []string{"X-Auth-Subject", "X-Auth-Account"}},
			"clientBasic":   {Scheme: "basic", RequiredHeaders: []string{"X-Auth-Subject"}},
		},
	}
}

func TestUnlistedOperationsRetainRoutingAndSecurity(t *testing.T) {
	const raw = `openapi: 3.1.0
paths:
  /objects:
    get:
      x-darban-visibility: public
      x-gateway-visibility: internal
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
      x-gateway-visibility: unlisted
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
- from: {method: POST, path: /observatory/v1/alias}
  to: {serviceName: observatory, path: /objects}
- from: {method: GET, path: /observatory/v1/legacy-objects}
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
		Services: map[string]serviceBinding{"observatory": {Prefix: "/observatory/v1", Origin: backend.URL}},
	}
	reg := registration{serviceName: "observatory", openAPI: raw, rewrites: rewrites}
	compiled, err := compile([]registration{reg}, bindings)
	if err != nil {
		t.Fatal(err)
	}
	for _, hidden := range []string{"post:", "/observatory/v1/alias", "/observatory/v1/legacy-objects", "/observatory/v1/internal", "HiddenResponse", "sessionBearer", "x-darban-visibility", "x-gateway-visibility"} {
		if strings.Contains(string(compiled.specYAML), hidden) {
			t.Fatalf("combined OpenAPI exposed %s", hidden)
		}
	}
	if !strings.Contains(string(compiled.specYAML), "/observatory/v1/objects:") {
		t.Fatal("listed operation on the same path disappeared")
	}

	g := newGateway(bindings)
	snapshot := g.build(compiled)
	for _, request := range []struct {
		method, path, authorization string
		status                      int
	}{
		{"POST", "/observatory/v1/objects", "", 401},
		{"POST", "/observatory/v1/objects", "Bearer fixture", 200},
		{"POST", "/observatory/v1/objects", "Bearer incomplete", 503},
		{"POST", "/observatory/v1/alias", "", 401},
		{"POST", "/observatory/v1/alias", "Bearer fixture", 200},
		{"GET", "/observatory/v1/legacy-objects", "Bearer fixture", 401},
		{"GET", "/observatory/v1/legacy-objects", "Basic fixture", 200},
		{"GET", "/observatory/v1/internal", "Bearer fixture", 404},
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
	changed, err := compile([]registration{reg}, bindings)
	if err != nil {
		t.Fatal(err)
	}
	if string(changed.specYAML) != string(compiled.specYAML) || changed.revision == compiled.revision {
		t.Fatal("changing only an unlisted route's auth policy should change the active revision")
	}
	reg.openAPI = strings.Replace(raw, "x-darban-visibility: unlisted", "x-darban-visibility: true", 1)
	if _, err := compile([]registration{reg}, bindings); err == nil {
		t.Fatal("accepted a boolean visibility")
	}
}

func TestSelectsOperationsFromFullServiceContract(t *testing.T) {
	const raw = `openapi: 3.1.0
paths:
  /sky/objects:
    get:
      responses:
        '200': {description: OK}
    post:
      responses:
        '201': {description: Created}
  /sky/objects/{id}:
    get:
      responses:
        '200': {description: OK}
`
	binding := serviceBinding{
		Prefix: "/observatory/v1",
		Operations: []operationSelection{{
			Method: "get", Path: "/sky/objects",
			Legacy: &legacySecurity{Profiles: []string{"sessionBearer"}},
		}},
	}
	bindings := upstreamBindings{
		Hostname: "api.example.net", Authorization: fixtureAuthorization(),
		Services: map[string]serviceBinding{"observatory": binding},
	}
	reg := registration{serviceName: "observatory", openAPI: raw, rewrites: "[]"}
	got, err := compile([]registration{reg}, bindings)
	if err != nil {
		t.Fatal(err)
	}
	want := compiledOperation{operationKey{"GET", "/observatory/v1/sky/objects"}, "observatory", "/sky/objects", []string{"sessionBearer"}}
	if !reflect.DeepEqual(got.routes, []compiledOperation{want}) {
		t.Fatalf("unexpected routes: %+v", got.routes)
	}

	reg.openAPI = strings.Replace(raw, "    get:\n", "    get:\n      security: []\n", 1)
	if _, err := compile([]registration{reg}, bindings); err == nil {
		t.Fatal("selected operation accepted with a changed security policy")
	}
	reg.openAPI = strings.Replace(raw, "    get:\n", "    get:\n      x-darban-visibility: internal\n", 1)
	got, err = compile([]registration{reg}, bindings)
	if err != nil || len(got.routes) != 0 || strings.Contains(string(got.specYAML), "/sky/objects") {
		t.Fatalf("selected internal operation must be removed from the active snapshot: %v", err)
	}
}

func TestLocalAndConfigMapCandidatesMatch(t *testing.T) {
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
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: contractNamePrefix + reg.serviceName, Namespace: "darban-fixtures"},
			Data:       map[string]string{"serviceName": reg.serviceName, "openapi.yaml": reg.openAPI, "rewrites.yaml": reg.rewrites},
		}
		if err := store.Add(cm); err != nil {
			t.Fatal(err)
		}
	}
	watched, err := registrationsFromStore(store)
	if err != nil {
		t.Fatal(err)
	}
	want, err := compile(local, bindings)
	if err != nil {
		t.Fatal(err)
	}
	got, err := compile(watched, bindings)
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
	path := operationKey{"GET", "/herbarium/v1/specimens/leaves"}
	waitPolicy := func(profile string) {
		t.Helper()
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			if current := active.Load(); current != nil &&
				reflect.DeepEqual(current.routes[path].credentials, []string{profile}) {
				return
			}
			select {
			case <-timer.C:
				t.Fatalf("local watcher did not activate %s", profile)
			case <-ticker.C:
			}
		}
	}
	waitPolicy("clientBasic")
	old := active.Load().revision
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
	waitPolicy("sessionBearer")
	if active.Load().revision == old {
		t.Fatal("policy changed without a new snapshot")
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
- from: {method: GET, path: /observatory/v1/private-alias}
  to: {serviceName: observatory, path: /listed}
- from: {method: GET, path: /observatory/v1/old-private}
  to: {serviceName: observatory, path: /private}
`
	internal, unlisted := visibilityInternal, visibilityUnlisted
	bindings := upstreamBindings{
		Hostname: "api.example.net", Authorization: fixtureAuthorization(), DefaultVisibility: &internal,
		Services: map[string]serviceBinding{"observatory": {Prefix: "/observatory/v1"}, "herbarium": {Prefix: "/herbarium/v1"}},
	}
	regs := []registration{
		{serviceName: "observatory", openAPI: raw, rewrites: rewrites, defaultVisibility: &unlisted},
		{serviceName: "herbarium", openAPI: raw, rewrites: "[]"},
	}
	withoutDocs, err := compile(regs, bindings)
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
	compiled, err := compile(regs, bindings)
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
	if strings.Contains(string(compiled.specJSON), "hidden-metadata") || !strings.Contains(string(compiled.specJSON), "public-metadata") {
		t.Fatal("expected only configured extension prefixes to be omitted")
	}
	for path, want := range map[string]int{
		"/observatory/v1/listed": 401, "/herbarium/v1/listed": 401, "/observatory/v1/inherited": 401,
		"/herbarium/v1/inherited": 404, "/observatory/v1/private": 404, "/observatory/v1/private-alias": 404,
		"/observatory/v1/old-private": 404, "/openapi.yaml": 404,
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
	bindings.OpenAPI.YAMLPath = "/observatory/v1/listed"
	if _, err := compile(regs, bindings); err == nil {
		t.Fatal("accepted an OpenAPI endpoint that would shadow an operation")
	}
}
