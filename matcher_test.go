package main

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

func anonymousOperation(method, path, operationID string) string {
	return "  " + path + ":\n    " + method + ":\n      operationId: " + operationID +
		"\n      security: []\n      x-darban-policy: anonymous\n      responses: {'200': {description: OK}}\n"
}

// templateHarness serves the shop service, mounted at /api, through its
// contract and records what the upstream receives.
type templateHarness struct {
	*skipHarness
	received []string
}

func newTemplateHarness(t *testing.T, bindings upstreamBindings, paths ...string) *templateHarness {
	h := &templateHarness{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.received = append(h.received, r.Method+" "+r.URL.EscapedPath())
		w.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(upstream.Close)
	shop := bindings.Services["shop"]
	shop.Origin = upstream.URL
	bindings.Services["shop"] = shop
	if route, ok := bindings.ServiceRoutes["/shop"]; ok {
		route.Origin = upstream.URL
		bindings.ServiceRoutes["/shop"] = route
	}
	h.skipHarness = newSkipHarness(t, bindings)
	h.apply(registration{serviceName: "shop", rewrites: "[]", openAPI: "openapi: 3.1.0\npaths:\n" + strings.Join(paths, "")})
	if status := h.status()["shop"]; status.Rejected {
		t.Fatalf("contract rejected: %+v", status.LastRejection)
	}
	return h
}

func (h *templateHarness) do(method, target string) (int, string) {
	h.received = nil
	req := httptest.NewRequest(method, target, nil)
	req.Host = h.g.bindings.Hostname
	res := httptest.NewRecorder()
	h.g.serve(h.active.Load(), res, req)
	upstream := ""
	if len(h.received) == 1 {
		upstream = h.received[0]
	}
	return res.Code, upstream
}

func shopBindings() upstreamBindings {
	return upstreamBindings{Hostname: "api.example.net", Services: map[string]serviceBinding{"shop": {Prefix: "/shop", Mount: "/api"}}}
}

func TestTemplatedRoutesMatchLiteralFirstWithBacktracking(t *testing.T) {
	h := newTemplateHarness(t, shopBindings(),
		anonymousOperation("get", "/api/items/{id}", "getItem"),
		anonymousOperation("get", "/api/items/special", "getSpecial"),
		anonymousOperation("get", "/api/items/special/{part}/view", "viewSpecial"),
		anonymousOperation("get", "/api/items/{id}/reviews/latest", "latestReview"),
		anonymousOperation("put", "/api/Items.v2/{itemId}/@tags/{tag}", "tagItem"),
		"  /api/items/{id}/secret:\n    get:\n      x-darban-visibility: internal\n",
	)
	for _, test := range []struct {
		method, path   string
		code           int
		upstreamTarget string
	}{
		{"GET", "/shop/items/special", 418, "GET /api/items/special"},
		{"GET", "/shop/items/42", 418, "GET /api/items/42"},
		{"GET", "/shop/items/a%20b", 418, "GET /api/items/a%20b"},
		{"GET", "/shop/items/%73pecial", 418, "GET /api/items/special"},
		// special/{part}/view does not continue with reviews, so backtrack to {id}.
		{"GET", "/shop/items/special/reviews/latest", 418, "GET /api/items/special/reviews/latest"},
		{"GET", "/shop/items/special/x/view", 418, "GET /api/items/special/x/view"},
		{"GET", "/shop/items/42/", 418, "GET /api/items/42"},
		{"PUT", "/shop/Items.v2/7/@tags/red~1", 418, "PUT /api/Items.v2/7/@tags/red~1"},
		{"GET", "/shop/items/42/secret", 404, ""},
		{"HEAD", "/shop/items/42/secret", 404, ""},
		{"POST", "/shop/items/42", 404, ""},
		{"GET", "/shop/items", 404, ""},
		{"GET", "/shop/items/42/reviews", 404, ""},
		// HEAD is implied by GET, and sent upstream as GET.
		{"HEAD", "/shop/items/42", 418, "GET /api/items/42"},
		// Guards: no encoded separators and no path that Clean changes.
		{"GET", "/shop/items/a%2Fb", 404, ""},
		{"GET", "/shop/items/a%2fb/reviews/latest", 404, ""},
		{"GET", "/shop/items/a%5Cb", 404, ""},
		{"GET", "/shop//items/42", 404, ""},
		{"GET", "/shop/items//42", 404, ""},
		{"GET", "/shop/items/./42", 404, ""},
		{"GET", "/shop/items/x/../42", 404, ""},
		{"GET", "/shop/items/%2E%2E", 404, ""},
		{"GET", "/shop/items/%2e", 404, ""},
	} {
		code, upstream := h.do(test.method, test.path)
		if code != test.code || upstream != test.upstreamTarget {
			t.Errorf("%s %s = %d %q, want %d %q", test.method, test.path, code, upstream, test.code, test.upstreamTarget)
		}
	}
}

func TestLiteralWinsOverParameterBetweenRoutes(t *testing.T) {
	h := newTemplateHarness(t, shopBindings(),
		anonymousOperation("get", "/api/items/{id}", "getItem"),
		anonymousOperation("get", "/api/items/special", "getSpecial"),
		anonymousOperation("get", "/api/items/special/{part}/view", "viewSpecial"),
		anonymousOperation("get", "/api/items/{id}/reviews/latest", "latestReview"),
	)
	table := h.active.Load().routeTable()
	for path, want := range map[string]string{
		"/shop/items/special":                "/shop/items/special",
		"/shop/items/42":                     "/shop/items/{id}",
		"/shop/items/special/x/view":         "/shop/items/special/{part}/view",
		"/shop/items/special/reviews/latest": "/shop/items/{id}/reviews/latest",
	} {
		entry := table.lookup(http.MethodGet, strings.Split(strings.TrimPrefix(path, "/"), "/"))
		if entry == nil || entry.kind != entryRoute || entry.key != (operationKey{http.MethodGet, want}) {
			t.Errorf("GET %s matched %+v, want %s", path, entry, want)
		}
	}
}

func TestExplicitHeadOperationWinsOverGet(t *testing.T) {
	h := newTemplateHarness(t, shopBindings(),
		anonymousOperation("get", "/api/items/{id}", "getItem")+
			"    head:\n      operationId: headItem\n      security: []\n      x-darban-policy: anonymous\n      responses: {'200': {description: OK}}\n",
		anonymousOperation("get", "/api/docs", "getDocs"),
		"  /api/docs/{id}:\n    get:\n      x-darban-visibility: internal\n",
	)
	if code, upstream := h.do("HEAD", "/shop/items/1"); code != 418 || upstream != "HEAD /api/items/1" {
		t.Fatalf("HEAD = %d %q", code, upstream)
	}
	route := h.active.Load().routeTable().lookup(http.MethodHead, []string{"shop", "items", "1"})
	if route == nil || route.key.method != http.MethodHead {
		t.Fatalf("HEAD matched %+v", route)
	}
	if code, _ := h.do("HEAD", "/shop/docs/1"); code != 404 {
		t.Fatalf("HEAD on an internal GET = %d", code)
	}
}

func TestDirectRouteGatesContractOperations(t *testing.T) {
	bindings := shopBindings()
	bindings.Services["shop"] = serviceBinding{Prefix: "/shop"}
	bindings.ServiceRoutes = map[string]serviceRoute{"/shop": {BackendAuth: true, DeniedPaths: []string{"/items/9"}}}
	h := newTemplateHarness(t, bindings,
		anonymousOperation("get", "/items/{id}", "getItem"),
		"  /items/{id}/secret:\n    get:\n      x-darban-visibility: internal\n",
	)
	for _, test := range []struct {
		path, upstreamTarget string
		code                 int
	}{
		{"/shop/items/1", "GET /items/1", 418},
		{"/shop/items/1/secret/", "", 404},
		// A direct route refuses a non-canonical path outright.
		{"/shop/items/a%2Fb", "", 404},
		{"/shop/items//1/secret", "", 404},
		{"/shop/items/1/x/../secret", "", 404},
		// The direct route's path policy also gates contract operations.
		{"/shop/items/9", "", 404},
		// An encoded prefix would match the contract operation for /shop
		// without that policy.
		{"/sh%6Fp/items/9", "", 404},
		{"/%73hop/items/1/secret", "", 404},
		// An absolute-form target has no path prefix to key the policy on.
		{"https://api.example.net/shop/items/9", "", 404},
	} {
		if code, upstream := h.do("GET", test.path); code != test.code || upstream != test.upstreamTarget {
			t.Errorf("GET %s = %d %q, want %d %q", test.path, code, upstream, test.code, test.upstreamTarget)
		}
	}
}

func TestOperationPathValidation(t *testing.T) {
	bindings := isolationBindings("shop")
	for name, test := range map[string]struct {
		paths string
		valid bool
	}{
		"template":           {anonymousOperation("get", "/items/{id}", "a"), true},
		"charset":            {anonymousOperation("get", "/.well-known/A_b.c~d@e-f", "a"), true},
		"partial template":   {anonymousOperation("get", "/files/{name}.txt", "a"), false},
		"empty parameter":    {anonymousOperation("get", "/files/{}", "a"), false},
		"dot segment":        {anonymousOperation("get", "/files/../x", "a"), false},
		"empty segment":      {anonymousOperation("get", "/files//x", "a"), false},
		"trailing slash":     {anonymousOperation("get", "/files/", "a"), false},
		"repeated parameter": {anonymousOperation("get", "/files/{id}/{id}", "a"), false},
		"bad character":      {anonymousOperation("get", "/files/a+b", "a"), false},
		"same shape": {anonymousOperation("get", "/items/{id}", "a") +
			anonymousOperation("get", "/items/{itemId}", "b"), false},
		"same shape, other method": {anonymousOperation("get", "/items/{id}", "a") +
			anonymousOperation("post", "/items/{itemId}", "b"), true},
		"same shape with an internal operation": {anonymousOperation("get", "/items/{id}", "a") +
			"  /items/{itemId}:\n    get:\n      x-darban-visibility: internal\n", false},
		"literal and parameter": {anonymousOperation("get", "/items/{id}", "a") +
			anonymousOperation("get", "/items/new", "b"), true},
	} {
		// YAML cannot hold two operations of one method on one path, so the
		// shape tests use two paths.
		reg := registration{serviceName: "shop", rewrites: "[]", openAPI: "openapi: 3.1.0\npaths:\n" + test.paths}
		_, report := compile([]registration{reg}, bindings, nil)
		if rejected := report.services["shop"].rejection != ""; rejected == test.valid {
			t.Errorf("%s: rejection %q", name, report.services["shop"].rejection)
		}
	}
}

func TestDiscriminatorMappingIsImportedAndRenamed(t *testing.T) {
	contract := `openapi: 3.1.0
paths:
  /pets:
    get:
      operationId: listPets
      security: []
      x-darban-policy: anonymous
      responses:
        '200':
          description: OK
          content:
            application/json:
              schema: {$ref: '#/components/schemas/Pet'}
components:
  schemas:
    Pet:
      oneOf: [{$ref: '#/components/schemas/Cat'}, {$ref: '#/components/schemas/Dog'}]
      discriminator:
        propertyName: kind
        x-note: kept
        mapping: {cat: '#/components/schemas/Cat', dog: Dog, bird: Bird}
      properties:
        discriminator: {$ref: '#/components/schemas/Tag'}
    Cat: {type: object}
    Dog: {type: object}
    Bird: {type: object}
    Tag: {type: string}
    Unused: {type: object}
`
	got, report := compile([]registration{{serviceName: "zoo", rewrites: "[]", openAPI: contract}}, isolationBindings("zoo"), nil)
	if rejection := report.services["zoo"].rejection; rejection != "" {
		t.Fatal(rejection)
	}
	var document struct {
		Components struct {
			Schemas map[string]map[string]any `json:"schemas"`
		} `json:"components"`
	}
	if err := yaml.Unmarshal(got.specYAML, &document); err != nil {
		t.Fatal(err)
	}
	schemas := document.Components.Schemas
	for _, name := range []string{"zoo.Pet", "zoo.Cat", "zoo.Dog", "zoo.Bird", "zoo.Tag"} {
		if _, ok := schemas[name]; !ok {
			t.Errorf("%s not imported: %v", name, schemas)
		}
	}
	if _, ok := schemas["zoo.Unused"]; ok {
		t.Error("an unreferenced schema was imported")
	}
	discriminator := schemas["zoo.Pet"]["discriminator"].(map[string]any)
	mapping := discriminator["mapping"].(map[string]any)
	if mapping["cat"] != "#/components/schemas/zoo.Cat" || mapping["dog"] != "zoo.Dog" || mapping["bird"] != "zoo.Bird" ||
		discriminator["propertyName"] != "kind" || discriminator["x-note"] != "kept" {
		t.Fatalf("discriminator %v", discriminator)
	}
	property := schemas["zoo.Pet"]["properties"].(map[string]any)["discriminator"].(map[string]any)
	if property["$ref"] != "#/components/schemas/zoo.Tag" {
		t.Fatalf("property named discriminator %v", property)
	}

	for name, mapping := range map[string]string{
		"external document": "{cat: 'other.yaml#/components/schemas/Cat'}",
		"unknown schema":    "{cat: Missing}",
	} {
		bad := strings.Replace(contract, "{cat: '#/components/schemas/Cat', dog: Dog, bird: Bird}", mapping, 1)
		_, report := compile([]registration{{serviceName: "zoo", rewrites: "[]", openAPI: bad}}, isolationBindings("zoo"), nil)
		if report.services["zoo"].rejection == "" {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestInternalPartialTemplateOnDirectRoute(t *testing.T) {
	bindings := shopBindings()
	bindings.Services["shop"] = serviceBinding{Prefix: "/shop"}
	bindings.ServiceRoutes = map[string]serviceRoute{"/shop": {BackendAuth: true}}
	h := newTemplateHarness(t, bindings,
		anonymousOperation("get", "/files/{id}", "getFile"),
		"  /files/{name}.txt:\n    get:\n      x-darban-visibility: internal\n",
		"  /logs/{name}.txt:\n    get:\n      x-darban-visibility: internal\n",
	)
	// The internal pattern wins over the routed parameter. A path it does not
	// match is still routed, or goes to the direct route.
	for path, want := range map[string]int{"/shop/files/a.txt": 404, "/shop/files/a": 418, "/shop/logs/a.txt": 404, "/shop/logs/a": 418, "/shop/other": 418} {
		if code, _ := h.do("GET", path); code != want {
			t.Errorf("GET %s = %d, want %d", path, code, want)
		}
	}
}

func TestInternalOperationsWinOverTemplates(t *testing.T) {
	// No direct route, so a denial is the only thing that keeps a template
	// from reaching an internal operation.
	h := newTemplateHarness(t, shopBindings(),
		anonymousOperation("get", "/api/v1/{id}", "getItem"),
		anonymousOperation("get", "/api/v2/{id}/{part}", "getPart"),
		"  /api/v1/secret:\n    get:\n      x-darban-visibility: internal\n",
		"  /api/v1/items{batch}:\n    get:\n      x-darban-visibility: internal\n",
		"  /api/v1/jobs:run:\n    get:\n      x-darban-visibility: internal\n",
		"  /api/v2/{id}/admin:\n    get:\n      x-darban-visibility: internal\n",
	)
	table := h.active.Load().routeTable()
	for _, test := range []struct {
		method, path string
		key          operationKey
		kind         routeEntryKind
	}{
		{"GET", "/shop/v1/secret", operationKey{"GET", "/shop/v1/secret"}, entryDenied},
		{"HEAD", "/shop/v1/secret", operationKey{"GET", "/shop/v1/secret"}, entryDenied},
		{"GET", "/shop/v1/items:batch", operationKey{"GET", "/shop/v1/items{batch}"}, entryDenied},
		{"GET", "/shop/v1/jobs:run", operationKey{"GET", "/shop/v1/jobs:run"}, entryDenied},
		{"GET", "/shop/v1/items", operationKey{"GET", "/shop/v1/{id}"}, entryRoute},
		{"GET", "/shop/v1/42", operationKey{"GET", "/shop/v1/{id}"}, entryRoute},
		{"GET", "/shop/v2/7/admin", operationKey{"GET", "/shop/v2/{id}/admin"}, entryDenied},
		{"GET", "/shop/v2/7/other", operationKey{"GET", "/shop/v2/{id}/{part}"}, entryRoute},
	} {
		entry := table.lookup(test.method, strings.Split(strings.TrimPrefix(test.path, "/"), "/"))
		if entry == nil || entry.key != test.key || entry.kind != test.kind {
			t.Errorf("%s %s matched %+v, want %v %v", test.method, test.path, entry, test.key, test.kind)
		}
		want := 404
		if test.kind == entryRoute {
			want = 418
		}
		if code, _ := h.do(test.method, test.path); code != want {
			t.Errorf("%s %s = %d, want %d", test.method, test.path, code, want)
		}
	}
	for _, path := range []string{"/shop/v1//secret", "/shop/v1/x/../secret", "/shop/v1/a%2F..%2Fsecret", "/shop/v1/%2e%2e/v1/secret", "/sh%6Fp/v1/secret"} {
		if code, upstream := h.do("GET", path); code != 404 || upstream != "" {
			t.Errorf("GET %s = %d %q", path, code, upstream)
		}
	}
}

func TestSelectedTemplateDoesNotCaptureUnselectedOperations(t *testing.T) {
	paths := []string{
		anonymousOperation("get", "/items/{id}", "getItem"),
		anonymousOperation("get", "/items/special", "getSpecial"),
		"  /items/secret:\n    get:\n      x-darban-visibility: internal\n",
	}
	selection := []operationSelection{{Method: "get", Path: "/items/{id}"}}

	// On a direct route, an unselected operation keeps the route's own policy.
	direct := shopBindings()
	direct.Services["shop"] = serviceBinding{Prefix: "/shop", Operations: selection}
	direct.ServiceRoutes = map[string]serviceRoute{"/shop": {AuthProfiles: []string{"account"}, PublicPaths: []string{"/items/special"}}}
	direct.Authorization.Profiles = map[string]credentialProfile{"account": {Scheme: "bearer"}}
	h := newTemplateHarness(t, direct, paths...)
	for path, want := range map[string]int{"/shop/items/1": 418, "/shop/items/special": 418, "/shop/items/secret": 404, "/shop/items/other/x": 401} {
		if code, _ := h.do("GET", path); code != want {
			t.Errorf("direct: GET %s = %d, want %d", path, code, want)
		}
	}
	entry := h.active.Load().routeTable().lookup("GET", []string{"shop", "items", "special"})
	if entry == nil || entry.kind != entryPassthrough {
		t.Fatalf("unselected operation matched %+v", entry)
	}

	// Without a direct route, an unselected operation is not served at all.
	plain := isolationBindings("shop")
	plain.Services["shop"] = serviceBinding{Prefix: "/shop", Operations: selection}
	h = newTemplateHarness(t, plain, paths...)
	for path, want := range map[string]int{"/shop/items/1": 418, "/shop/items/special": 404, "/shop/items/secret": 404} {
		if code, _ := h.do("GET", path); code != want {
			t.Errorf("plain: GET %s = %d, want %d", path, code, want)
		}
	}
}

func composedComponents(t *testing.T, contract string) (map[string]map[string]any, map[string]any) {
	t.Helper()
	got, report := compile([]registration{{serviceName: "zoo", rewrites: "[]", openAPI: contract}}, isolationBindings("zoo"), nil)
	if rejection := report.services["zoo"].rejection; rejection != "" {
		t.Fatal(rejection)
	}
	var document struct {
		Paths      map[string]map[string]any `json:"paths"`
		Components struct {
			Schemas   map[string]map[string]any `json:"schemas"`
			Responses map[string]any            `json:"responses"`
		} `json:"components"`
	}
	if err := yaml.Unmarshal(got.specYAML, &document); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got.specYAML), "'#/components/schemas/Cat'") || strings.Contains(string(got.specYAML), "#/components/schemas/Tag\n") {
		t.Fatalf("a reference was not renamed:\n%s", got.specYAML)
	}
	return document.Components.Schemas, document.Paths["/zoo/pets"]["get"].(map[string]any)
}

func TestReferencesUnderNamesThatAreKeywordsAreRenamed(t *testing.T) {
	schemas, operation := composedComponents(t, `openapi: 3.1.0
paths:
  /pets:
    get:
      operationId: listPets
      security: []
      x-darban-policy: anonymous
      responses:
        '200':
          description: OK
          content:
            application/json:
              schema: {$ref: '#/components/schemas/Settings'}
        default: {$ref: '#/components/responses/Error'}
components:
  responses:
    Error: {description: Error}
  schemas:
    Settings:
      type: object
      default: {$ref: not-a-reference}
      properties:
        default: {anyOf: [{$ref: '#/components/schemas/Tag'}, {type: 'null'}]}
        example: {$ref: '#/components/schemas/Tag'}
        enum: {$ref: '#/components/schemas/Tag'}
        const: {$ref: '#/components/schemas/Tag'}
        $ref: {type: string}
    Tag: {type: string}
`)
	properties := schemas["zoo.Settings"]["properties"].(map[string]any)
	for _, name := range []string{"example", "enum", "const"} {
		if ref := properties[name].(map[string]any)["$ref"]; ref != "#/components/schemas/zoo.Tag" {
			t.Errorf("property %s: %v", name, ref)
		}
	}
	if ref := properties["default"].(map[string]any)["anyOf"].([]any)[0].(map[string]any)["$ref"]; ref != "#/components/schemas/zoo.Tag" {
		t.Errorf("property default: %v", ref)
	}
	if properties["$ref"].(map[string]any)["type"] != "string" {
		t.Errorf("property $ref: %v", properties["$ref"])
	}
	// A schema's own default is data.
	if schemas["zoo.Settings"]["default"].(map[string]any)["$ref"] != "not-a-reference" {
		t.Errorf("default value changed: %v", schemas["zoo.Settings"]["default"])
	}
	if ref := operation["responses"].(map[string]any)["default"].(map[string]any)["$ref"]; ref != "#/components/responses/zoo.Error" {
		t.Errorf("default response: %v", ref)
	}
}

func TestDiscriminatorExtensionsAndInferredValues(t *testing.T) {
	schemas, _ := composedComponents(t, `openapi: 3.1.0
paths:
  /pets:
    get:
      operationId: listPets
      security: []
      x-darban-policy: anonymous
      responses:
        '200':
          description: OK
          content:
            application/json:
              schema:
                oneOf: [{$ref: '#/components/schemas/Pet'}, {$ref: '#/components/schemas/Animal'}, {$ref: '#/components/schemas/Fish'}]
components:
  schemas:
    Pet:
      oneOf: [{$ref: '#/components/schemas/Cat'}, {$ref: '#/components/schemas/Dog'}, {$ref: '#/components/schemas/Bird'}]
      discriminator:
        propertyName: kind
        x-default: {$ref: '#/components/schemas/Cat'}
        mapping: {hound: Dog}
    Cat: {type: object}
    Dog: {type: object}
    Bird: {type: object}
    Animal:
      type: object
      discriminator: {propertyName: species}
    Fish:
      allOf: [{$ref: '#/components/schemas/Animal'}, {type: object}]
    Snake:
      allOf: [{$ref: '#/components/schemas/Animal'}, {$ref: '#/components/schemas/Missing'}]
`)
	pet := schemas["zoo.Pet"]["discriminator"].(map[string]any)
	if ref := pet["x-default"].(map[string]any)["$ref"]; ref != "#/components/schemas/zoo.Cat" {
		t.Errorf("x- extension: %v", ref)
	}
	// Dog is mapped explicitly. Cat and Bird keep the values they inferred.
	want := map[string]any{"hound": "zoo.Dog", "Cat": "#/components/schemas/zoo.Cat", "Bird": "#/components/schemas/zoo.Bird"}
	if mapping := pet["mapping"].(map[string]any); !maps.Equal(mapping, want) {
		t.Errorf("Pet mapping %v, want %v", mapping, want)
	}
	animal := schemas["zoo.Animal"]["discriminator"].(map[string]any)
	// Only extenders that a published operation already imports are mapped. An
	// unreferenced one, even a broken one, is neither published nor checked.
	want = map[string]any{"Fish": "#/components/schemas/zoo.Fish"}
	if mapping, _ := animal["mapping"].(map[string]any); !maps.Equal(mapping, want) {
		t.Errorf("Animal mapping %v, want %v", mapping, want)
	}
	if _, ok := schemas["zoo.Snake"]; ok {
		t.Error("an unreferenced extender was published")
	}
}

func TestUnselectedOperationsCountAsWritten(t *testing.T) {
	paths := []string{
		anonymousOperation("get", "/v1/{collection}", "getCollection"),
		anonymousOperation("get", "/v1/items{batch}", "batchItems"),
		anonymousOperation("get", "/v1/jobs:run", "runJobs"),
	}
	selection := []operationSelection{{Method: "get", Path: "/v1/{collection}"}}
	direct := shopBindings()
	direct.Services["shop"] = serviceBinding{Prefix: "/shop", Operations: selection}
	direct.ServiceRoutes = map[string]serviceRoute{"/shop": {AuthProfiles: []string{"account"}}}
	direct.Authorization.Profiles = map[string]credentialProfile{"account": {Scheme: "bearer"}}
	plain := isolationBindings("shop")
	plain.Services["shop"] = serviceBinding{Prefix: "/shop", Operations: selection}
	// The selected template is anonymous. Unselected paths must not reach it:
	// the direct route requires credentials, and without one they are 404.
	for name, test := range map[string]struct {
		bindings   upstreamBindings
		unselected int
	}{"direct": {direct, 401}, "plain": {plain, 404}} {
		h := newTemplateHarness(t, test.bindings, paths...)
		for path, want := range map[string]int{"/shop/v1/things": 418, "/shop/v1/items:batch": test.unselected, "/shop/v1/jobs:run": test.unselected} {
			if code, _ := h.do("GET", path); code != want {
				t.Errorf("%s: GET %s = %d, want %d", name, path, code, want)
			}
		}
	}
}

func TestMalformedDiscriminatorIsRejected(t *testing.T) {
	contract := `openapi: 3.1.0
paths:
  /pets:
    get:
      operationId: listPets
      security: []
      x-darban-policy: anonymous
      responses:
        '200':
          description: OK
          content:
            application/json:
              schema:
                oneOf: [{$ref: '#/components/schemas/Cat'}]
                discriminator: {propertyName: kind, bogus: 1, mapping: {cat: Cat}}
components:
  schemas:
    Cat: {type: object}
`
	_, report := compile([]registration{{serviceName: "zoo", rewrites: "[]", openAPI: contract}}, isolationBindings("zoo"), nil)
	if !strings.Contains(report.services["zoo"].rejection, "discriminator") {
		t.Fatalf("rejection %q", report.services["zoo"].rejection)
	}
}

func TestNamedExamplesAreRenamed(t *testing.T) {
	_, operation := composedComponents(t, `openapi: 3.1.0
paths:
  /pets:
    get:
      operationId: listPets
      security: []
      x-darban-policy: anonymous
      responses:
        '200':
          description: OK
          content:
            application/json:
              examples:
                default: {$ref: '#/components/examples/Sample'}
components:
  examples:
    Sample: {value: {name: cat}}
`)
	examples := operation["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["examples"].(map[string]any)
	if ref := examples["default"].(map[string]any)["$ref"]; ref != "#/components/examples/zoo.Sample" {
		t.Fatalf("default example: %v", ref)
	}
}

func TestPassthroughPatternNeverShadowsAnInternalParameter(t *testing.T) {
	bindings := shopBindings()
	bindings.Services["shop"] = serviceBinding{Prefix: "/shop", Operations: []operationSelection{{Method: "get", Path: "/sel"}}}
	bindings.ServiceRoutes = map[string]serviceRoute{"/shop": {BackendAuth: true}}
	h := newTemplateHarness(t, bindings,
		anonymousOperation("get", "/sel", "sel"),
		anonymousOperation("get", "/v1/items{batch}", "batch"),
		"  /v1/{id}:\n    get:\n      x-darban-visibility: internal\n",
	)
	// TSF routes /v1/items:batch to the literal and anything else, including
	// /v1/itemsZ, to the internal /v1/:id. The pattern cannot tell them apart,
	// so the denial wins.
	for path, want := range map[string]int{"/shop/v1/itemsZ": 404, "/shop/v1/items:batch": 404, "/shop/v1/other": 404, "/shop/sel": 418} {
		if code, _ := h.do("GET", path); code != want {
			t.Errorf("GET %s = %d, want %d", path, code, want)
		}
	}
}

func TestExampleDataIsNotParsed(t *testing.T) {
	schemas, operation := composedComponents(t, `openapi: 3.1.0
paths:
  /pets:
    get:
      operationId: listPets
      security: []
      x-darban-policy: anonymous
      responses:
        '200':
          description: OK
          content:
            application/json:
              schema: {$ref: '#/components/schemas/Pet'}
              examples:
                sample: {value: {discriminator: cat, $ref: kept}}
components:
  schemas:
    Pet:
      type: object
      examples: [{discriminator: cat, $ref: kept}]
`)
	media := operation["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)
	value := media["examples"].(map[string]any)["sample"].(map[string]any)["value"].(map[string]any)
	data := schemas["zoo.Pet"]["examples"].([]any)[0].(map[string]any)
	for _, example := range []map[string]any{value, data} {
		if example["discriminator"] != "cat" || example["$ref"] != "kept" {
			t.Errorf("example data changed: %v", example)
		}
	}
}
