package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
		// HEAD is implied by GET.
		{"HEAD", "/shop/items/42", 418, "HEAD /api/items/42"},
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

func TestDirectRouteKeepsItsGatingForNonCanonicalPaths(t *testing.T) {
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
		// Not canonical, so no contract match: the direct route proxies it as is.
		{"/shop/items/a%2Fb", "GET /items/a%2Fb", 418},
		// The cleaned form of a non-canonical path is still denied.
		{"/shop/items//1/secret", "", 404},
		{"/shop/items/1/x/../secret", "", 404},
		{"/shop/items/1/secret/", "", 404},
		// The direct route's path policy also gates contract operations, in
		// either request-target form.
		{"/shop/items/9", "", 404},
		{"https://api.example.net/shop/items/9", "", 404},
		{"https://api.example.net/shop/items/8", "GET /items/8", 418},
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

func TestInternalPartialTemplateOnDirectRoute(t *testing.T) {
	bindings := shopBindings()
	bindings.Services["shop"] = serviceBinding{Prefix: "/shop"}
	bindings.ServiceRoutes = map[string]serviceRoute{"/shop": {BackendAuth: true}}
	h := newTemplateHarness(t, bindings,
		anonymousOperation("get", "/files/{id}", "getFile"),
		"  /files/{name}.txt:\n    get:\n      x-darban-visibility: internal\n",
		"  /logs/{name}.txt:\n    get:\n      x-darban-visibility: internal\n",
	)
	for path, want := range map[string]int{"/shop/files/a.txt": 418, "/shop/logs/a.txt": 404, "/shop/logs/a": 404, "/shop/other": 418} {
		if code, _ := h.do("GET", path); code != want {
			t.Errorf("GET %s = %d, want %d", path, code, want)
		}
	}
}
