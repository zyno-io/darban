package main

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

const proxyContract = `openapi: 3.1.0
paths:
  /items/{id}:
    get:
      operationId: getItem
      security: [{account: []}]
      responses: {'200': {description: OK}}
  /public/{id}:
    get:
      operationId: getPublic
      security: []
      x-darban-policy: anonymous
      responses: {'200': {description: OK}}
  /slow:
    get:
      operationId: slow
      security: []
      x-darban-policy: anonymous
      responses: {'200': {description: OK}}
  /redirect:
    get:
      operationId: redirect
      security: []
      x-darban-policy: anonymous
      responses: {'302': {description: Found}}
  /admin/{id}:
    get:
      x-darban-visibility: internal
components:
  securitySchemes:
    account: {type: http, scheme: bearer}
`

// proxyRig serves the shop service with the given settings, and records what
// the upstream and the authorizer receive.
type proxyRig struct {
	h          *skipHarness
	upstream   *http.Request
	authorizer *http.Request
	authzCode  int
}

func newProxyRig(t *testing.T, binding serviceBinding) *proxyRig {
	r := &proxyRig{authzCode: http.StatusNoContent}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		r.upstream = q.Clone(q.Context())
		switch q.URL.Path {
		case "/slow":
			time.Sleep(2500 * time.Millisecond)
		case "/redirect":
			w.Header().Set("Location", "/items/next")
			w.Header().Set("Set-Cookie", "session=1; Path=/items; Domain=backend.example; Secure")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "https://backend.example")
		w.WriteHeader(http.StatusTeapot)
	}))
	authz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		r.authorizer = q.Clone(q.Context())
		w.Header().Set("X-Id", "verified")
		w.Header().Set("X-Other", "dropped")
		w.WriteHeader(r.authzCode)
	}))
	t.Cleanup(upstream.Close)
	t.Cleanup(authz.Close)
	bindings := upstreamBindings{
		Hostname: "api.example.net", Authz: authz.URL, BrowserOrigins: []string{"https://app.example.net"},
		Authorization: authorizationConfig{Path: "/authz", RequestHeaders: []string{"X-Tenant"},
			ResponseHeaders: []string{"X-Id"}, StripHeaderPrefixes: []string{"X-Id-"}},
		Services: map[string]serviceBinding{"shop": binding},
	}
	binding.Origin = upstream.URL
	bindings.Services["shop"] = binding
	r.h = newSkipHarness(t, bindings)
	r.h.apply(registration{serviceName: "shop", rewrites: "[]", openAPI: proxyContract})
	if status := r.h.status()["shop"]; status.Rejected {
		t.Fatalf("rejected: %+v", status.LastRejection)
	}
	return r
}

func (r *proxyRig) do(method, path string, headers map[string]string) *httptest.ResponseRecorder {
	r.upstream, r.authorizer = nil, nil
	req := httptest.NewRequest(method, path, nil)
	req.Host = "api.example.net"
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	res := httptest.NewRecorder()
	r.h.g.serve(r.h.active.Load(), res, req)
	return res
}

func TestServiceAuthorizationModel(t *testing.T) {
	for name, binding := range map[string]serviceBinding{"service": {Prefix: "/shop"}} {
		r := newProxyRig(t, binding)
		spoofed := map[string]string{"X-Id": "forged", "X-Id-Extra": "forged", "X-Tenant": "t1"}

		// Any scheme goes to the authorizer as sent. The upstream gets the
		// authorizer's identity, not the credentials or forged copies.
		for _, credential := range []string{"Bearer abc", "Basic dXNlcg==", "ZMDA device-token", "Custom anything"} {
			headers := map[string]string{"Authorization": credential}
			for k, v := range spoofed {
				headers[k] = v
			}
			res := r.do("GET", "/shop/items/1", headers)
			if res.Code != http.StatusTeapot || r.authorizer == nil || r.upstream == nil {
				t.Fatalf("%s %s: %d", name, credential, res.Code)
			}
			if got := r.authorizer.Header.Get("Authorization"); got != credential || r.authorizer.Header.Get("X-Tenant") != "t1" ||
				r.authorizer.Header.Get("X-Original-Uri") != "/shop/items/1" {
				t.Errorf("%s: authorizer got %v", name, r.authorizer.Header)
			}
			if r.upstream.Header.Get("Authorization") != "" || r.upstream.Header.Get("X-Id") != "verified" ||
				r.upstream.Header.Get("X-Id-Extra") != "" || r.upstream.Header.Get("X-Other") != "" {
				t.Errorf("%s: upstream got %v", name, r.upstream.Header)
			}
		}
		// Without credentials there is nothing to authorize.
		if res := r.do("GET", "/shop/items/1", nil); res.Code != http.StatusUnauthorized || r.authorizer != nil {
			t.Errorf("%s: no credentials = %d", name, res.Code)
		}
		// The authorizer's refusals pass through.
		for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
			r.authzCode = code
			if res := r.do("GET", "/shop/items/1", map[string]string{"Authorization": "Bearer x"}); res.Code != code || r.upstream != nil {
				t.Errorf("%s: authorizer %d = %d", name, code, res.Code)
			}
		}
		r.authzCode = http.StatusNoContent
		// An anonymous operation skips the authorizer and keeps Authorization,
		// but caller copies of identity headers are still stripped.
		res := r.do("GET", "/shop/public/1", map[string]string{"Authorization": "Bearer abc", "X-Id": "forged"})
		if res.Code != http.StatusTeapot || r.authorizer != nil || r.upstream.Header.Get("Authorization") != "Bearer abc" ||
			r.upstream.Header.Get("X-Id") != "" {
			t.Errorf("%s: anonymous = %d %v", name, res.Code, r.upstream)
		}
		// Unmatched and internal paths are refused; nothing falls through.
		for _, path := range []string{"/shop/other", "/shop/items", "/shop/admin/1", "/shop/items/1/x"} {
			if res := r.do("GET", path, map[string]string{"Authorization": "Bearer abc"}); res.Code != http.StatusNotFound || r.upstream != nil {
				t.Errorf("%s: GET %s = %d", name, path, res.Code)
			}
		}
	}

	// A backendAuth service leaves every operation's authorization to the
	// backend, with the caller's Authorization.
	r := newProxyRig(t, serviceBinding{Prefix: "/shop", BackendAuth: true})
	res := r.do("GET", "/shop/items/1", map[string]string{"Authorization": "Bearer abc"})
	if res.Code != http.StatusTeapot || r.authorizer != nil || r.upstream.Header.Get("Authorization") != "Bearer abc" {
		t.Errorf("backendAuth: %d %v", res.Code, r.upstream)
	}
	if r.upstream.Header.Get("X-Original-Uri") != "/shop/items/1" {
		t.Errorf("backendAuth: X-Original-URI = %q", r.upstream.Header.Get("X-Original-Uri"))
	}
}

func TestServiceTransportSettings(t *testing.T) {
	r := newProxyRig(t, serviceBinding{Prefix: "/shop", UpstreamHost: "shop.internal.example", LegacyHosts: []string{"shop.example.net"}})

	// Within the regular 60s response-header timeout.
	if res := r.do("GET", "/shop/slow", nil); res.Code != http.StatusTeapot {
		t.Errorf("slow handler = %d", res.Code)
	}
	if r.upstream.Host != "shop.internal.example" || r.upstream.URL.Path != "/slow" {
		t.Errorf("upstream host %q path %q", r.upstream.Host, r.upstream.URL.Path)
	}
	// Redirects and cookies are scoped to the prefix.
	res := r.do("GET", "/shop/redirect", nil)
	if res.Code != http.StatusFound || res.Header().Get("Location") != "/shop/items/next" {
		t.Errorf("redirect %d %q", res.Code, res.Header().Get("Location"))
	}
	if cookies := res.Result().Cookies(); len(cookies) != 1 || cookies[0].Path != "/shop/items" || cookies[0].Domain != "" {
		t.Errorf("cookies %v", cookies)
	}
	// A legacy host serves the same operations.
	req := httptest.NewRequest("GET", "/public/1", nil)
	req.Host = "shop.example.net"
	rec := httptest.NewRecorder()
	r.h.g.serve(r.h.active.Load(), rec, req)
	if rec.Code != http.StatusTeapot || r.upstream.Host != "shop.example.net" || r.upstream.URL.Path != "/public/1" {
		t.Errorf("legacy host: %d %v", rec.Code, r.upstream)
	}
	// HEAD on a GET operation goes upstream as GET.
	if res := r.do("HEAD", "/shop/public/1", nil); res.Code != http.StatusTeapot || r.upstream.Method != http.MethodGet {
		t.Errorf("HEAD = %d %v", res.Code, r.upstream)
	}

	// Gateway CORS for authorized operations, backend CORS for anonymous ones.
	preflight := func(path, origin string) *httptest.ResponseRecorder {
		return r.do("OPTIONS", path, map[string]string{"Origin": origin, "Access-Control-Request-Method": "GET"})
	}
	if res := preflight("/shop/items/1", "https://unknown.example"); res.Code != http.StatusForbidden || r.upstream != nil {
		t.Errorf("protected preflight from an unknown origin = %d", res.Code)
	}
	if res := preflight("/shop/items/1", "https://app.example.net"); res.Code != http.StatusNoContent || r.upstream != nil {
		t.Errorf("protected preflight from a browser origin = %d", res.Code)
	}
	if res := preflight("/shop/public/1", "https://unknown.example"); res.Code != http.StatusTeapot || r.upstream == nil {
		t.Errorf("anonymous preflight from an unknown origin = %d", res.Code)
	}
}

func TestBackendCORSServiceLeavesPreflightToTheBackend(t *testing.T) {
	r := newProxyRig(t, serviceBinding{Prefix: "/shop", BackendCORS: true})
	// A preflight carries no credentials, so it goes to the backend as is.
	res := r.do("OPTIONS", "/shop/items/1", map[string]string{"Origin": "https://unknown.example", "Access-Control-Request-Method": "GET"})
	if r.upstream == nil || r.authorizer != nil || res.Header().Get("Access-Control-Allow-Origin") != "https://backend.example" {
		t.Errorf("backendCORS preflight = %d %v", res.Code, res.Header())
	}
	// The operation itself is still authorized.
	if res := r.do("GET", "/shop/items/1", nil); res.Code != http.StatusUnauthorized {
		t.Errorf("backendCORS GET without credentials = %d", res.Code)
	}
}

func TestExtraRoutes(t *testing.T) {
	binding := serviceBinding{Prefix: "/shop", ExtraRoutes: []extraRoute{
		{Method: "GET", Path: "/healthz", Auth: extraAuthNone},
		{Method: "GET", Path: "/assets/*", Auth: extraAuthNone},
		{Method: "GET", Path: "/events/{channel}", Auth: extraAuthGateway},
		// An operation of the same shape keeps its own policy.
		{Method: "GET", Path: "/items/{key}", Auth: extraAuthNone},
	}}
	for name, binding := range map[string]serviceBinding{"service": binding} {
		r := newProxyRig(t, binding)
		for _, test := range []struct {
			path, authorization string
			code                int
			upstreamPath        string
			authorized          bool
		}{
			{"/shop/healthz", "", 418, "/healthz", false},
			{"/shop/assets", "", 418, "/assets", false},
			{"/shop/assets/app.js", "", 418, "/assets/app.js", false},
			{"/shop/assets/img/logo%20big.png", "", 418, "/assets/img/logo big.png", false},
			{"/shop/events/news", "Bearer x", 418, "/events/news", true},
			{"/shop/events/news", "", 401, "", false},
			{"/shop/items/1", "", 401, "", false},
			{"/shop/assets/../admin/1", "", 404, "", false},
			{"/shop/healthz/x", "", 404, "", false},
		} {
			headers := map[string]string{}
			if test.authorization != "" {
				headers["Authorization"] = test.authorization
			}
			res := r.do("GET", test.path, headers)
			upstreamPath := ""
			if r.upstream != nil {
				upstreamPath = r.upstream.URL.Path
			}
			if res.Code != test.code || upstreamPath != test.upstreamPath || (r.authorizer != nil) != test.authorized {
				t.Errorf("%s: GET %s = %d %q authorized=%v", name, test.path, res.Code, upstreamPath, r.authorizer != nil)
			}
		}
		if status := r.h.status()["shop"]; status.Routes != 8 {
			t.Errorf("%s: routes %d", name, status.Routes)
		}
	}
}

func TestExtraRoutesValidation(t *testing.T) {
	base := `{"hostname": "api.example.net", "services": {"shop": {"prefix": "/shop", "extraRoutes": [%s]}}}`
	if err := writeBindings(t, strings.Replace(base, "%s", `{"method": "GET", "path": "/assets/*", "auth": "none"}`, 1)); err != nil {
		t.Fatalf("valid: %v", err)
	}
	for name, routes := range map[string]string{
		"method":        `{"method": "get", "path": "/x", "auth": "none"}`,
		"path":          `{"method": "GET", "path": "/x/../y", "auth": "none"}`,
		"inner star":    `{"method": "GET", "path": "/*/x", "auth": "none"}`,
		"partial":       `{"method": "GET", "path": "/x{y}", "auth": "none"}`,
		"auth":          `{"method": "GET", "path": "/x", "auth": "bearer"}`,
		"gateway":       `{"method": "GET", "path": "/x", "auth": "gateway"}`,
		"duplicate":     `{"method": "GET", "path": "/x", "auth": "none"}, {"method": "GET", "path": "/x", "auth": "gateway"}`,
		"unknown field": `{"method": "GET", "path": "/x", "auth": "none", "bogus": 1}`,
	} {
		if err := writeBindings(t, strings.Replace(base, "%s", routes, 1)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ignored := `{"hostname": "api.example.net", "authz": "http://authz.fixtures.svc.cluster.local:80", "authorization": {"path": "/authz"},
		"services": {"shop": {"backendAuth": true, "extraRoutes": [{"method": "GET", "path": "/x", "auth": "gateway"}]}}}`
	if err := writeBindings(t, ignored); err == nil {
		t.Error("auth gateway on a backendAuth service accepted")
	}
}

func TestDiscoveryDefaultsAndBindingOverrides(t *testing.T) {
	bindings := contractOnlyBindings()
	bindings.Authz = "http://authz.zyno-alpha.svc.cluster.local:80"
	// No entry: the contract's upstream, mount and prefix.
	plain := clusterContract("plain", "/api/items", "listPlain", "http://plain:3000/api", "")
	// An entry overrides the contract's origin, adds settings, and keeps the
	// contract's mount.
	bindings.Services["shop"] = serviceBinding{Origin: "http://shop-v2." + testNamespace + ".svc.cluster.local:8080",
		UpstreamHost: "shop.internal.example", BackendAuth: true}
	shop := clusterContract("shop", "/api/items", "listShop", "http://shop:3000/api", "/store")
	// An entry with its own prefix wins over the contract's.
	bindings.Services["desk"] = serviceBinding{Prefix: "/help"}
	desk := clusterContract("desk", "/items", "listDesk", "http://desk:3000", "/desk")
	got, report := compile([]registration{plain, shop, desk}, bindings, nil)
	for _, name := range []string{"plain", "shop", "desk"} {
		if outcome := report.services[name]; outcome.serving != servingCurrent {
			t.Fatalf("%s: %+v", name, outcome)
		}
	}
	wantPaths(t, got, "/help/items", "/plain/items", "/store/items")
	want := map[string]serviceBinding{
		"plain": {Origin: "http://plain." + testNamespace + ".svc.cluster.local:3000", Mount: "/api", Prefix: "/plain"},
		"shop": {Origin: "http://shop-v2." + testNamespace + ".svc.cluster.local:8080", Mount: "/api", Prefix: "/store",
			UpstreamHost: "shop.internal.example", BackendAuth: true},
		"desk": {Origin: "http://desk." + testNamespace + ".svc.cluster.local:3000", Prefix: "/help"},
	}
	for name, binding := range want {
		if !reflect.DeepEqual(got.services[name], binding) {
			t.Errorf("%s: %+v, want %+v", name, got.services[name], binding)
		}
	}
	if !strings.Contains(report.overrides["shop"], "origin") || !strings.Contains(report.overrides["desk"], "prefix") || report.overrides["plain"] != "" {
		t.Errorf("overrides %v", report.overrides)
	}
	// An entry without a contract fails closed.
	bindings.Services["idle"] = serviceBinding{Origin: "http://idle." + testNamespace + ".svc.cluster.local:80"}
	got, report = compile([]registration{plain}, bindings, nil)
	if !report.services["idle"].missing || !slices.Contains(got.unserved, "/idle") || !slices.Contains(got.unserved, "/shop") {
		t.Errorf("idle %+v unserved %v", report.services["idle"], got.unserved)
	}
}
