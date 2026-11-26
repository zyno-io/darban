package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

// reviewRig serves the shop service on a direct route with a custom contract
// and rewrites, and records what the upstream and the authorizer receive.
type reviewRig struct {
	h          *skipHarness
	upstream   *http.Request
	authorizer *http.Request
}

func newReviewRig(t *testing.T, route serviceRoute, browserOrigins []string, binding serviceBinding, openAPI, rewrites string) *reviewRig {
	r := &reviewRig{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		r.upstream = q.Clone(q.Context())
		if q.URL.Path == "/slow" {
			time.Sleep(200 * time.Millisecond)
		}
		w.Header().Set("Access-Control-Allow-Origin", "https://backend.example")
		w.WriteHeader(http.StatusTeapot)
	}))
	authz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		r.authorizer = q.Clone(q.Context())
		w.Header().Set("X-Id", "verified")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	t.Cleanup(authz.Close)
	route.Origin = upstream.URL
	binding.Prefix = "/shop"
	bindings := upstreamBindings{
		Hostname: "api.example.net", Authz: authz.URL, BrowserOrigins: browserOrigins,
		Authorization: authorizationConfig{Path: "/authz", RequestHeaders: []string{"X-Tenant", "X-Id"},
			ResponseHeaders: []string{"X-Id"}, StripHeaderPrefixes: []string{"X-Id-"}},
		Services:      map[string]serviceBinding{"shop": binding},
		ServiceRoutes: map[string]serviceRoute{"/shop": route},
	}
	if err := bindings.validateServiceRoutes(true); err != nil {
		t.Fatal(err)
	}
	r.h = newSkipHarness(t, bindings)
	if openAPI != "" {
		r.h.apply(registration{serviceName: "shop", rewrites: rewrites, openAPI: openAPI})
		if status := r.h.status()["shop"]; status.Rejected {
			t.Fatalf("rejected: %+v", status.LastRejection)
		}
	} else {
		r.h.apply()
	}
	return r
}

func (r *reviewRig) do(method, host, path string, headers http.Header) *httptest.ResponseRecorder {
	r.upstream, r.authorizer = nil, nil
	req := httptest.NewRequest(method, path, nil)
	req.Host = host
	for name, values := range headers {
		req.Header[name] = values
	}
	res := httptest.NewRecorder()
	r.h.g.serve(r.h.active.Load(), res, req)
	return res
}

const reviewContract = `openapi: 3.1.0
paths:
  /private:
    get:
      operationId: private
      security: [{account: []}]
      responses: {'200': {description: OK}}
  /open:
    get:
      operationId: open
      security: []
      x-darban-policy: anonymous
      responses: {'200': {description: OK}}
  /items/{id}:
    get:
      operationId: getItem
      security: [{account: []}]
      responses: {'200': {description: OK}}
    options:
      operationId: itemOptions
      security: [{account: []}]
      responses: {'200': {description: OK}}
  /slow:
    get:
      operationId: slow
      security: []
      x-darban-policy: anonymous
      responses: {'200': {description: OK}}
  /items/private:
    get:
      x-darban-visibility: internal
components:
  securitySchemes:
    account: {type: http, scheme: bearer}
`

const api = "api.example.net"

func TestRewriteWithinADirectPrefixForwardsItsTarget(t *testing.T) {
	// A rewrite of the protected /private to the anonymous /open must serve
	// /open, not /private without authorization.
	r := newReviewRig(t, serviceRoute{}, nil, serviceBinding{}, reviewContract,
		`[{from: {method: GET, path: /shop/private}, to: {serviceName: shop, path: /open}}]`)
	res := r.do("GET", api, "/shop/private", nil)
	if res.Code != http.StatusTeapot || r.upstream == nil || r.upstream.URL.Path != "/open" || r.authorizer != nil {
		t.Fatalf("rewrite = %d %v", res.Code, r.upstream)
	}
	// The service's own operations still use the route's transport.
	if res := r.do("GET", api, "/shop/open", nil); res.Code != http.StatusTeapot || r.upstream.URL.Path != "/open" {
		t.Fatalf("own operation = %d", res.Code)
	}
}

func TestBackendCORSExemptsOnlyRealPreflights(t *testing.T) {
	preflight := func(requested string) http.Header {
		return http.Header{"Origin": {"https://unknown.example"}, "Access-Control-Request-Method": {requested}}
	}
	for name, origins := range map[string][]string{"browser origins": {"https://app.example.net"}, "no browser origins": nil} {
		r := newReviewRig(t, serviceRoute{BackendCORS: true}, origins, serviceBinding{}, reviewContract, "[]")
		// A preflight for GET on a path the contract serves goes to the backend.
		if res := r.do("OPTIONS", api, "/shop/private", preflight("GET")); res.Code != http.StatusTeapot || r.authorizer != nil ||
			r.upstream.Method != http.MethodOptions {
			t.Errorf("%s: preflight = %d", name, res.Code)
		}
		// A protected OPTIONS operation is served as itself, with authorization.
		if res := r.do("OPTIONS", api, "/shop/items/1", preflight("GET")); res.Code != http.StatusUnauthorized || r.upstream != nil {
			t.Errorf("%s: OPTIONS operation = %d", name, res.Code)
		}
		// A "preflight" that asks about OPTIONS is no preflight.
		if res := r.do("OPTIONS", api, "/shop/private", preflight("OPTIONS")); r.upstream != nil {
			t.Errorf("%s: OPTIONS about OPTIONS = %d", name, res.Code)
		}
		// A path the contract does not serve is refused.
		if res := r.do("OPTIONS", api, "/shop/other", preflight("GET")); res.Code != http.StatusNotFound || r.upstream != nil {
			t.Errorf("%s: preflight for an unknown path = %d", name, res.Code)
		}
	}

	// A route: false backendCORS route exempts the same preflights.
	r := newReviewRig(t, serviceRoute{BackendCORS: true}, nil, serviceBinding{Route: new(false), Publish: new(false)}, "", "")
	if res := r.do("OPTIONS", api, "/shop/private", preflight("GET")); res.Code != http.StatusTeapot || r.authorizer != nil {
		t.Errorf("route false: preflight = %d", res.Code)
	}
	if res := r.do("OPTIONS", api, "/shop/private", preflight("OPTIONS")); res.Code != http.StatusUnauthorized || r.upstream != nil {
		t.Errorf("route false: OPTIONS about OPTIONS = %d", res.Code)
	}
	if res := r.do("OPTIONS", api, "/shop/private", nil); res.Code != http.StatusUnauthorized || r.upstream != nil {
		t.Errorf("route false: plain OPTIONS = %d", res.Code)
	}
}

func TestBackendAuthForwardsIdentityHeadersOnlyWhenListed(t *testing.T) {
	caller := http.Header{"X-Tenant": {"t1"}, "X-Id": {"forged"}, "X-Id-Extra": {"forged"}, "Authorization": {"Bearer x"}}
	for name, forward := range map[string][]string{"default": nil, "listed": {"x-id"}} {
		for _, routed := range []bool{false, true} {
			contract, binding := "", serviceBinding{Route: new(false), Publish: new(false)}
			if routed {
				contract, binding = reviewContract, serviceBinding{}
			}
			r := newReviewRig(t, serviceRoute{BackendAuth: true, ForwardRequestHeaders: slices.Clone(forward)}, nil, binding, contract, "[]")
			if res := r.do("GET", api, "/shop/open", caller); res.Code != http.StatusTeapot {
				t.Fatalf("%s routed=%v: %d", name, routed, res.Code)
			}
			wantID := ""
			if forward != nil {
				wantID = "forged"
			}
			if r.upstream.Header.Get("X-Tenant") != "t1" || r.upstream.Header.Get("X-Id") != wantID ||
				r.upstream.Header.Get("X-Id-Extra") != "" || r.upstream.Header.Get("Authorization") != "Bearer x" {
				t.Errorf("%s routed=%v: upstream got %v", name, routed, r.upstream.Header)
			}
		}
	}
	for name, route := range map[string]serviceRoute{
		"not backendAuth": {Origin: "http://shop.fixtures.svc.cluster.local:80", ForwardRequestHeaders: []string{"X-Id"}},
		"authorization":   {Origin: "http://shop.fixtures.svc.cluster.local:80", BackendAuth: true, ForwardRequestHeaders: []string{"Authorization"}},
		"forwarded":       {Origin: "http://shop.fixtures.svc.cluster.local:80", BackendAuth: true, ForwardRequestHeaders: []string{"X-Forwarded-For"}},
		"invalid":         {Origin: "http://shop.fixtures.svc.cluster.local:80", BackendAuth: true, ForwardRequestHeaders: []string{"bad header"}},
		"duplicate":       {Origin: "http://shop.fixtures.svc.cluster.local:80", BackendAuth: true, ForwardRequestHeaders: []string{"X-Id", "X-Id"}},
	} {
		bindings := upstreamBindings{Hostname: api, Authz: "http://authz.fixtures.svc.cluster.local:80", ServiceRoutes: map[string]serviceRoute{"/shop": route}}
		if err := bindings.validateServiceRoutes(true); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRoutedAuthorizationEdgeCases(t *testing.T) {
	r := newReviewRig(t, serviceRoute{LegacyHosts: []string{"shop.example.net"}}, nil, serviceBinding{}, reviewContract, "[]")
	// Two Authorization headers are ambiguous.
	if res := r.do("GET", api, "/shop/private", http.Header{"Authorization": {"Bearer a", "Bearer b"}}); res.Code != http.StatusUnauthorized || r.authorizer != nil {
		t.Errorf("duplicate Authorization = %d", res.Code)
	}
	// A header that is both a request and an identity header, as X-ZS-TID is in
	// Alpha, reaches the authorizer as sent, and the upstream only as the
	// authorizer returned it.
	res := r.do("GET", api, "/shop/private", http.Header{"Authorization": {"Bearer a"}, "X-Id": {"selector"}})
	if res.Code != http.StatusTeapot || r.authorizer.Header.Get("X-Id") != "selector" || r.upstream.Header.Get("X-Id") != "verified" {
		t.Errorf("overlapping header: %d authorizer %v upstream %v", res.Code, r.authorizer.Header, r.upstream.Header)
	}
	// An encoded internal path on a legacy host is denied.
	for _, path := range []string{"/items/private", "/items/%70rivate"} {
		if res := r.do("GET", "shop.example.net", path, http.Header{"Authorization": {"Bearer a"}}); res.Code != http.StatusNotFound || r.upstream != nil {
			t.Errorf("legacy %s = %d", path, res.Code)
		}
	}
}

func TestRoutedOperationsKeepTheRouteClientIPAndTimeouts(t *testing.T) {
	r := newReviewRig(t, serviceRoute{ForwardTrustedClientIP: true, LongResponsePaths: []string{"/slow"}, LongResponseHeaderTimeout: "50ms"},
		nil, serviceBinding{}, reviewContract, "[]")
	if res := r.do("GET", api, "/shop/open", http.Header{"X-Real-Ip": {"::ffff:192.0.2.7"}}); res.Code != http.StatusTeapot ||
		r.upstream.Header.Get("X-Real-Ip") != "192.0.2.7" {
		t.Errorf("client IP: %d %v", res.Code, r.upstream)
	}
	if res := r.do("GET", api, "/shop/open", nil); res.Code != http.StatusServiceUnavailable || r.upstream != nil {
		t.Errorf("missing client IP = %d", res.Code)
	}
	// /slow is a long-response path, here with a timeout shorter than its
	// 200ms handler.
	if res := r.do("GET", api, "/shop/slow", http.Header{"X-Real-Ip": {"192.0.2.7"}}); res.Code != http.StatusBadGateway {
		t.Errorf("long-response timeout = %d", res.Code)
	}
}

func TestExtraRoutesForOptionsHeadAndHealth(t *testing.T) {
	binding := serviceBinding{ExtraRoutes: []extraRoute{
		{Method: "GET", Path: "/healthz", Auth: extraAuthNone},
		{Method: "OPTIONS", Path: "/cors", Auth: extraAuthNone},
		{Method: "HEAD", Path: "/ping", Auth: extraAuthNone},
	}}
	r := newReviewRig(t, serviceRoute{}, nil, binding, reviewContract, "[]")
	for _, test := range []struct{ method, path, upstream string }{
		{"GET", "/shop/healthz", "GET /healthz"},
		{"HEAD", "/shop/healthz", "GET /healthz"},
		{"OPTIONS", "/shop/cors", "OPTIONS /cors"},
		{"HEAD", "/shop/ping", "HEAD /ping"},
	} {
		res := r.do(test.method, api, test.path, nil)
		if res.Code != http.StatusTeapot || r.upstream == nil || r.upstream.Method+" "+r.upstream.URL.Path != test.upstream || r.authorizer != nil {
			t.Errorf("%s %s = %d %v", test.method, test.path, res.Code, r.upstream)
		}
	}
	for _, test := range []struct{ method, path string }{{"GET", "/shop/ping"}, {"POST", "/shop/healthz"}} {
		if res := r.do(test.method, api, test.path, nil); res.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d", test.method, test.path, res.Code)
		}
	}
}

func TestExtraRoutesRejectSameShapesAndIgnoredAuth(t *testing.T) {
	for name, body := range map[string]string{
		"same shape": `{"hostname": "api.example.net", "authz": "http://authz.fixtures.svc.cluster.local:80", "authorization": {"path": "/authz"},
			"services": {"shop": {"prefix": "/shop", "extraRoutes": [{"method": "GET", "path": "/a/{x}", "auth": "gateway"}, {"method": "GET", "path": "/a/{y}", "auth": "none"}]}}}`,
		"gateway on backendAuth": `{"hostname": "api.example.net", "authz": "http://authz.fixtures.svc.cluster.local:80", "authorization": {"path": "/authz"},
			"serviceRoutes": {"/shop": {"origin": "http://shop.fixtures.svc.cluster.local:80", "backendAuth": true}},
			"services": {"shop": {"prefix": "/shop", "extraRoutes": [{"method": "GET", "path": "/a", "auth": "gateway"}]}}}`,
	} {
		if err := writeBindings(t, body); err == nil || !strings.Contains(err.Error(), "extra route") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
