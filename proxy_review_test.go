package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

// reviewRig serves the shop service with a custom contract
// and rewrites, and records what the upstream and the authorizer receive.
type reviewRig struct {
	h          *skipHarness
	upstream   *http.Request
	authorizer *http.Request
}

// validateServices validates every service binding as loadBindings does.
func validateServices(t *testing.T, bindings upstreamBindings) {
	t.Helper()
	if err := bindings.validateRequestHeaders(true); err != nil {
		t.Fatal(err)
	}
	for name, binding := range bindings.Services {
		if err := binding.validate(name, bindings, true, true); err != nil {
			t.Fatal(err)
		}
	}
}

func newReviewRig(t *testing.T, binding serviceBinding, browserOrigins []string, openAPI, rewrites string) *reviewRig {
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
	binding.Origin = upstream.URL
	binding.Prefix = "/shop"
	bindings := upstreamBindings{
		Hostname: "api.example.net", Authz: authz.URL, BrowserOrigins: browserOrigins,
		Authorization: authorizationConfig{Path: "/authz", RequestHeaders: []string{"X-Tenant", "X-Id"},
			ResponseHeaders: []string{"X-Id"}, StripHeaderPrefixes: []string{"X-Id-"}},
		Services: map[string]serviceBinding{"shop": binding},
	}
	validateServices(t, bindings)
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

func TestRewriteWithinThePrefixForwardsItsTarget(t *testing.T) {
	// A rewrite of the protected /private to the anonymous /open must serve
	// /open, not /private without authorization.
	r := newReviewRig(t, serviceBinding{}, nil, reviewContract,
		`[{from: {method: GET, path: /shop/private}, to: {serviceName: shop, path: /open}}]`)
	res := r.do("GET", api, "/shop/private", nil)
	if res.Code != http.StatusTeapot || r.upstream == nil || r.upstream.URL.Path != "/open" || r.authorizer != nil {
		t.Fatalf("rewrite = %d %v", res.Code, r.upstream)
	}
	// The service's own operations use the same transport.
	if res := r.do("GET", api, "/shop/open", nil); res.Code != http.StatusTeapot || r.upstream.URL.Path != "/open" {
		t.Fatalf("own operation = %d", res.Code)
	}
}

func TestBackendCORSExemptsOnlyRealPreflights(t *testing.T) {
	preflight := func(requested string) http.Header {
		return http.Header{"Origin": {"https://unknown.example"}, "Access-Control-Request-Method": {requested}}
	}
	for name, origins := range map[string][]string{"browser origins": {"https://app.example.net"}, "no browser origins": nil} {
		r := newReviewRig(t, serviceBinding{BackendCORS: true}, origins, reviewContract, "[]")
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
}

func TestBackendAuthForwardsIdentityHeadersOnlyWhenListed(t *testing.T) {
	caller := http.Header{"X-Tenant": {"t1"}, "X-Id": {"forged"}, "X-Id-Extra": {"forged"}, "Authorization": {"Bearer x"}}
	for name, forward := range map[string][]string{"default": nil, "listed": {"x-id"}} {
		r := newReviewRig(t, serviceBinding{BackendAuth: true, ForwardRequestHeaders: slices.Clone(forward)}, nil, reviewContract, "[]")
		if res := r.do("GET", api, "/shop/open", caller); res.Code != http.StatusTeapot {
			t.Fatalf("%s: %d", name, res.Code)
		}
		wantID := ""
		if forward != nil {
			wantID = "forged"
		}
		if r.upstream.Header.Get("X-Tenant") != "t1" || r.upstream.Header.Get("X-Id") != wantID ||
			r.upstream.Header.Get("X-Id-Extra") != "" || r.upstream.Header.Get("Authorization") != "Bearer x" {
			t.Errorf("%s: upstream got %v", name, r.upstream.Header)
		}
	}
	for name, binding := range map[string]serviceBinding{
		"not backendAuth":    {ForwardRequestHeaders: []string{"X-Id"}},
		"authorization":      {BackendAuth: true, ForwardRequestHeaders: []string{"Authorization"}},
		"forwarded":          {BackendAuth: true, ForwardRequestHeaders: []string{"X-Forwarded-For"}},
		"client IP":          {BackendAuth: true, ForwardRequestHeaders: []string{"X-Real-IP"}},
		"invalid":            {BackendAuth: true, ForwardRequestHeaders: []string{"bad header"}},
		"duplicate":          {BackendAuth: true, ForwardRequestHeaders: []string{"X-Id", "X-Id"}},
		"duplicate spelling": {BackendAuth: true, ForwardRequestHeaders: []string{"X-ZS-TID", "X-ZS-TID"}},
	} {
		bindings := upstreamBindings{Hostname: api, Authz: "http://authz.fixtures.svc.cluster.local:80"}
		err := binding.validate("shop", bindings, true, true)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		// The message names the actual problem.
		if needsBackendAuth := strings.Contains(err.Error(), "needs backendAuth"); needsBackendAuth != (name == "not backendAuth") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAuthorizationEdgeCases(t *testing.T) {
	r := newReviewRig(t, serviceBinding{LegacyHosts: []string{"shop.example.net"}}, nil, reviewContract, "[]")
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

func TestLongResponsePathsUseTheirTimeout(t *testing.T) {
	r := newReviewRig(t, serviceBinding{LongResponsePaths: []string{"/slow"}, LongResponseHeaderTimeout: "50ms"}, nil, reviewContract, "[]")
	if res := r.do("GET", api, "/shop/open", nil); res.Code != http.StatusTeapot {
		t.Errorf("regular path = %d", res.Code)
	}
	// /slow is a long-response path, here with a timeout shorter than its
	// 200ms handler. It goes last: its handler outlives the request.
	if res := r.do("GET", api, "/shop/slow", nil); res.Code != http.StatusBadGateway {
		t.Errorf("long-response timeout = %d", res.Code)
	}
}

func TestExtraRoutesForOptionsHeadAndHealth(t *testing.T) {
	binding := serviceBinding{ExtraRoutes: []extraRoute{
		{Method: "GET", Path: "/healthz", Auth: extraAuthNone},
		{Method: "OPTIONS", Path: "/cors", Auth: extraAuthNone},
		{Method: "HEAD", Path: "/ping", Auth: extraAuthNone},
	}}
	r := newReviewRig(t, binding, nil, reviewContract, "[]")
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
			"services": {"shop": {"prefix": "/shop", "backendAuth": true, "extraRoutes": [{"method": "GET", "path": "/a", "auth": "gateway"}]}}}`,
	} {
		if err := writeBindings(t, body); err == nil || !strings.Contains(err.Error(), "extra route") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestBackendAuthForwardsUpstreamRequestHeadersThatLookLikeIdentity(t *testing.T) {
	// Alpha forwards X-ZS-Date upstream although X-ZS- is a stripped prefix.
	// On a backendAuth service the backend gets it, and the authorizer request
	// headers, which it is not, exclude it.
	var upstream, authorizer http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		upstream = q.Header.Clone()
		w.WriteHeader(http.StatusTeapot)
	}))
	defer backend.Close()
	authz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		authorizer = q.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer authz.Close()
	bindings := upstreamBindings{
		Hostname: api, Authz: authz.URL, UpstreamRequestHeaders: []string{"X-Zs-Date"},
		Authorization: authorizationConfig{Path: "/authz", RequestHeaders: []string{"X-Zs-Tid"}, ResponseHeaders: []string{"X-Zs-Tid"},
			StripHeaderPrefixes: []string{"X-Zs-"}},
		Services: map[string]serviceBinding{
			"auth":  {Origin: backend.URL, BackendAuth: true},
			"suite": {Origin: backend.URL},
		},
	}
	validateServices(t, bindings)
	h := newSkipHarness(t, bindings)
	protected := "openapi: 3.1.0\npaths:\n  /x:\n    get:\n      security: [{account: []}]\n      responses: {'200': {description: OK}}\n" +
		"components:\n  securitySchemes:\n    account: {type: http, scheme: bearer}\n"
	h.apply(registration{serviceName: "auth", rewrites: "[]", openAPI: protected}, registration{serviceName: "suite", rewrites: "[]", openAPI: protected})
	for _, path := range []string{"/auth/x", "/suite/x"} {
		upstream, authorizer = nil, nil
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = api
		req.Header.Set("Authorization", "Bearer x")
		req.Header.Set("X-ZS-Date", "2026-11-26")
		req.Header.Set("X-ZS-TID", "forged")
		res := httptest.NewRecorder()
		h.g.serve(h.active.Load(), res, req)
		if res.Code != http.StatusTeapot || upstream.Get("X-Zs-Date") != "2026-11-26" || upstream.Get("X-Zs-Tid") != "" {
			t.Errorf("%s: %d upstream %v", path, res.Code, upstream)
		}
		if authorizer != nil && authorizer.Get("X-Zs-Date") != "" {
			t.Errorf("%s: authorizer got X-ZS-Date", path)
		}
	}
	if authorizer == nil {
		t.Fatal("the protected service did not call the authorizer")
	}
}
