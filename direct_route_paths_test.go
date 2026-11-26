package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestDirectRouteRefusesPathsItCouldGateDifferently checks that a direct route
// never gates one path and forwards another. Its policy sees path.Clean of the
// decoded path, while the backend resolves the path as sent: WHATWG and Node
// keep empty segments when resolving .., and do not decode %2F.
func TestDirectRouteRefusesPathsItCouldGateDifferently(t *testing.T) {
	var hits []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.Method+" "+r.URL.EscapedPath())
		w.WriteHeader(http.StatusTeapot)
	}))
	defer upstream.Close()
	authz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer authz.Close()

	const legacyHost = "legacy.example.net"
	bindings := upstreamBindings{
		Hostname: "api.example.net", Authz: authz.URL,
		Authorization: authorizationConfig{Path: "/authz", Profiles: map[string]credentialProfile{"account": {Scheme: "bearer"}}},
		ServiceRoutes: map[string]serviceRoute{
			"/denied":  {Origin: upstream.URL, BackendAuth: true, DeniedPaths: []string{"/authz", "/zrpc/*"}, LegacyHosts: []string{legacyHost}},
			"/allowed": {Origin: upstream.URL, BackendAuth: true, AllowedPaths: []string{"/open/*"}},
			"/public":  {Origin: upstream.URL, AuthProfiles: []string{"account"}, PublicPaths: []string{"/tabs/*"}},
		},
	}
	gw := newGateway(bindings)
	for _, test := range []struct {
		host, method, path string
		want               int
		upstream           string
	}{
		// Normal paths, with and without a trailing slash, still work.
		{"", "POST", "/denied/svc/method", 418, "POST /svc/method"},
		{"", "GET", "/denied/svc/method/", 418, "GET /svc/method/"},
		{"", "GET", "/denied/svc/%6Dethod", 418, "GET /svc/%6Dethod"},
		{"", "GET", "/allowed/open/x/", 418, "GET /open/x/"},
		{"", "GET", "/public/tabs/x/", 418, "GET /tabs/x/"},
		{"", "GET", "/public/private/x", 401, ""},
		{legacyHost, "GET", "/svc/method/", 418, "GET /svc/method/"},
		// Denied paths stay denied.
		{"", "POST", "/denied/zrpc/svc/m", 404, ""},
		{"", "GET", "/denied/authz/", 404, ""},
		// Clean collapses // before resolving .., the backend does not.
		{"", "POST", "/denied/zrpc//../svc/m", 404, ""},
		{"", "GET", "/denied/authz//..", 404, ""},
		{"", "GET", "/allowed/x//../open/y", 404, ""},
		{"", "GET", "/public/private/a//../../tabs/x", 404, ""},
		{legacyHost, "POST", "/zrpc//../svc/m", 404, ""},
		{legacyHost, "GET", "/authz//..", 404, ""},
		// Clean decodes %2F, the backend does not.
		{"", "POST", "/denied/zrpc/a/b%2F..%2F..%2Fx", 404, ""},
		{"", "GET", "/allowed/x%2F..%2Fopen/y", 404, ""},
		{"", "GET", "/public/private%2F..%2Ftabs/x", 404, ""},
		{"", "GET", "/denied/svc%5Cmethod", 404, ""},
		{"", "GET", `/denied/svc\method`, 404, ""},
		// Dot segments, plain or encoded.
		{"", "POST", "/denied/svc/../zrpc/m", 404, ""},
		{"", "POST", "/denied/svc/%2e%2e/zrpc/m", 404, ""},
		{"", "POST", "/denied/svc/%2E./zrpc/m", 404, ""},
		{"", "GET", "/denied/svc/./method", 404, ""},
		{"", "GET", "/denied/svc/%2e/method", 404, ""},
		{"", "GET", "/allowed/open/%2e%2e/x", 404, ""},
		{"", "GET", "/public/tabs/%2E%2E/private", 404, ""},
		{legacyHost, "GET", "/svc/%2e%2e/authz", 404, ""},
		// An encoded prefix would skip the policy for its decoded form.
		{"", "POST", "/%64enied/zrpc/svc/m", 404, ""},
		{"", "GET", "/allowe%64/x", 404, ""},
		{"", "GET", "/publi%63/private/x", 404, ""},
	} {
		hits = nil
		req := httptest.NewRequest(test.method, test.path, nil)
		req.Host = bindings.Hostname
		if test.host != "" {
			req.Host = test.host
		}
		res := httptest.NewRecorder()
		gw.serve(&snapshot{}, res, req)
		upstreamHit := ""
		if len(hits) == 1 {
			upstreamHit = hits[0]
		}
		if res.Code != test.want || upstreamHit != test.upstream || len(hits) > 1 {
			t.Errorf("%s %s%s = %d %v, want %d %q", test.method, test.host, test.path, res.Code, hits, test.want, test.upstream)
		}
	}
}
