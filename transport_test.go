package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// transportRig serves "shop" with every transport setting, a debug origin,
// and "front", whose rewrite targets shop. Each backend records what it gets.
type transportRig struct {
	h          *skipHarness
	mu         sync.Mutex
	received   []*http.Request
	authorized int
}

const shopContract = `openapi: 3.1.0
paths:
  /items/{id}:
    get:
      operationId: getItem
      security: [{account: []}]
      responses: {'200': {description: OK}}
  /slow:
    get:
      operationId: slow
      security: []
      x-darban-policy: anonymous
      responses: {'200': {description: OK}}
  /login/{step}:
    post:
      operationId: login
      security: []
      x-darban-policy: anonymous
      responses: {'200': {description: OK}}
  /cart:
    post:
      operationId: checkout
      security: [{account: []}]
      responses: {'200': {description: OK}}
  /zrpc/{method}:
    post:
      x-darban-visibility: internal
components:
  securitySchemes:
    account: {type: http, scheme: bearer}
`

func newTransportRig(t *testing.T, shop serviceBinding, options ...func(*upstreamBindings)) *transportRig {
	r := &transportRig{}
	handler := func(w http.ResponseWriter, q *http.Request) {
		r.mu.Lock()
		r.received = append(r.received, q.Clone(q.Context()))
		r.mu.Unlock()
		if strings.HasSuffix(q.URL.Path, "/slow") {
			time.Sleep(200 * time.Millisecond)
		}
		w.Header().Set("Location", "/items/next?step=2")
		w.Header().Set("Set-Cookie", "session=1; Path=/items; Domain=backend.example; Secure")
		w.WriteHeader(http.StatusTeapot)
	}
	primary, debug := httptest.NewServer(http.HandlerFunc(handler)), httptest.NewServer(http.HandlerFunc(handler))
	authz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		r.mu.Lock()
		r.authorized++
		r.mu.Unlock()
		w.Header().Set("X-Id", "verified")
		w.Header().Set("X-Real-Ip", "198.51.100.66")
		if q.Header.Get("Authorization") == "Bearer admin" {
			w.Header().Set("X-Debug-Allowed", "true")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(primary.Close)
	t.Cleanup(debug.Close)
	t.Cleanup(authz.Close)
	shop.Origin, shop.DebugOrigin = primary.URL, debug.URL
	bindings := upstreamBindings{
		Hostname: "api.example.net", Authz: authz.URL, UpstreamRequestHeaders: []string{"X-Trace"},
		Authorization: authorizationConfig{Path: "/authz", RequestHeaders: []string{"X-Tenant"},
			ResponseHeaders: []string{"X-Id", "X-Debug-Allowed"}, StripHeaderPrefixes: []string{"X-Id-"}},
		Debug: debugConfig{RequestHeader: "X-Debug-Backend", RequiredHeader: "X-Debug-Allowed", RequiredValue: "true"},
		Services: map[string]serviceBinding{
			"shop":  shop,
			"front": {Origin: primary.URL},
		},
	}
	for name, binding := range bindings.Services {
		binding.Origin = primary.URL
		if name == "shop" {
			binding.DebugOrigin = debug.URL
		}
		bindings.Services[name] = binding
	}
	// The rig's requests come from 192.0.2.10, the ingress.
	bindings.ClientIP = clientIPConfig{TrustedProxies: []string{"192.0.2.0/24"}}
	for _, option := range options {
		option(&bindings)
	}
	if err := bindings.ClientIP.validate(); err != nil {
		t.Fatal(err)
	}
	validateServices(t, bindings)
	r.h = newSkipHarness(t, bindings)
	r.h.apply(
		registration{serviceName: "shop", rewrites: "[]", openAPI: shopContract},
		registration{serviceName: "front", openAPI: anonymousContract("/home", "home"),
			rewrites: `[{from: {method: GET, path: /front/slow}, to: {serviceName: shop, path: /slow}},
				{from: {method: POST, path: /front/checkout}, to: {serviceName: shop, path: /cart}}]`},
	)
	for _, name := range []string{"shop", "front"} {
		if status := r.h.status()[name]; status.Rejected {
			t.Fatalf("%s rejected: %+v", name, status.LastRejection)
		}
	}
	return r
}

func (r *transportRig) do(method, host, target string, headers http.Header) (*httptest.ResponseRecorder, *http.Request) {
	r.mu.Lock()
	r.received = nil
	r.mu.Unlock()
	req := httptest.NewRequest(method, target, nil)
	req.Host = host
	req.RemoteAddr = "192.0.2.10:4444"
	for name, values := range headers {
		req.Header[name] = values
	}
	res := httptest.NewRecorder()
	r.h.g.serve(r.h.active.Load(), res, req)
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.received) != 1 {
		return res, nil
	}
	return res, r.received[0]
}

func TestEveryKindOfRequestGetsTheSameTransport(t *testing.T) {
	r := newTransportRig(t, serviceBinding{UpstreamHost: "shop.internal.example", LegacyHosts: []string{"shop.example.net"},
		Prefix: "/shop", LongResponsePaths: []string{"/slow"}, LongResponseHeaderTimeout: "50ms",
		ExtraRoutes: []extraRoute{{Method: "GET", Path: "/assets/*", Auth: extraAuthGateway}}})
	caller := http.Header{"Authorization": {"Bearer x"}, "X-Trace": {"t-1"}, "X-Id": {"forged"}, "X-Id-Extra": {"forged"},
		"X-Real-Ip": {"203.0.113.9"}, "X-Forwarded-For": {"198.51.100.1"}, "Forwarded": {"for=198.51.100.1"},
		"X-Forwarded-Prefix": {"/evil"}, "X-Forwarded-Client-Cert": {"evil"}, "True-Client-Ip": {"198.51.100.1"},
		"Client-Ip": {"198.51.100.1"}}
	admin := http.Header{}
	for name, values := range caller {
		admin[name] = values
	}
	admin["Authorization"] = []string{"Bearer admin"}
	admin["X-Debug-Backend"] = []string{"true"}
	for name, request := range map[string]struct {
		host, target string
		headers      http.Header
		upstreamPath string
	}{
		"operation":    {"api.example.net", "/shop/items/7?q=1", caller, "/items/7"},
		"extra route":  {"api.example.net", "/shop/assets/app.js?q=1", caller, "/assets/app.js"},
		"debug origin": {"api.example.net", "/shop/items/7?q=1", admin, "/items/7"},
	} {
		res, upstream := r.do("GET", request.host, request.target, request.headers)
		if res.Code != http.StatusTeapot || upstream == nil {
			t.Fatalf("%s: %d", name, res.Code)
		}
		want := map[string]string{
			"Host": "shop.internal.example", "Path": request.upstreamPath, "Query": "q=1",
			"X-Real-Ip": "203.0.113.9", "X-Forwarded-For": "", "Forwarded": "", "X-Trace": "t-1",
			"X-Id": "verified", "X-Id-Extra": "", "Authorization": "", "X-Debug-Backend": "",
			"X-Forwarded-Prefix": "", "X-Forwarded-Client-Cert": "", "True-Client-Ip": "", "Client-Ip": "",
		}
		got := map[string]string{"Host": upstream.Host, "Path": upstream.URL.Path, "Query": upstream.URL.RawQuery}
		for header := range want {
			if _, special := got[header]; !special {
				got[header] = upstream.Header.Get(header)
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: upstream got %v, want %v", name, got, want)
		}
		if location := res.Header().Get("Location"); location != "/shop/items/next?step=2" {
			t.Errorf("%s: Location %q", name, location)
		}
		if cookies := res.Result().Cookies(); len(cookies) != 1 || cookies[0].Path != "/shop/items" || cookies[0].Domain != "" {
			t.Errorf("%s: cookies %v", name, cookies)
		}
	}
	// The rewrite from front goes to shop's path through shop's transport:
	// its host, its long-response timeout, its client IP.
	res, _ := r.do("GET", "api.example.net", "/front/slow", caller)
	if res.Code != http.StatusBadGateway {
		t.Errorf("rewrite: %d, want shop's long-response timeout", res.Code)
	}
	for name, target := range map[string]string{"operation": "/shop/slow", "debug": "/shop/slow"} {
		headers := caller
		if name == "debug" {
			headers = admin
		}
		if res, _ := r.do("GET", "api.example.net", target, headers); res.Code != http.StatusBadGateway {
			t.Errorf("%s: %d, want the long-response timeout", name, res.Code)
		}
	}
	// A legacy host keeps its Host and the backend's own paths.
	res, upstream := r.do("GET", "shop.example.net", "/items/7", caller)
	if res.Code != http.StatusTeapot || upstream.Host != "shop.example.net" || upstream.URL.Path != "/items/7" ||
		upstream.Header.Get("X-Real-Ip") != "203.0.113.9" || res.Header().Get("Location") != "/items/next?step=2" {
		t.Errorf("legacy host: %d %v %v", res.Code, upstream, res.Header())
	}
}

func TestRewriteGetsItsTargetsSettings(t *testing.T) {
	r := newTransportRig(t, serviceBinding{UpstreamHost: "shop.internal.example", Prefix: "/shop"})
	forged := http.Header{"X-Real-Ip": {"203.0.113.9"}, "X-Id": {"forged"}, "X-Id-Extra": {"forged"}, "Authorization": {"Bearer x"}}
	// An anonymous target: the caller's credentials pass, forged identity
	// headers do not.
	res, upstream := r.do("GET", "api.example.net", "/front/slow", forged)
	if res.Code != http.StatusTeapot || upstream.Host != "shop.internal.example" || upstream.URL.Path != "/slow" ||
		upstream.Header.Get("X-Real-Ip") != "203.0.113.9" || res.Header().Get("Location") != "/shop/items/next?step=2" ||
		upstream.Header.Get("X-Id") != "" || upstream.Header.Get("X-Id-Extra") != "" || upstream.Header.Get("Authorization") != "Bearer x" {
		t.Fatalf("rewrite: %d %v %v", res.Code, upstream, res.Header())
	}
	// A protected target: the authorizer's identity replaces the credentials.
	res, upstream = r.do("POST", "api.example.net", "/front/checkout", forged)
	if res.Code != http.StatusTeapot || upstream.URL.Path != "/cart" || upstream.Header.Get("X-Id") != "verified" ||
		upstream.Header.Get("X-Id-Extra") != "" || upstream.Header.Get("Authorization") != "" || r.authorized != 1 {
		t.Fatalf("protected rewrite: %d %v", res.Code, upstream)
	}
	// Cookies are scoped to the target's prefix, without the backend's domain.
	if cookies := res.Result().Cookies(); len(cookies) != 1 || cookies[0].Path != "/shop/items" || cookies[0].Domain != "" {
		t.Errorf("rewrite cookies %v", cookies)
	}
}

func TestTheRawQueryIsForwardedAsSent(t *testing.T) {
	r := newTransportRig(t, serviceBinding{Prefix: "/shop"})
	for _, query := range []string{"a=1;x", "b=%zz&b=2", "c", "d=1&&e="} {
		if _, upstream := r.do("GET", "api.example.net", "/shop/slow?"+query, nil); upstream == nil || upstream.URL.RawQuery != query {
			t.Errorf("%q: upstream %v", query, upstream)
		}
	}
}

func TestBackendAuthPreservesMethodQueryAndCredentials(t *testing.T) {
	r := newTransportRig(t, serviceBinding{Prefix: "/shop", BackendAuth: true})
	res, upstream := r.do("POST", "api.example.net", "/shop/login/%6eext?one=a%2Bb&one=c", http.Header{
		"Authorization": {"Bearer example"}, "Cookie": {"session=example"}, "X-Tenant": {"tenant"},
		"X-Id": {"spoofed"}, "X-Original-Uri": {"/spoofed"},
	})
	if res.Code != http.StatusTeapot || upstream.Method != "POST" || upstream.RequestURI != "/login/next?one=a%2Bb&one=c" {
		t.Fatalf("forwarded %d %v", res.Code, upstream)
	}
	for key, want := range map[string]string{
		"Authorization": "Bearer example", "Cookie": "session=example", "X-Tenant": "tenant",
		"X-Id": "", "X-Original-Uri": "/shop/login/%6eext?one=a%2Bb&one=c",
	} {
		if got := upstream.Header.Get(key); got != want {
			t.Errorf("forwarded %s = %q, want %q", key, got, want)
		}
	}
	if r.authorized != 0 {
		t.Error("backendAuth called the authorizer")
	}
}

func TestClientIPIsAlwaysSetAndCannotBeSpoofed(t *testing.T) {
	ingress := clientIPConfig{TrustedProxies: []string{"10.0.0.0/8"}}
	for name, test := range map[string]struct {
		config  clientIPConfig
		remote  string
		headers http.Header
		want    string
	}{
		"no trusted proxies":       {clientIPConfig{}, "10.0.0.5:1", http.Header{"X-Real-Ip": {"203.0.113.9"}}, "10.0.0.5"},
		"from the ingress":         {ingress, "10.0.0.5:1", http.Header{"X-Real-Ip": {"203.0.113.9"}}, "203.0.113.9"},
		"mapped address":           {ingress, "10.0.0.5:1", http.Header{"X-Real-Ip": {"::ffff:203.0.113.9"}}, "203.0.113.9"},
		"no header":                {ingress, "10.0.0.5:1", nil, "10.0.0.5"},
		"two values":               {ingress, "10.0.0.5:1", http.Header{"X-Real-Ip": {"203.0.113.9", "198.51.100.1"}}, "10.0.0.5"},
		"not an address":           {ingress, "10.0.0.5:1", http.Header{"X-Real-Ip": {"evil"}}, "10.0.0.5"},
		"zone":                     {ingress, "10.0.0.5:1", http.Header{"X-Real-Ip": {"fe80::1%eth0"}}, "10.0.0.5"},
		"forwarded-for is ignored": {ingress, "10.0.0.5:1", http.Header{"X-Forwarded-For": {"203.0.113.9"}}, "10.0.0.5"},
		"trusted proxy":            {clientIPConfig{TrustedProxies: []string{"10.0.0.0/8"}}, "10.0.0.5:1", http.Header{"X-Real-Ip": {"203.0.113.9"}}, "203.0.113.9"},
		"untrusted peer":           {clientIPConfig{TrustedProxies: []string{"10.0.0.0/8"}}, "192.0.2.10:1", http.Header{"X-Real-Ip": {"203.0.113.9"}}, "192.0.2.10"},
		"single trusted address":   {clientIPConfig{TrustedProxies: []string{"10.0.0.5"}}, "10.0.0.5:1", http.Header{"X-Real-Ip": {"203.0.113.9"}}, "203.0.113.9"},
		"other header":             {clientIPConfig{Header: "CF-Connecting-IP", TrustedProxies: []string{"10.0.0.0/8"}}, "10.0.0.5:1", http.Header{"Cf-Connecting-Ip": {"203.0.113.9"}, "X-Real-Ip": {"198.51.100.1"}}, "203.0.113.9"},
	} {
		if err := test.config.validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = test.remote
		for key, values := range test.headers {
			req.Header[key] = values
		}
		if got := test.config.clientIP(req); got != test.want {
			t.Errorf("%s: %q, want %q", name, got, test.want)
		}
	}
	for _, good := range []string{"X-Real-IP", "cf-connecting-ip", "True-Client-IP", "X-Envoy-External-Address"} {
		if err := (&clientIPConfig{Header: good}).validate(); err != nil {
			t.Errorf("%s: %v", good, err)
		}
	}
	for _, bad := range []clientIPConfig{{Header: "Authorization"}, {Header: "bad header"}, {Header: "Cookie"}, {Header: "Content-Type"},
		{Header: "X-Forwarded-For"}, {Header: "X-Custom"}, {TrustedProxies: []string{"10.0.0.0/33"}}, {TrustedProxies: []string{"proxy"}}} {
		if err := bad.validate(); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}

	// Upstream, the address replaces every caller copy, in any configuration.
	r := newTransportRig(t, serviceBinding{Prefix: "/shop"}, func(b *upstreamBindings) {
		b.ClientIP = clientIPConfig{Header: "CF-Connecting-IP", TrustedProxies: []string{"10.0.0.0/8"}}
	})
	_, upstream := r.do("GET", "api.example.net", "/shop/slow", http.Header{"Cf-Connecting-Ip": {"203.0.113.9"}, "X-Real-Ip": {"198.51.100.1"}})
	if upstream == nil || upstream.Header.Get("X-Real-Ip") != "192.0.2.10" || upstream.Header.Get("Cf-Connecting-Ip") != "" {
		t.Fatalf("untrusted peer: %v", upstream)
	}
}

func TestProtectedOperationChecksAuthzAndProjectsOnlyItsIdentity(t *testing.T) {
	r := newTransportRig(t, serviceBinding{Prefix: "/shop"})
	if res, upstream := r.do("GET", "api.example.net", "/shop/items/123", http.Header{"Upgrade": {"websocket"}, "Connection": {"Upgrade"}}); res.Code != 401 || upstream != nil {
		t.Fatalf("upgrade without credentials returned %d", res.Code)
	}
	res, upstream := r.do("GET", "api.example.net", "/shop/items/123", http.Header{"Authorization": {"Bearer example"}, "X-Id": {"spoofed"}})
	if res.Code != http.StatusTeapot || upstream.RequestURI != "/items/123" || upstream.Header.Get("Authorization") != "" || upstream.Header.Get("X-Id") != "verified" {
		t.Fatalf("protected upstream request %d %v", res.Code, upstream)
	}
}

func TestServiceRejectsAPublicOrigin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bindings.json")
	os.WriteFile(path, []byte(`{"hostname": "api.example.net", "contractAPIGroup": "darban.zyno.io", "services": {"catalog": {"origin": "http://catalog.example.net:3000"}}}`), 0o600)
	if _, err := loadBindings(path, false); err == nil {
		t.Fatal("public host is not a Kubernetes Service")
	}
}

func TestEveryRequestIsVerifiedOnEveryHost(t *testing.T) {
	r := newTransportRig(t, serviceBinding{Prefix: "/shop", LegacyHosts: []string{"shop.example.net"}, BackendAuth: true,
		ExtraRoutes: []extraRoute{{Method: "GET", Path: "/assets/*", Auth: extraAuthNone}}})
	for _, test := range []struct {
		method, host, target string
		code                 int
		upstream             string
	}{
		{"GET", "api.example.net", "/shop/items/7", 418, "GET /items/7"},
		{"HEAD", "api.example.net", "/shop/items/7", 418, "GET /items/7"},
		{"GET", "api.example.net", "/shop/assets/a/b.css", 418, "GET /assets/a/b.css"},
		{"GET", "shop.example.net", "/items/7", 418, "GET /items/7"},
		{"HEAD", "shop.example.net", "/items/7", 418, "GET /items/7"},
		// One trailing slash is allowed, and the backend sees it.
		{"GET", "api.example.net", "/shop/items/7/", 418, "GET /items/7/"},
		{"GET", "shop.example.net", "/items/7/", 418, "GET /items/7/"},
		{"GET", "api.example.net", "/shop/assets/a/", 418, "GET /assets/a/"},
		{"GET", "shop.example.net", "/assets/a.css", 418, "GET /assets/a.css"},
		// Undeclared methods and paths, on every service and host.
		{"POST", "api.example.net", "/shop/items/7", 404, ""},
		{"GET", "api.example.net", "/shop/other", 404, ""},
		{"GET", "api.example.net", "/shop", 404, ""},
		{"GET", "api.example.net", "/front/other", 404, ""},
		{"GET", "api.example.net", "/front", 404, ""},
		{"GET", "api.example.net", "/nobody/home", 404, ""},
		{"GET", "shop.example.net", "/other", 404, ""},
		{"GET", "shop.example.net", "/", 404, ""},
		{"DELETE", "shop.example.net", "/items/7", 404, ""},
		// Internal operations.
		{"POST", "api.example.net", "/shop/zrpc/run", 404, ""},
		{"POST", "shop.example.net", "/zrpc/run", 404, ""},
		{"POST", "shop.example.net", "/zrpc/%72un", 404, ""},
		// Non-canonical and encoded-prefix paths.
		{"GET", "api.example.net", "/shop/items//7", 404, ""},
		{"GET", "api.example.net", "/shop/items/a%2Fb", 404, ""},
		{"GET", "api.example.net", "/shop/x/../items/7", 404, ""},
		{"GET", "shop.example.net", "/items/a%2Fb", 404, ""},
		{"GET", "shop.example.net", "/x/../items/7", 404, ""},
		{"GET", "api.example.net", "/sh%6Fp/items/7", 404, ""},
		{"GET", "api.example.net", "/%73hop/assets/a.css", 404, ""},
	} {
		res, upstream := r.do(test.method, test.host, test.target, nil)
		sent := ""
		if upstream != nil {
			sent = upstream.Method + " " + upstream.URL.EscapedPath()
		}
		if res.Code != test.code || sent != test.upstream {
			t.Errorf("%s %s%s = %d %q, want %d %q", test.method, test.host, test.target, res.Code, sent, test.code, test.upstream)
		}
	}
}

func TestAProjectedIdentityCannotSetTheClientIP(t *testing.T) {
	r := newTransportRig(t, serviceBinding{Prefix: "/shop"}, func(b *upstreamBindings) {
		b.Authorization.ResponseHeaders = append(b.Authorization.ResponseHeaders, "X-Real-Ip")
	})
	_, upstream := r.do("GET", "api.example.net", "/shop/items/7", http.Header{"Authorization": {"Bearer x"}, "X-Real-Ip": {"203.0.113.9"}})
	if upstream == nil || upstream.Header.Get("X-Real-Ip") != "203.0.113.9" {
		t.Fatalf("upstream %v", upstream)
	}
}

func TestBackendPreflightFollowsTheServiceThatServesThePath(t *testing.T) {
	preflight := http.Header{"Origin": {"https://unknown.example"}, "Access-Control-Request-Method": {"POST"}}
	// front leaves CORS to its backend, but its rewrite is served by shop,
	// which does not: the preflight never reaches shop without authorization.
	r := newTransportRig(t, serviceBinding{Prefix: "/shop"}, func(b *upstreamBindings) {
		front := b.Services["front"]
		front.BackendCORS = true
		b.Services["front"] = front
	})
	if res, upstream := r.do("OPTIONS", "api.example.net", "/front/checkout", preflight); upstream != nil || res.Code != http.StatusNotFound {
		t.Errorf("backendCORS owner, gateway target: %d %v", res.Code, upstream)
	}
	// With browserOrigins, as in Alpha, the gateway answers it instead, for
	// any origin, still without reaching shop or the authorizer.
	for _, origin := range []string{"https://unknown.example", "https://app.example.net"} {
		r = newTransportRig(t, serviceBinding{Prefix: "/shop"}, func(b *upstreamBindings) {
			b.BrowserOrigins = []string{"https://app.example.net"}
			front := b.Services["front"]
			front.BackendCORS = true
			b.Services["front"] = front
		})
		headers := http.Header{"Origin": {origin}, "Access-Control-Request-Method": {"POST"}}
		if res, upstream := r.do("OPTIONS", "api.example.net", "/front/checkout", headers); upstream != nil || r.authorized != 0 || res.Code >= 500 {
			t.Errorf("browser origins %s: %d %v", origin, res.Code, upstream)
		}
	}
	// The reverse: shop leaves CORS to its backend, which answers the
	// preflight for the rewrite into it, with or without browserOrigins.
	r = newTransportRig(t, serviceBinding{Prefix: "/shop", BackendCORS: true}, func(b *upstreamBindings) {
		b.BrowserOrigins = []string{"https://app.example.net"}
	})
	if res, upstream := r.do("OPTIONS", "api.example.net", "/front/checkout", preflight); res.Code != http.StatusTeapot || upstream == nil || r.authorized != 0 {
		t.Errorf("browser origins, backendCORS target: %d %v", res.Code, upstream)
	}
	r = newTransportRig(t, serviceBinding{Prefix: "/shop", BackendCORS: true})
	res, upstream := r.do("OPTIONS", "api.example.net", "/front/checkout", preflight)
	if res.Code != http.StatusTeapot || upstream == nil || upstream.Method != "OPTIONS" || upstream.URL.Path != "/cart" || r.authorized != 0 {
		t.Errorf("gateway owner, backendCORS target: %d %v authorized=%d", res.Code, upstream, r.authorized)
	}
	// The operation itself is still authorized.
	if res, _ := r.do("POST", "api.example.net", "/front/checkout", nil); res.Code != http.StatusUnauthorized {
		t.Errorf("POST without credentials = %d", res.Code)
	}
}

func TestLoadRejectsSettingsDarbanWouldOverride(t *testing.T) {
	bindings := contractOnlyBindings()
	bindings.Services["shop"] = serviceBinding{LegacyHosts: []string{"shop.example.net"}}
	_, report := compile([]registration{clusterContract("shop", "/api/items", "listShop", "http://shop/api", "")}, bindings, nil)
	if !strings.Contains(report.services["shop"].rejection, "legacyHosts") {
		t.Fatalf("shop %+v", report.services["shop"])
	}
	for name, body := range map[string]string{
		"mount":    `{"hostname": "api.example.net", "services": {"a": {"mount": "/api", "legacyHosts": ["a.example.net"]}}}`,
		"reserved": `{"hostname": "api.example.net", "openapi": {"yamlPath": "/docs/openapi.yaml"}, "services": {"docs": {}}}`,
		"projected": `{"hostname": "api.example.net", "authz": "http://authz.fixtures.svc.cluster.local:80",
			"authorization": {"path": "/authz", "responseHeaders": ["X-Forwarded-User"]}}`,
		"alias": `{"hostname": "api.example.net", "upstreamRequestHeaders": ["True-Client-IP"]}`,
	} {
		if err := writeBindings(t, body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestProtectedOperationsNeedAnAuthorizer(t *testing.T) {
	bindings := contractOnlyBindings()
	bindings.Services["shop"] = serviceBinding{Origin: "http://shop." + testNamespace + ".svc.cluster.local:80"}
	reg := registration{serviceName: "shop", rewrites: "[]", openAPI: shopContract}
	// -print-spec and -report need no authorizer.
	if _, report := compile([]registration{reg}, bindings, nil); report.services["shop"].rejection != "" {
		t.Fatalf("one-shot: %+v", report.services["shop"])
	}
	bindings.requireAuthz = true
	if _, report := compile([]registration{reg}, bindings, nil); !strings.Contains(report.services["shop"].rejection, "needs authz") {
		t.Fatalf("serving: %+v", report.services["shop"])
	}
	// backendAuth needs none.
	bindings.Services["shop"] = serviceBinding{Origin: "http://shop." + testNamespace + ".svc.cluster.local:80", BackendAuth: true}
	if _, report := compile([]registration{reg}, bindings, nil); report.services["shop"].rejection != "" {
		t.Fatalf("backendAuth: %+v", report.services["shop"])
	}
}
