package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIngressRoutePreservesMethodQueryAndCredentials(t *testing.T) {
	var receivedURI, receivedMethod string
	var receivedHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedURI, receivedMethod = r.RequestURI, r.Method
		receivedHeaders = r.Header.Clone()
		w.Header().Set("Set-Cookie", "session=example; Path=/login/renew; Secure; HttpOnly; SameSite=None")
		w.Header().Set("Location", "/login/next?source=browser")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer upstream.Close()

	bindings := upstreamBindings{
		Hostname: "api.example.net", IngressRoutes: map[string]string{"/auth": upstream.URL},
		Authorization: authorizationConfig{
			RequestHeaders: []string{"X-Tenant"}, ResponseHeaders: []string{"X-Identity"},
			StripHeaderPrefixes: []string{"X-Identity-"},
		},
	}
	if err := bindings.validateIngressRoutes(true); err != nil {
		t.Fatal(err)
	}
	gw := newGateway(bindings)
	request := httptest.NewRequest("POST", "/auth/login/%6eext?one=a%2Bb&one=c", nil)
	request.Host = bindings.Hostname
	request.Header.Set("Authorization", "Bearer example")
	request.Header.Set("Cookie", "session=example")
	request.Header.Set("X-Tenant", "tenant")
	request.Header.Set("X-Identity", "spoofed")
	request.Header.Set("X-Identity-Extra", "spoofed")
	request.Header.Set("X-Original-Uri", "/spoofed")
	response := httptest.NewRecorder()
	gw.serve(&snapshot{}, response, request)
	if receivedURI != "/login/%6eext?one=a%2Bb&one=c" || receivedMethod != "POST" {
		t.Fatalf("forwarded %s %s", receivedMethod, receivedURI)
	}
	for key, want := range map[string]string{
		"Authorization": "Bearer example", "Cookie": "session=example", "X-Tenant": "tenant",
		"X-Identity": "", "X-Identity-Extra": "", "X-Original-Uri": "",
	} {
		if got := receivedHeaders.Get(key); got != want {
			t.Errorf("forwarded %s = %q, want %q", key, got, want)
		}
	}
	if response.Code != 307 || response.Header().Get("Location") != "/auth/login/next?source=browser" {
		t.Errorf("redirect %d %s", response.Code, response.Header().Get("Location"))
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Path != "/auth/login/renew" || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteNoneMode {
		t.Errorf("unexpected cookie attributes: %v", cookies)
	}
}

func TestIngressCannotOverrideManagedOperationOrInternalPath(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ingress")
	}))
	defer upstream.Close()

	bindings := upstreamBindings{
		Hostname: "api.example.net", IngressRoutes: map[string]string{"/catalog": upstream.URL},
		BrowserOrigins: []string{"https://app.example.net"},
	}
	gw := newGateway(bindings)
	active := &snapshot{
		routes:          map[operationKey]registeredRoute{{http.MethodGet, "/catalog/prices"}: {credentials: []string{"account"}}},
		denied:          map[operationKey]bool{{http.MethodGet, "/catalog/private"}: true},
		deniedTemplates: []operationKey{{http.MethodGet, "/catalog/internal/{id}"}},
	}
	for _, tc := range []struct {
		method, path, origin string
		want                 int
	}{
		{"GET", "/catalog/tabs/123", "", 200},
		{"GET", "/catalog/prices", "", 401},
		{"GET", "/catalog/%70rices/", "", 401},
		{"GET", "/catalog/private", "", 404},
		{"GET", "/catalog/internal/123", "", 404},
		{"GET", "/catalog/../other", "", 404},
		{"GET", "/catalogue/tabs", "", 404},
		{"OPTIONS", "/catalog/prices", "https://app.example.net", 204},
		{"OPTIONS", "/catalog/prices", "https://unknown.example.net", 403},
	} {
		t.Run(tc.method+" "+tc.path+" "+tc.origin, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Host = bindings.Hostname
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
				req.Header.Set("Access-Control-Request-Method", "GET")
				req.Header.Set("Access-Control-Request-Headers", "authorization,x-tenant")
			}
			res := httptest.NewRecorder()
			gw.serve(active, res, req)
			if res.Code != tc.want {
				t.Fatalf("status %d, want %d", res.Code, tc.want)
			}
			if tc.want == 204 && (!strings.EqualFold(res.Header().Get("Access-Control-Allow-Headers"), "authorization,x-tenant") ||
				res.Header().Get("Access-Control-Allow-Origin") != tc.origin) {
				t.Fatalf("unexpected CORS headers: %v", res.Header())
			}
		})
	}
}

func TestIngressFallbackBlocksInternalOperationsOutsideSelection(t *testing.T) {
	bindings := upstreamBindings{
		Hostname: "api.example.net",
		Services: map[string]serviceBinding{
			"catalog": {Prefix: "/catalog", Operations: []operationSelection{{Method: "get", Path: "/prices"}}},
		},
		IngressRoutes: map[string]string{"/catalog": "https://catalog.example.net"},
	}
	reg := registration{
		serviceName: "catalog",
		rewrites:    "[]",
		openAPI: `openapi: 3.1.0
paths:
  /prices:
    get:
      security: []
      x-gateway-policy: anonymous
      responses:
        "200": {description: OK}
  /private/{id}:
    post:
      x-darban-visibility: internal
`,
	}
	compiled, err := compile([]registration{reg}, bindings)
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.denied) != 1 || compiled.denied[0] != (operationKey{"POST", "/catalog/private/{id}"}) {
		t.Fatalf("unexpected internal routes: %v", compiled.denied)
	}
	reg.openAPI = strings.ReplaceAll(reg.openAPI, "internal", "unlisted")
	withoutDenial, err := compile([]registration{reg}, bindings)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.revision == withoutDenial.revision {
		t.Fatal("internal fallback exclusions must affect the runtime revision")
	}
}
