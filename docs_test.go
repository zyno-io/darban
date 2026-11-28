package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// docsContract is a service contract with tags, a tag description and the
// two security schemes every Alpha service defines.
func docsContract(operationID, bearerFormat string) string {
	return fmt.Sprintf(`openapi: 3.1.0
tags:
  - {name: billingCatalog, description: Products and prices.}
paths:
  /items:
    get:
      operationId: list%[1]s
      tags: [billingCatalog, crm.authPolicies]
      security: [{accountBearer: []}, {tenantApiKey: []}]
      responses: {'200': {description: OK, content: {application/json: {schema: {$ref: '#/components/schemas/Item'}}}}}
  /keys:
    get:
      operationId: keys%[1]s
      security: [{keys: []}]
      responses: {'200': {description: OK}}
  /open:
    get:
      operationId: open%[1]s
      security: []
      x-darban-policy: anonymous
      responses: {'200': {description: OK}}
components:
  schemas:
    Item: {type: object}
  securitySchemes:
    accountBearer: {type: http, scheme: bearer, bearerFormat: %[2]s}
    tenantApiKey: {type: http, scheme: basic}
    keys: {type: apiKey, in: header, name: X-Key}
`, operationID, bearerFormat)
}

type composedDocument struct {
	Info       map[string]any `json:"info"`
	Tags       []map[string]any
	TagGroups  []map[string]any `json:"x-tagGroups"`
	Components struct {
		SecuritySchemes map[string]map[string]any `json:"securitySchemes"`
	} `json:"components"`
	Paths map[string]map[string]struct {
		Tags     []string              `json:"tags"`
		Security []map[string][]string `json:"security"`
	} `json:"paths"`
}

func compose(t *testing.T, bindings upstreamBindings, regs ...registration) (candidate, composedDocument) {
	t.Helper()
	got, report := compile(regs, bindings, nil)
	for name, outcome := range report.services {
		if outcome.rejection != "" {
			t.Fatalf("%s: %s", name, outcome.rejection)
		}
	}
	var document composedDocument
	if err := json.Unmarshal(got.specJSON, &document); err != nil {
		t.Fatal(err)
	}
	return got, document
}

func docsBindings(names ...string) upstreamBindings {
	bindings := isolationBindings(names...)
	bindings.OpenAPI.JSONPath = "/openapi.json"
	return bindings
}

func TestIdenticalSecuritySchemesAreMerged(t *testing.T) {
	bindings := docsBindings("auth", "sales")
	regs := []registration{
		{serviceName: "auth", rewrites: "[]", openAPI: docsContract("Auth", "JWT")},
		{serviceName: "sales", rewrites: "[]", openAPI: docsContract("Sales", "JWT")},
	}
	first, document := compose(t, bindings, regs...)
	if got := mapKeys(document.Components.SecuritySchemes); !reflect.DeepEqual(got, []string{"accountBearer", "keys", "tenantApiKey"}) {
		t.Fatalf("schemes %v", got)
	}
	for _, path := range []string{"/auth/items", "/sales/items"} {
		if security := document.Paths[path]["get"].Security; !reflect.DeepEqual(security, []map[string][]string{{"accountBearer": {}}, {"tenantApiKey": {}}}) {
			t.Errorf("%s security %v", path, security)
		}
	}
	// The merge does not depend on map order.
	for range 20 {
		if again, _ := compose(t, bindings, regs...); string(again.specJSON) != string(first.specJSON) {
			t.Fatal("the document depends on map order")
		}
	}
}

func TestDottedSchemeNamesMergeOnce(t *testing.T) {
	contract := func(id string) string {
		return strings.NewReplacer("accountBearer", "acct.bearer", "tenantApiKey", "tenant.key").Replace(docsContract(id, "JWT"))
	}
	_, document := compose(t, docsBindings("auth", "sales"),
		registration{serviceName: "auth", rewrites: "[]", openAPI: contract("Auth")},
		registration{serviceName: "sales", rewrites: "[]", openAPI: contract("Sales")},
	)
	if got := mapKeys(document.Components.SecuritySchemes); !reflect.DeepEqual(got, []string{"acct.bearer", "keys", "tenant.key"}) {
		t.Fatalf("schemes %v", got)
	}
}

func TestDifferentSecuritySchemesKeepTheirPrefixes(t *testing.T) {
	bindings := docsBindings("auth", "sales", "talk")
	_, document := compose(t, bindings,
		registration{serviceName: "auth", rewrites: "[]", openAPI: docsContract("Auth", "JWT")},
		registration{serviceName: "sales", rewrites: "[]", openAPI: docsContract("Sales", "JWT")},
		registration{serviceName: "talk", rewrites: "[]", openAPI: docsContract("Talk", "opaque")},
	)
	// accountBearer differs in talk, so all three keep their names; the
	// others are identical and merge.
	want := []string{"auth.accountBearer", "sales.accountBearer", "talk.accountBearer", "keys", "tenantApiKey"}
	if got := mapKeys(document.Components.SecuritySchemes); !sameElements(got, want) {
		t.Fatalf("schemes %v", got)
	}
	if security := document.Paths["/talk/items"]["get"].Security; !reflect.DeepEqual(security, []map[string][]string{{"talk.accountBearer": {}}, {"tenantApiKey": {}}}) {
		t.Errorf("talk security %v", security)
	}
}

func TestTagsAreGroupedByServiceWithReadableNames(t *testing.T) {
	bindings := docsBindings("auth", "book-catalog")
	auth := bindings.Services["auth"]
	auth.Title = "Identity & Access"
	bindings.Services["auth"] = auth
	_, document := compose(t, bindings,
		registration{serviceName: "auth", rewrites: "[]", openAPI: docsContract("Auth", "JWT")},
		registration{serviceName: "book-catalog", rewrites: "[]", openAPI: docsContract("Books", "JWT")},
	)
	// Tag names stay as published.
	if tags := document.Paths["/auth/items"]["get"].Tags; !reflect.DeepEqual(tags, []string{"authBillingCatalog", "authCrm.authPolicies"}) {
		t.Fatalf("operation tags %v", tags)
	}
	wantTags := []map[string]any{
		{"name": "authBillingCatalog", "x-displayName": "Billing Catalog", "description": "Products and prices."},
		{"name": "authCrm.authPolicies", "x-displayName": "Crm Auth Policies"},
		{"name": "bookCatalogBillingCatalog", "x-displayName": "Billing Catalog", "description": "Products and prices."},
		{"name": "bookCatalogCrm.authPolicies", "x-displayName": "Crm Auth Policies"},
	}
	if !reflect.DeepEqual(document.Tags, wantTags) {
		t.Errorf("tags %v", document.Tags)
	}
	wantGroups := []map[string]any{
		{"name": "Identity & Access", "tags": []any{"authBillingCatalog", "authCrm.authPolicies"}},
		{"name": "Book Catalog", "tags": []any{"bookCatalogBillingCatalog", "bookCatalogCrm.authPolicies"}},
	}
	if !reflect.DeepEqual(document.TagGroups, wantGroups) {
		t.Errorf("groups %v", document.TagGroups)
	}

	// With prefixTags: firstOnly two services can publish the same tag: it is
	// listed once, and appears in both groups.
	bindings.OpenAPI.PrefixTags = firstTagOnly
	_, document = compose(t, bindings,
		registration{serviceName: "auth", rewrites: "[]", openAPI: docsContract("Auth", "JWT")},
		registration{serviceName: "book-catalog", rewrites: "[]", openAPI: docsContract("Books", "JWT")},
	)
	shared := 0
	for _, tag := range document.Tags {
		if tag["name"] == "crm.authPolicies" {
			shared++
		}
	}
	if shared != 1 || len(document.TagGroups) != 2 {
		t.Fatalf("tags %v groups %v", document.Tags, document.TagGroups)
	}
	for _, group := range document.TagGroups {
		if !strings.Contains(fmt.Sprint(group["tags"]), "crm.authPolicies") {
			t.Errorf("group %v lacks the shared tag", group)
		}
	}
}

func TestDisplayNames(t *testing.T) {
	for tag, want := range map[string]string{
		"salesBillingCatalog":    "Sales Billing Catalog",
		"crm.authPolicies":       "Crm Auth Policies",
		"XCrmMemberships":        "X Crm Memberships",
		"SSEEvents":              "SSE Events",
		"v2Items":                "V2 Items",
		"cap":                    "Cap",
		"tenant-api_keys list":   "Tenant Api Keys List",
		"customerApp.auth":       "Customer App Auth",
		"oidcDiscovery":          "Oidc Discovery",
		"ÉtatCivil":              "État Civil",
		"already Readable Words": "Already Readable Words",
	} {
		if got := displayName(tag); got != want {
			t.Errorf("%q: %q, want %q", tag, got, want)
		}
	}
}

func TestDocumentInfo(t *testing.T) {
	bindings := docsBindings("auth")
	reg := registration{serviceName: "auth", rewrites: "[]", openAPI: docsContract("Auth", "JWT")}
	_, document := compose(t, bindings, reg)
	if !reflect.DeepEqual(document.Info, map[string]any{"title": "Darban", "version": "1"}) {
		t.Errorf("default info %v", document.Info)
	}
	bindings.OpenAPI.Info = &openAPIInfo{Title: "Zyno API", Description: "All of Zyno.", TermsOfService: "https://zyno.dev/terms",
		Contact: &openAPIContact{Name: "Zyno", Email: "api@zyno.dev"}, License: &openAPILicense{Name: "Proprietary"}}
	_, document = compose(t, bindings, reg)
	want := map[string]any{"title": "Zyno API", "version": "1", "description": "All of Zyno.", "termsOfService": "https://zyno.dev/terms",
		"contact": map[string]any{"name": "Zyno", "email": "api@zyno.dev"}, "license": map[string]any{"name": "Proprietary"}}
	if !reflect.DeepEqual(document.Info, want) {
		t.Errorf("info %v", document.Info)
	}
	base := `{"hostname": "api.example.net", "openapi": {%s}}`
	if err := writeBindings(t, fmt.Sprintf(base, `"cacheControl": "public, max-age=300", "info": {"title": "Zyno API", "version": "2026-11", "license": {"name": "MIT", "identifier": "MIT"}}`)); err != nil {
		t.Errorf("valid: %v", err)
	}
	for name, body := range map[string]string{
		"license name":  `"info": {"license": {"url": "https://example.net/l"}}`,
		"license both":  `"info": {"license": {"name": "MIT", "identifier": "MIT", "url": "https://example.net/l"}}`,
		"terms":         `"info": {"termsOfService": "terms.html"}`,
		"contact url":   `"info": {"contact": {"url": "example"}}`,
		"unknown field": `"info": {"logo": "x"}`,
		"cache control": `"cacheControl": "public\nmax-age=1"`,
		"blank cache":   `"cacheControl": "  "`,
		"openapi field": `"x": 1`,
	} {
		if err := writeBindings(t, fmt.Sprintf(base, body)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for _, title := range []string{" padded ", "two\nlines"} {
		if err := writeBindings(t, fmt.Sprintf(`{"hostname": "api.example.net", "services": {"a": {"title": %q}}}`, title)); err == nil {
			t.Errorf("service title %q accepted", title)
		}
	}
}

// specRig serves the composed documents of one service.
func specRig(t *testing.T, configure func(*upstreamBindings)) (*gateway, *snapshot) {
	t.Helper()
	bindings := docsBindings("auth")
	bindings.OpenAPI.YAMLPath = "/openapi.yaml"
	if configure != nil {
		configure(&bindings)
	}
	g := newGateway(bindings)
	compiled, _ := compile([]registration{{serviceName: "auth", rewrites: "[]", openAPI: docsContract("Auth", "JWT")}}, bindings, nil)
	return g, g.build(compiled)
}

func requestSpec(g *gateway, active *snapshot, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Host = g.bindings.Hostname
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	res := httptest.NewRecorder()
	g.serve(active, res, req)
	return res
}

func TestSpecEndpointsServeCORSGzipAndETags(t *testing.T) {
	g, active := specRig(t, nil)
	for _, path := range []string{"/openapi.json", "/openapi.yaml"} {
		plain := requestSpec(g, active, "GET", path, nil)
		etag := plain.Header().Get("ETag")
		if plain.Code != 200 || plain.Header().Get("Access-Control-Allow-Origin") != "*" || plain.Header().Get("Access-Control-Allow-Credentials") != "" ||
			plain.Header().Get("Content-Encoding") != "" || plain.Header().Get("Vary") != "Accept-Encoding" ||
			plain.Header().Get("Cache-Control") != "public, max-age=60" || !strings.HasPrefix(etag, `"`) || strings.HasPrefix(etag, "W/") {
			t.Fatalf("%s plain: %d %v", path, plain.Code, plain.Header())
		}
		zipped := requestSpec(g, active, "GET", path, map[string]string{"Accept-Encoding": "br, gzip;q=0.8"})
		zippedLength := zipped.Body.Len()
		reader, err := gzip.NewReader(zipped.Body)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		inflated, _ := io.ReadAll(reader)
		zetag := zipped.Header().Get("ETag")
		if zipped.Header().Get("Content-Encoding") != "gzip" || !bytes.Equal(inflated, plain.Body.Bytes()) || zetag == etag ||
			zipped.Header().Get("Content-Length") != fmt.Sprint(zippedLength) {
			t.Errorf("%s gzip: %v", path, zipped.Header())
		}
		// Each representation revalidates against its own ETag.
		for _, test := range []struct {
			encoding, match string
			code            int
		}{
			{"", etag, 304}, {"", "W/" + etag, 304}, {"", `"other", ` + etag, 304}, {"", "*", 304},
			{"gzip", zetag, 304}, {"gzip", etag, 200}, {"", zetag, 200}, {"", `"other"`, 200},
		} {
			res := requestSpec(g, active, "GET", path, map[string]string{"Accept-Encoding": test.encoding, "If-None-Match": test.match})
			if res.Code != test.code || res.Header().Get("Access-Control-Allow-Origin") != "*" {
				t.Errorf("%s %q If-None-Match %s: %d", path, test.encoding, test.match, res.Code)
			}
			if res.Code == 304 && (res.Body.Len() != 0 || res.Header().Get("ETag") == "" || res.Header().Get("Content-Type") != "") {
				t.Errorf("%s 304: %v", path, res.Header())
			}
		}
		head := requestSpec(g, active, "HEAD", path, map[string]string{"Accept-Encoding": "gzip"})
		if head.Code != 200 || head.Body.Len() != 0 || head.Header().Get("Content-Length") != zipped.Header().Get("Content-Length") ||
			head.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("%s HEAD: %d %v", path, head.Code, head.Header())
		}
		preflight := requestSpec(g, active, "OPTIONS", path, map[string]string{"Origin": "https://apidocs.zyno.dev",
			"Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "if-none-match"})
		if preflight.Code != 204 || preflight.Header().Get("Access-Control-Allow-Origin") != "*" ||
			preflight.Header().Get("Access-Control-Allow-Methods") != "GET, HEAD" || preflight.Header().Get("Access-Control-Allow-Headers") != "if-none-match" ||
			preflight.Header().Get("Access-Control-Allow-Credentials") != "" {
			t.Errorf("%s preflight: %d %v", path, preflight.Code, preflight.Header())
		}
		if res := requestSpec(g, active, "POST", path, nil); res.Code != 405 || res.Header().Get("Allow") != "GET, HEAD, OPTIONS" {
			t.Errorf("%s POST: %d %v", path, res.Code, res.Header())
		}
	}
	// The documents are compressed once per snapshot.
	if first, again := active.spec(true), active.spec(true); &first.gzipped[0] != &again.gzipped[0] {
		t.Error("the document was compressed again")
	}
	// A new document has a new ETag; cacheControl is configurable.
	g2, other := specRig(t, func(b *upstreamBindings) {
		b.OpenAPI.CacheControl = "no-cache"
		b.OpenAPI.Info = &openAPIInfo{Title: "Other"}
	})
	res := requestSpec(g2, other, "GET", "/openapi.json", nil)
	if res.Header().Get("ETag") == requestSpec(g, active, "GET", "/openapi.json", nil).Header().Get("ETag") || res.Header().Get("Cache-Control") != "no-cache" {
		t.Errorf("other: %v", res.Header())
	}
}

func TestAcceptsGzip(t *testing.T) {
	for header, want := range map[string]bool{
		"": false, "gzip": true, "GZIP": true, "x-gzip": true, "deflate, gzip;q=0.5": true, "gzip;q=0": false,
		"gzip; q=0.0": false, "*": true, "*;q=0": false, "br, *": true, "gzip;q=0, *": false, "identity": false,
		"gzip;q=bogus": false, "br": false, "gzip;level=1": true,
	} {
		var values []string
		if header != "" {
			values = []string{header}
		}
		if got := acceptsGzip(values); got != want {
			t.Errorf("%q: %v", header, got)
		}
	}
	if !acceptsGzip([]string{"br", "gzip"}) {
		t.Error("gzip in a second header")
	}
}

func mapKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}

func sameElements(a, b []string) bool {
	return reflect.DeepEqual(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}
