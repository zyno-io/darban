package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const reportContract = `openapi: 3.1.0
paths:
  /items/{id}:
    get:
      operationId: getItem%[1]s
      security: [{account: []}]
      responses: {'200': {description: OK}}
    delete:
      operationId: deleteItem%[1]s
      security: [{account: []}]
      responses: {'200': {description: OK}}
  /public/{id}:
    get:
      operationId: getPublic%[1]s
      security: []
      x-darban-policy: anonymous
      responses: {'200': {description: OK}}
  /zrpc/{method}:
    post:
      x-darban-visibility: internal
  /admin/stats:
    get:
      x-darban-visibility: internal
  /hidden:
    get:
      operationId: hidden%[1]s
      x-darban-visibility: unlisted
      security: [{account: []}]
      responses: {'200': {description: OK}}
components:
  securitySchemes:
    account: {type: http, scheme: bearer}
`

// reportFixture has an unpublished service with an extra route (talk), a
// service with an operations selection and an extra route (suite), a service
// with rewrites (shop), a rejected contract (bad), a bound service with no
// contract (hub), and an unpublished service with no contract that a rewrite
// targets (archive).
func reportFixture(t *testing.T) ([]registration, upstreamBindings) {
	t.Helper()
	authz := "http://authz.fixtures.svc.cluster.local:80"
	bindings := upstreamBindings{
		Hostname: "api.example.net", Authz: authz, Authorization: authorizationConfig{Path: "/authz"},
		OpenAPI: openAPIConfig{YAMLPath: "/openapi.yaml"},
		Services: map[string]serviceBinding{
			"talk": {Prefix: "/talk", Origin: "http://talk.fixtures.svc.cluster.local:80", Publish: new(false),
				ExtraRoutes: []extraRoute{{Method: "GET", Path: "/healthz", Auth: extraAuthNone}}},
			"suite": {Prefix: "/suite", Origin: "http://suite.fixtures.svc.cluster.local:80",
				Operations:  []operationSelection{{Method: "get", Path: "/items/{id}"}},
				ExtraRoutes: []extraRoute{{Method: "GET", Path: "/health", Auth: extraAuthNone}}},
			"shop":    {Prefix: "/shop", Origin: "http://shop.fixtures.svc.cluster.local:80"},
			"bad":     {Prefix: "/bad", Origin: "http://bad.fixtures.svc.cluster.local:80"},
			"hub":     {Prefix: "/hub", Origin: "http://hub.fixtures.svc.cluster.local:80"},
			"archive": {Prefix: "/archive", Publish: new(false)},
		},
	}
	regs := []registration{
		{serviceName: "talk", openAPI: fmt.Sprintf(reportContract, "Talk"), rewrites: "[]"},
		{serviceName: "suite", openAPI: fmt.Sprintf(reportContract, "Suite"), rewrites: "[]"},
		{serviceName: "shop", openAPI: fmt.Sprintf(reportContract, "Shop"),
			rewrites: `[{from: {method: GET, path: /shop/old}, to: {serviceName: shop, path: /hidden}},
				{from: {method: GET, path: /shop/archived}, to: {serviceName: archive, path: /items}}]`},
		{serviceName: "bad", openAPI: strings.Replace(fmt.Sprintf(reportContract, "Bad"), "x-darban-policy: anonymous", "x-darban-policy: bogus", 1), rewrites: "[]"},
	}
	return regs, bindings
}

func TestReportGolden(t *testing.T) {
	for _, name := range []string{"report.golden"} {
		regs, bindings := reportFixture(t)
		var out bytes.Buffer
		ok, err := writeReport(&out, regs, bindings)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Errorf("%s: a rejected contract must fail the report", name)
		}
		path := filepath.Join("testdata", name)
		if os.Getenv("UPDATE_GOLDEN") != "" {
			if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if out.String() != string(want) {
			t.Errorf("%s differs; run with UPDATE_GOLDEN=1 and review the diff\n%s", name, out.String())
		}
		// The same input gives the same report.
		var again bytes.Buffer
		if _, err := writeReport(&again, regs, bindings); err != nil || again.String() != out.String() {
			t.Errorf("%s: report is not stable", name)
		}
	}
	// Without the rejected and missing contracts the report still fails, on
	// the rewrite into a service without a contract, as -print-spec does.
	regs, bindings := reportFixture(t)
	delete(bindings.Services, "bad")
	delete(bindings.Services, "hub")
	var out bytes.Buffer
	if ok, err := writeReport(&out, regs[:3], bindings); err != nil || ok || !strings.Contains(out.String(), "problem: service shop: rewrite GET /shop/archived") {
		t.Errorf("rewrite problem: ok=%v err=%v\n%s", ok, err, out.String())
	}
	if _, err := compileStrict(regs[:3], bindings); err == nil {
		t.Error("-print-spec accepts what -report refuses")
	}
	delete(bindings.Services, "archive")
	regs[2].rewrites = `[{from: {method: GET, path: /shop/old}, to: {serviceName: shop, path: /hidden}}]`
	if ok, err := writeReport(new(bytes.Buffer), regs[:3], bindings); err != nil || !ok {
		t.Errorf("clean report: ok=%v err=%v", ok, err)
	}
}

func gzipContract(t *testing.T, service, upstream, yaml string) map[string]any {
	t.Helper()
	var packed bytes.Buffer
	writer := gzip.NewWriter(&packed)
	writer.Write([]byte(yaml))
	writer.Close()
	digest := sha256.Sum256([]byte(yaml))
	return map[string]any{
		"apiVersion": "darban.zyno.io/v1alpha1", "kind": "GatewayContract",
		"metadata": map[string]any{"name": contractNamePrefix + service, "namespace": testNamespace, "creationTimestamp": "2026-11-01T00:00:00Z"},
		"spec": map[string]any{"serviceName": service, "upstream": upstream,
			"openapi":  map[string]any{"gzipBase64": base64.StdEncoding.EncodeToString(packed.Bytes()), "sha256": hex.EncodeToString(digest[:])},
			"rewrites": []any{}},
	}
}

func TestLoadContractListDecodesLikeClusterMode(t *testing.T) {
	other := gzipContract(t, "other", "http://other:3000", anonymousContract("/items", "listOther"))
	other["metadata"].(map[string]any)["namespace"] = "elsewhere"
	twice := gzipContract(t, "zipped", "http://zipped:3000", anonymousContract("/items", "listZipped"))
	for name, items := range map[string][]any{
		"two namespaces": {gzipContract(t, "zipped", "http://zipped:3000", anonymousContract("/items", "listZipped")), other},
		"listed twice":   {twice, twice},
	} {
		path := filepath.Join(t.TempDir(), "contracts.json")
		raw, _ := json.Marshal(map[string]any{"items": items})
		os.WriteFile(path, raw, 0o600)
		if _, err := loadContractList(path); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	plain := plainGatewayContract("plain", anonymousContract("/items", "listPlain"))
	plain.SetNamespace(testNamespace)
	plain.Object["spec"].(map[string]any)["upstream"] = "http://plain:3000"
	broken := plainGatewayContract("broken", "openapi: 3.1.0\n")
	broken.SetNamespace(testNamespace)
	broken.Object["spec"].(map[string]any)["openapi"].(map[string]any)["sha256"] = "00"
	list := map[string]any{"apiVersion": "v1", "kind": "List", "items": []any{
		gzipContract(t, "zipped", "http://zipped:3000", anonymousContract("/items", "listZipped")),
		plain.Object, broken.Object,
	}}
	path := filepath.Join(t.TempDir(), "contracts.json")
	raw, _ := json.Marshal(list)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	regs, err := loadContractList(path)
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(regs, func(a, b registration) int { return strings.Compare(a.serviceName, b.serviceName) })
	if len(regs) != 3 || regs[0].serviceName != "broken" || regs[0].invalid == nil ||
		regs[2].serviceName != "zipped" || regs[2].upstream != "http://zipped:3000" || regs[2].namespace != testNamespace ||
		regs[2].created.IsZero() || !strings.Contains(regs[2].openAPI, "listZipped") {
		t.Fatalf("registrations %+v", regs)
	}
	compiled, report := compile(regs, contractOnlyBindings(), nil)
	wantPaths(t, compiled, "/plain/items", "/zipped/items")
	if report.services["broken"].rejection == "" {
		t.Fatal("a broken contract was not rejected on its own")
	}
	for name, body := range map[string]string{
		"not a list": `{"kind": "GatewayContract"}`,
		"other kind": `{"items": [{"kind": "ConfigMap", "metadata": {"name": "x"}}]}`,
		"not JSON":   `items: []`,
	} {
		os.WriteFile(path, []byte(body), 0o600)
		if _, err := loadContractList(path); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
