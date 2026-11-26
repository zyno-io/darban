package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeBindings(t *testing.T, body string) error {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bindings.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadBindings(path, true)
	return err
}

func TestBindingsRejectUnknownKeysAndTrailingData(t *testing.T) {
	const valid = `{"hostname": "api.example.net",
		"authz": "http://authz.fixtures.svc.cluster.local:3000",
		"authorization": {"path": "/authz", "responseHeaders": ["X-Id"]},
		"openapi": {"yamlPath": "/openapi.yaml"},
		"serviceRoutes": {"/x": {"origin": "http://x.fixtures.svc.cluster.local:80", "backendAuth": true}},
		"services": {"a": {"prefix": "/a", "operations": [{"method": "get", "path": "/a"}]}}}`
	if err := writeBindings(t, valid+"\n"); err != nil {
		t.Fatalf("valid bindings: %v", err)
	}
	for name, body := range map[string]string{
		"top level":      strings.Replace(valid, `"hostname"`, `"bogus": 1, "hostname"`, 1),
		"service":        strings.Replace(valid, `"prefix": "/a"`, `"prefix": "/a", "bogus": true`, 1),
		"operation":      strings.Replace(valid, `"path": "/a"}`, `"path": "/a", "bogus": 1}`, 1),
		"service route":  strings.Replace(valid, `"backendAuth": true`, `"backendAuth": true, "bogus": []`, 1),
		"authorization":  strings.Replace(valid, `"path": "/authz"`, `"path": "/authz", "bogus": ""`, 1),
		"openapi":        strings.Replace(valid, `"yamlPath"`, `"bogus": "", "yamlPath"`, 1),
		"trailing value": valid + ` {}`,
		"trailing junk":  valid + ` x`,
		"two documents":  valid + valid,
	} {
		if err := writeBindings(t, body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
