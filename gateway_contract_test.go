package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
)

func plainGatewayContract(service, yaml string) *unstructured.Unstructured {
	digest := sha256.Sum256([]byte(yaml))
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "darban.zyno.io/v1alpha1",
		"kind":       "GatewayContract",
		"metadata":   map[string]any{"name": contractNamePrefix + service, "namespace": "fixtures"},
		"spec": map[string]any{
			"serviceName": service,
			"openapi":     map[string]any{"yaml": yaml, "sha256": hex.EncodeToString(digest[:])},
			"rewrites":    []any{},
		},
	}}
}

func TestGatewayContractMigrationAndLargeInlineOpenAPI(t *testing.T) {
	var packed bytes.Buffer
	compressor := gzip.NewWriter(&packed)
	raw := strings.Repeat("# OpenAPI description\n", 60_000) + "openapi: 3.1.0\n"
	if len(raw) <= 1<<20 {
		t.Fatal("fixture must exceed the 1 MiB object size limit")
	}
	if _, err := compressor.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	if err := compressor.Close(); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(raw))
	observatory := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "darban.zyno.io/v1alpha1",
		"kind":       "GatewayContract",
		"metadata":   map[string]any{"name": "api-contract-observatory", "namespace": "fixtures"},
		"spec": map[string]any{
			"serviceName":       "observatory",
			"defaultVisibility": "unlisted",
			"openapi": map[string]any{
				"gzipBase64": base64.StdEncoding.EncodeToString(packed.Bytes()),
				"sha256":     hex.EncodeToString(digest[:]),
			},
			"rewrites": []any{},
		},
	}}
	current := cache.NewStore(cache.MetaNamespaceKeyFunc)
	for _, object := range []*unstructured.Unstructured{plainGatewayContract("herbarium", "old"), observatory} {
		if err := current.Add(object); err != nil {
			t.Fatal(err)
		}
	}
	result, err := loadClusterRegistrations(current)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 2 {
		t.Fatalf("expected two distinct services, got %d", len(result))
	}
	for _, reg := range result {
		if reg.serviceName == "observatory" && (reg.openAPI != raw || reg.defaultVisibility == nil || *reg.defaultVisibility != visibilityUnlisted) ||
			reg.serviceName == "herbarium" && (reg.openAPI != "old" || reg.defaultVisibility != nil) {
			t.Fatalf("wrong OpenAPI source for %s", reg.serviceName)
		}
	}
	plain := observatory.DeepCopy()
	if err := unstructured.SetNestedMap(plain.Object, map[string]any{
		"yaml": raw, "sha256": hex.EncodeToString(digest[:]),
	}, "spec", "openapi"); err != nil {
		t.Fatal(err)
	}
	plainReg, err := decodeGatewayContract(plain)
	if err != nil || plainReg.openAPI != raw {
		t.Fatalf("plain OpenAPI did not round-trip: %v", err)
	}
	if err := current.Update(plain); err != nil {
		t.Fatal(err)
	}
	if _, err := loadClusterRegistrations(current); err != nil {
		t.Fatal(err)
	}
	corrupt := plain.DeepCopy()
	if err := unstructured.SetNestedField(corrupt.Object, strings.Repeat("0", 64), "spec", "openapi", "sha256"); err != nil {
		t.Fatal(err)
	}
	if err := current.Update(corrupt); err != nil {
		t.Fatal(err)
	}
	isolated, err := loadClusterRegistrations(current)
	if err != nil {
		t.Fatal(err)
	}
	for _, reg := range isolated {
		if reg.serviceName == "observatory" && (reg.invalid == nil || reg.openAPI != "") {
			t.Fatal("a corrupted CRD contract must reject its service and must not activate any other source")
		}
		if reg.serviceName == "herbarium" && reg.invalid != nil {
			t.Fatal("a corrupted CRD contract must not affect other services")
		}
	}
}

func TestGatewayContractRequiresExactlyOneInlineFormat(t *testing.T) {
	raw := "openapi: 3.1.0\n"
	empty := ""
	digest := sha256.Sum256([]byte(raw))
	for _, input := range []gatewayOpenAPI{
		{SHA256: hex.EncodeToString(digest[:])},
		{YAML: &raw, GzipBase64: &empty, SHA256: hex.EncodeToString(digest[:])},
		{YAML: &empty, SHA256: hex.EncodeToString(digest[:])},
	} {
		if _, err := decodeOpenAPI(input); err == nil {
			t.Fatal("accepted an invalid inline OpenAPI representation")
		}
	}
}
