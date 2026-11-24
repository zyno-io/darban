package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMountOnDirectRouteServiceIsRejected(t *testing.T) {
	bindings := directRouteBindings("http://catalog.zyno-alpha.svc.cluster.local:80")
	bindings.Services["catalog"] = serviceBinding{Prefix: "/catalog", Origin: "http://catalog.zyno-alpha.svc.cluster.local:80"}
	const upstream = "http://catalog." + testNamespace + ".svc.cluster.local/api"
	reg := clusterContract("catalog", "/api/items", "listItems", upstream, "/catalog")
	reg.openAPI += "  /api/private:\n    post:\n      x-darban-visibility: internal\n"
	_, report := compile([]registration{reg}, bindings, nil)
	if outcome := report.services["catalog"]; outcome.serving != servingNone || !strings.Contains(outcome.rejection, "direct route") {
		t.Fatalf("catalog outcome = %+v", outcome)
	}
	// Without a mount the same contract is accepted and denies the operation.
	reg = clusterContract("catalog", "/items", "listItems", "http://catalog."+testNamespace+".svc.cluster.local", "/catalog")
	reg.openAPI += "  /private:\n    post:\n      x-darban-visibility: internal\n"
	got, report := compile([]registration{reg}, bindings, nil)
	if report.services["catalog"].rejection != "" {
		t.Fatalf("unmounted contract rejected: %+v", report.services["catalog"])
	}
	if len(got.denied) != 1 || got.denied[0] != (operationKey{"POST", "/catalog/private"}) {
		t.Fatalf("denied = %v", got.denied)
	}
	// A static mount on a direct route is a startup error.
	raw, _ := json.Marshal(map[string]any{
		"hostname":      "api.example.net",
		"services":      map[string]any{"catalog": map[string]any{"origin": "http://127.0.0.1:8443", "prefix": "/catalog", "mount": "/api"}},
		"serviceRoutes": map[string]any{"/catalog": map[string]any{"origin": "http://127.0.0.1:8443", "backendAuth": true}},
	})
	path := filepath.Join(t.TempDir(), "bindings.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBindings(path, true); err == nil || !strings.Contains(err.Error(), "mount") {
		t.Fatalf("loadBindings = %v, want a mount error", err)
	}
}

func rewriteOwner(operationID string) registration {
	reg := contractFor("x", "/x/alias", operationID)
	reg.openAPI = anonymousContract("/alias", operationID)
	reg.rewrites = `[{from: {method: GET, path: /x/alias}, to: {serviceName: t, path: /items}}]`
	return reg
}

func TestRewriteOwnerIsCheckedAgainstServedTargetBinding(t *testing.T) {
	bindings := isolationBindings("t", "x")
	// The target's update names a new prefix but is otherwise invalid, so it
	// keeps serving at /t.
	brokenMove := contractFor("t", "/items", "listT", badVisibility)
	brokenMove.prefix = "/t2"
	_, r1 := compile([]registration{contractFor("t", "/items", "listT"), rewriteOwner("aliasX")}, bindings, nil)
	if len(r1.accepted) != 2 {
		t.Fatalf("setup: %+v", r1.services)
	}
	for _, update := range []string{"aliasX", "aliasX2"} {
		got, r2 := compile([]registration{brokenMove, rewriteOwner(update)}, bindings, r1.accepted)
		if r2.services["x"].rejection != "" || r2.services["x"].serving != servingCurrent {
			t.Fatalf("x with %s: %+v", update, r2.services["x"])
		}
		if r2.services["t"].serving != servingLastGood || r2.services["t"].rejection == "" {
			t.Fatalf("t: %+v", r2.services["t"])
		}
		wantPaths(t, got, "/t/items", "/x/alias")
	}
	// A fresh pod answers the same for x: accepted, with the alias denied
	// because t has no serving contract.
	got, fresh := compile([]registration{brokenMove, rewriteOwner("aliasX")}, bindings, nil)
	if fresh.services["x"].serving != servingCurrent || fresh.services["x"].rejection != "" {
		t.Fatalf("fresh x: %+v", fresh.services["x"])
	}
	wantPaths(t, got)
}

func TestRewriteOwnerSurvivesTargetPrefixCollision(t *testing.T) {
	bindings := contractOnlyBindings()
	bindings.Services["t"] = serviceBinding{Prefix: "/t", Origin: "http://t.zyno-alpha.svc.cluster.local:80"}
	bindings.Services["x"] = serviceBinding{Prefix: "/x", Origin: "http://x.zyno-alpha.svc.cluster.local:80"}
	other := clusterContract("u", "/things", "listU", "http://u", "/u")
	regs := []registration{contractFor("t", "/items", "listT"), rewriteOwner("aliasX"), other}
	_, r1 := compile(regs, bindings, nil)
	if len(r1.accepted) != 3 {
		t.Fatalf("setup: %+v", r1.services)
	}
	// t moves onto u's prefix and loses the collision.
	moved := contractFor("t", "/items", "listT")
	moved.prefix = "/u"
	got, r2 := compile([]registration{moved, rewriteOwner("aliasX2"), other}, bindings, r1.accepted)
	if r2.services["t"].serving != servingLastGood || !strings.Contains(r2.services["t"].rejection, "already used") {
		t.Fatalf("t: %+v", r2.services["t"])
	}
	if r2.services["x"].serving != servingCurrent || r2.services["x"].rejection != "" {
		t.Fatalf("x: %+v", r2.services["x"])
	}
	wantPaths(t, got, "/t/items", "/u/things", "/x/alias")
}

func TestBindingsPrefixIsReservedForItsService(t *testing.T) {
	bindings := contractOnlyBindings()
	bindings.Services["billing"] = serviceBinding{Prefix: "/billing", Origin: "http://billing.zyno-alpha.svc.cluster.local:80"}
	evil := clusterContract("evil", "/items", "listEvil", "http://evil", "/billing")
	billing := contractFor("billing", "/items", "listBilling")
	// Before billing has a contract, then in both arrival orders.
	_, report := compile([]registration{evil}, bindings, nil)
	if outcome := report.services["evil"]; outcome.serving != servingNone || !strings.Contains(outcome.rejection, "reserved") {
		t.Fatalf("evil alone: %+v", outcome)
	}
	for name, regs := range map[string][]registration{
		"evil first":    {evil, billing},
		"billing first": {billing, evil},
	} {
		got, report := compile(regs, bindings, nil)
		if report.services["billing"].serving != servingCurrent || report.services["evil"].serving != servingNone {
			t.Errorf("%s: %+v", name, report.services)
		}
		wantPaths(t, got, "/billing/items")
	}
	// Billing is established; evil arriving later cannot take the prefix.
	_, first := compile([]registration{billing}, bindings, nil)
	_, report = compile([]registration{billing, evil}, bindings, first.accepted)
	if report.services["billing"].serving != servingCurrent || report.services["evil"].serving != servingNone {
		t.Errorf("established: %+v", report.services)
	}
}

func TestCAModeRejectsCertificateForAnotherNameOnIPTarget(t *testing.T) {
	ca := newTestCA(t, "upstream-ca")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "someone-else.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"someone-else.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	defer server.Close()
	if !strings.HasPrefix(server.URL, "https://127.0.0.1:") {
		t.Fatalf("unexpected URL %s", server.URL)
	}
	if err := fetch(t, upstreamTLSConfig{CAFile: writeCA(t, ca.pem)}, server.URL); err == nil {
		t.Fatal("certificate for another name verified on an IP target")
	}
	// The verifier itself refuses an unnamed connection.
	verifier, err := newUpstreamVerifier(upstreamTLSConfig{CAFile: writeCA(t, ca.pem)})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.tlsConfig().VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{ca.cert}}); err == nil {
		t.Fatal("empty server name verified")
	}
}
