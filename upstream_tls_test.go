package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, name string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return testCA{cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca testCA) serverCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "upstream"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func tlsUpstream(t *testing.T, ca testCA) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{ca.serverCert(t)}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func writeCA(t *testing.T, contents []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func fetch(t *testing.T, config upstreamTLSConfig, target string) error {
	t.Helper()
	verifier, err := newUpstreamVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	return fetchWith(verifier, target)
}

func fetchWith(verifier *upstreamVerifier, target string) error {
	transport := newTransport(verifier.tlsConfig())
	defer transport.CloseIdleConnections()
	resp, err := (&http.Client{Transport: transport}).Get(target)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if body, _ := io.ReadAll(resp.Body); string(body) != "ok" {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func TestUpstreamOriginSchemes(t *testing.T) {
	for _, origin := range []string{
		"http://svc.ns.svc.cluster.local:8080",
		"https://svc.ns.svc.cluster.local:8443",
	} {
		if _, err := upstreamOrigin(origin, false); err != nil {
			t.Errorf("%s: %v", origin, err)
		}
	}
	if _, err := upstreamOrigin("https://127.0.0.1:8443", true); err != nil {
		t.Errorf("local https: %v", err)
	}
	for _, origin := range []string{
		"ftp://svc.ns.svc.cluster.local:8080",
		"https://svc.ns.svc.cluster.local",
		"https://svc.ns.svc.cluster.local:8443/path",
		"https://svc.ns.svc.cluster.local:8443?q=1",
		"https://user@svc.ns.svc.cluster.local:8443",
		"https://svc.ns.svc.cluster.local:8443#frag",
		"https://example.com:8443",
		"https://127.0.0.1:8443",
	} {
		if _, err := upstreamOrigin(origin, false); err == nil {
			t.Errorf("%s accepted", origin)
		}
	}
	if _, err := upstreamOrigin("https://example.com:8443", true); err == nil {
		t.Error("non-loopback accepted in local mode")
	}
}

func TestDefaultPort(t *testing.T) {
	for raw, want := range map[string]string{
		"http://a.b.svc.cluster.local": "80", "https://a.b.svc.cluster.local": "443", "https://a.b.svc.cluster.local:9": "9",
	} {
		target, _ := url.Parse(raw)
		if got := effectivePort(target); got != want {
			t.Errorf("%s = %s, want %s", raw, got, want)
		}
	}
}

func TestUpstreamTLSRoundTrips(t *testing.T) {
	ca := newTestCA(t, "upstream-ca")
	server := tlsUpstream(t, ca)
	caFile := writeCA(t, ca.pem)

	if err := fetch(t, upstreamTLSConfig{CAFile: caFile}, server.URL); err != nil {
		t.Fatalf("with CA: %v", err)
	}
	if err := fetch(t, upstreamTLSConfig{}, server.URL); err == nil {
		t.Fatal("system roots verified a private CA")
	}
	if err := fetch(t, upstreamTLSConfig{InsecureSkipVerify: true}, server.URL); err != nil {
		t.Fatalf("insecure: %v", err)
	}
	// The certificate covers 127.0.0.1 only.
	mismatch := strings.Replace(server.URL, "127.0.0.1", "localhost", 1)
	if err := fetch(t, upstreamTLSConfig{CAFile: caFile}, mismatch); err == nil {
		t.Fatal("hostname mismatch verified")
	}
	other := newTestCA(t, "other-ca")
	if err := fetch(t, upstreamTLSConfig{CAFile: writeCA(t, other.pem)}, server.URL); err == nil {
		t.Fatal("wrong CA verified")
	}
}

func TestUpstreamTLSGatewayTransports(t *testing.T) {
	ca := newTestCA(t, "upstream-ca")
	server := tlsUpstream(t, ca)
	g := newGateway(upstreamBindings{UpstreamTLS: upstreamTLSConfig{CAFile: writeCA(t, ca.pem)}})
	for name, rt := range map[string]http.RoundTripper{
		"regular": g.transports.get(regularResponseHeaderTimeout, false), "long": g.transports.get(time.Hour, false),
		"debug": g.transports.get(regularResponseHeaderTimeout, true), "authz": g.authClient.Transport,
	} {
		resp, err := (&http.Client{Transport: rt}).Get(server.URL)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		resp.Body.Close()
	}
}

func TestUpstreamCAReload(t *testing.T) {
	first, second := newTestCA(t, "first"), newTestCA(t, "second")
	server := tlsUpstream(t, second)
	caFile := writeCA(t, first.pem)
	verifier, err := newUpstreamVerifier(upstreamTLSConfig{CAFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	if err := fetchWith(verifier, server.URL); err == nil {
		t.Fatal("first CA verified the second CA's server")
	}
	if err := os.WriteFile(caFile, second.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	verifier.refresh()
	if err := fetchWith(verifier, server.URL); err != nil {
		t.Fatalf("after reload: %v", err)
	}
	// A bad file keeps the last good pool.
	if err := os.WriteFile(caFile, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	verifier.refresh()
	verifier.refresh()
	if verifier.lastErr == "" {
		t.Fatal("reload error not recorded")
	}
	if err := fetchWith(verifier, server.URL); err != nil {
		t.Fatalf("after bad reload: %v", err)
	}
}

func TestUpstreamTLSValidation(t *testing.T) {
	ca := newTestCA(t, "ca")
	caFile := writeCA(t, ca.pem)
	bindings := func(tlsConfig map[string]any) string {
		raw, _ := json.Marshal(map[string]any{
			"hostname": "api.example.net",
			"services": map[string]any{"catalog": map[string]any{
				"origin": "https://127.0.0.1:8443", "prefix": "/catalog",
			}},
			"upstreamTLS": tlsConfig,
		})
		path := filepath.Join(t.TempDir(), "bindings.json")
		os.WriteFile(path, raw, 0o600)
		return path
	}
	if _, err := loadBindings(bindings(map[string]any{"caFile": caFile, "insecureSkipVerify": true}), true); err == nil {
		t.Error("both options accepted")
	}
	if _, err := loadBindings(bindings(map[string]any{"caFile": filepath.Join(t.TempDir(), "missing")}), true); err == nil {
		t.Error("missing CA file accepted")
	}
	if _, err := loadBindings(bindings(map[string]any{"caFile": writeCA(t, []byte("junk"))}), true); err == nil {
		t.Error("unparseable CA file accepted")
	}
	if _, err := loadBindings(bindings(map[string]any{"caFile": caFile}), true); err != nil {
		t.Errorf("caFile: %v", err)
	}
	if _, err := loadBindings(bindings(map[string]any{"insecureSkipVerify": true}), true); err != nil {
		t.Errorf("insecureSkipVerify: %v", err)
	}
}
