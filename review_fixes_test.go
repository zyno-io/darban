package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMountMapsUpstreamPathsToThePrefix(t *testing.T) {
	bindings := contractOnlyBindings()
	bindings.Services["catalog"] = serviceBinding{Prefix: "/catalog"}
	const upstream = "http://catalog." + testNamespace + ".svc.cluster.local/api"
	reg := clusterContract("catalog", "/api/items", "listItems", upstream, "")
	reg.openAPI += "  /api/private:\n    post:\n      x-darban-visibility: internal\n"
	got, report := compile([]registration{reg}, bindings, nil)
	if report.services["catalog"].rejection != "" {
		t.Fatalf("catalog outcome = %+v", report.services["catalog"])
	}
	wantPaths(t, got, "/catalog/items")
	if len(got.denied) != 1 || got.denied[0] != (operationKey{"POST", "/catalog/private"}) {
		t.Fatalf("denied = %v", got.denied)
	}
	if binding := got.services["catalog"]; binding.Mount != "/api" || binding.Origin != "http://catalog."+testNamespace+".svc.cluster.local:80" {
		t.Fatalf("binding = %+v", binding)
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
	// t has no bindings entry, so its contract chooses its prefix.
	bindings.Services["x"] = serviceBinding{Prefix: "/x", Origin: "http://x.zyno-alpha.svc.cluster.local:80"}
	other := clusterContract("u", "/things", "listU", "http://u", "/u")
	regs := []registration{clusterContract("t", "/items", "listT", "http://t", ""), rewriteOwner("aliasX"), other}
	_, r1 := compile(regs, bindings, nil)
	if len(r1.accepted) != 3 {
		t.Fatalf("setup: %+v", r1.services)
	}
	// t moves onto u's prefix and loses the collision.
	moved := clusterContract("t", "/items", "listT", "http://t", "/u")
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

// assertAliasDenied checks that x is served with its alias denied and warned,
// and that t is served.
func assertAliasDenied(t *testing.T, label string, got candidate, report compileReport, wantT string) {
	t.Helper()
	if report.services["x"].serving != servingCurrent || report.services["x"].rejection != "" || len(report.services["x"].warnings) == 0 {
		t.Errorf("%s: x = %+v", label, report.services["x"])
	}
	if report.services["t"].serving != servingCurrent || report.services["t"].rejection != "" {
		t.Errorf("%s: t = %+v", label, report.services["t"])
	}
	wantPaths(t, got, wantT)
}

func TestRewriteThatCannotMapNeverBlamesTargetOrOwner(t *testing.T) {
	// Trace A: t's bindings mount is /api, but x rewrites to /items (outside it).
	bindings := isolationBindings("x")
	bindings.Services["t"] = serviceBinding{Prefix: "/t", Origin: "http://t.zyno-alpha.svc.cluster.local:80", Mount: "/api"}
	owner := rewriteOwner("aliasX")
	target := contractFor("t", "/api/items", "listT")
	for name, order := range map[string][]registration{
		"owner first":  {owner, target},
		"target first": {target, owner},
	} {
		got, report := compile(order, bindings, nil)
		assertAliasDenied(t, "fresh "+name, got, report, "/t/items")
		// Established pod: owner served alone, then the target arrives.
		_, first := compile([]registration{owner}, bindings, nil)
		if first.services["x"].serving != servingCurrent {
			t.Fatalf("setup: %+v", first.services)
		}
		got2, report := compile(order, bindings, first.accepted)
		assertAliasDenied(t, "established "+name, got2, report, "/t/items")
		if got2.revision != got.revision {
			t.Errorf("%s: fresh and established revisions differ", name)
		}
	}
	// Trace B: t's update adds a mount through spec.upstream, so the rewrite no
	// longer maps. t is served with the update, x is warned, nobody is rejected.
	bindings = isolationBindings("t", "x")
	plain := contractFor("t", "/items", "listT")
	_, r1 := compile([]registration{plain, owner}, bindings, nil)
	if len(r1.accepted) != 2 || len(r1.services["x"].warnings) != 0 {
		t.Fatalf("setup: %+v", r1.services)
	}
	moved := clusterContract("t", "/api/items", "listT", "http://t."+testNamespace+".svc.cluster.local/api", "/t")
	got, established := compile([]registration{moved, owner}, bindings, r1.accepted)
	assertAliasDenied(t, "trace B established", got, established, "/t/items")
	got, fresh := compile([]registration{moved, owner}, bindings, nil)
	assertAliasDenied(t, "trace B fresh", got, fresh, "/t/items")
}

func TestRewriteApprovalDoesNotDependOnHowTargetFails(t *testing.T) {
	bindings := isolationBindings("t", "x")
	badUpstream := contractFor("t", "/items", "listT")
	badUpstream.namespace, badUpstream.upstream = testNamespace, "ftp://t"
	for name, target := range map[string]registration{
		"bad upstream":   badUpstream,
		"bad visibility": contractFor("t", "/items", "listT", badVisibility),
	} {
		got, report := compile([]registration{target, rewriteOwner("aliasX")}, bindings, nil)
		if report.services["x"].serving != servingCurrent || report.services["x"].rejection != "" {
			t.Errorf("%s: x = %+v", name, report.services["x"])
		}
		if report.services["t"].serving != servingNone {
			t.Errorf("%s: t = %+v", name, report.services["t"])
		}
		wantPaths(t, got)
		for _, key := range got.denied {
			if key == (operationKey{"GET", "/x/alias"}) {
				goto denied
			}
		}
		t.Errorf("%s: alias not denied: %v", name, got.denied)
	denied:
	}
}

func TestBindingsEntryWithoutPrefixReservesItsDefaultPrefix(t *testing.T) {
	for _, publish := range []bool{true, false} {
		bindings := contractOnlyBindings()
		bindings.Services["foo"] = serviceBinding{Origin: "http://foo.zyno-alpha.svc.cluster.local:80", Publish: &publish}
		evil := clusterContract("evil", "/items", "listEvil", "http://evil", "/foo")
		foo := contractFor("foo", "/items", "listFoo")
		for name, regs := range map[string][]registration{
			"evil only":  {evil},
			"evil first": {evil, foo},
			"foo first":  {foo, evil},
		} {
			_, report := compile(regs, bindings, nil)
			if outcome := report.services["evil"]; outcome.serving != servingNone || !strings.Contains(outcome.rejection, "reserved") {
				t.Errorf("publish=%v %s: evil = %+v", publish, name, outcome)
			}
			if _, has := report.services["foo"]; has && report.services["foo"].rejection != "" {
				t.Errorf("publish=%v %s: foo = %+v", publish, name, report.services["foo"])
			}
		}
	}
}

func hangingTLSListener(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			conn.Close()
		}
	})
	return "https://" + listener.Addr().String()
}

func TestTLSHandshakeTimeoutFreesConnectionSlots(t *testing.T) {
	ca := newTestCA(t, "upstream-ca")
	healthy := tlsUpstream(t, ca)
	hung := hangingTLSListener(t)
	verifier, err := newUpstreamVerifier(upstreamTLSConfig{CAFile: writeCA(t, ca.pem)})
	if err != nil {
		t.Fatal(err)
	}
	transport := newTransport(verifier.tlsConfig())
	transport.TLSHandshakeTimeout = 200 * time.Millisecond
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	for wave := 0; wave < 2; wave++ {
		start := time.Now()
		var wg sync.WaitGroup
		for i := 0; i < 80; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if resp, err := client.Get(hung); err == nil {
					resp.Body.Close()
					t.Error("hung upstream answered")
				}
			}()
		}
		wg.Wait()
		// 80 attempts exceed MaxConnsPerHost (64), so slots must be released.
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Fatalf("wave %d took %v", wave, elapsed)
		}
	}
	resp, err := client.Get(healthy.URL)
	if err != nil {
		t.Fatalf("healthy upstream: %v", err)
	}
	resp.Body.Close()
}
