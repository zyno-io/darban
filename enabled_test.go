package main

import (
	"bytes"
	"net/http"
	"slices"
	"strings"
	"testing"
)

func TestDisabledServiceServesNothing(t *testing.T) {
	// shop is discovered; its entry only adds legacy hosts, extra routes and
	// enabled: false. front rewrites into it.
	r := newTransportRig(t, serviceBinding{Prefix: "/shop", LegacyHosts: []string{"shop.example.net"}, Enabled: new(false),
		ExtraRoutes: []extraRoute{{Method: "GET", Path: "/assets/*", Auth: extraAuthNone}}})
	for _, test := range []struct{ method, host, target string }{
		{"GET", "api.example.net", "/shop/items/7"},
		{"GET", "api.example.net", "/shop/slow"},
		{"GET", "api.example.net", "/shop/assets/a.css"},
		{"GET", "api.example.net", "/shop/undeclared"},
		{"POST", "api.example.net", "/shop/zrpc/run"},
		{"GET", "shop.example.net", "/items/7"},
		{"GET", "shop.example.net", "/assets/a.css"},
	} {
		if res, upstream := r.do(test.method, test.host, test.target, http.Header{"Authorization": {"Bearer x"}}); res.Code != http.StatusServiceUnavailable || upstream != nil {
			t.Errorf("%s %s%s = %d %v", test.method, test.host, test.target, res.Code, upstream)
		}
	}
	// The rewrite into it is denied and warned on its owner, which still serves.
	if res, upstream := r.do("GET", "api.example.net", "/front/slow", nil); res.Code != http.StatusNotFound || upstream != nil {
		t.Errorf("rewrite into a disabled service = %d", res.Code)
	}
	if res, _ := r.do("GET", "api.example.net", "/front/home", nil); res.Code != http.StatusTeapot {
		t.Errorf("front = %d", res.Code)
	}
	status := r.h.status()
	if shop := status["shop"]; shop.Enabled || shop.State != stateDisabled || shop.Rejected || shop.Routes != 0 || !strings.Contains(shop.Reason, "503") {
		t.Errorf("shop status %+v", shop)
	}
	if front := status["front"]; !front.Enabled || front.State != stateServing || len(front.Warnings) != 2 || !strings.Contains(front.Warnings[0], "disabled") {
		t.Errorf("front status %+v", front)
	}
	if strings.Contains(string(r.h.active.Load().specYAML), "/shop/") {
		t.Error("a disabled service is in the document")
	}
}

func TestDisabledDiscoveredServiceKeepsItsPrefixAndIsValidated(t *testing.T) {
	bindings := contractOnlyBindings()
	// The entry only says enabled: false, and the contract chooses /store.
	bindings.Services["shop"] = serviceBinding{Enabled: new(false)}
	shop := clusterContract("shop", "/items", "listShop", "http://shop", "/store")
	intruder := clusterContract("intruder", "/things", "listIntruder", "http://intruder", "/store")
	intruder.created = shop.created.Add(1)
	got, report := compile([]registration{shop, intruder}, bindings, nil)
	if outcome := report.services["shop"]; outcome.serving != servingCurrent || outcome.enabled || outcome.rejection != "" {
		t.Fatalf("shop %+v", outcome)
	}
	if outcome := report.services["intruder"]; outcome.serving != servingNone || !strings.Contains(outcome.rejection, "/store") {
		t.Fatalf("intruder %+v", outcome)
	}
	if len(got.routes) != 0 || !slices.Contains(got.unserved, "/store") || documentedPaths(t, got) != nil {
		t.Fatalf("routes %v unserved %v", got.routes, got.unserved)
	}
	// The contract is still validated: a bad one is rejected.
	shop.openAPI = anonymousContract("/items", "listShop", badVisibility)
	if _, report = compile([]registration{shop}, bindings, nil); report.services["shop"].rejection == "" {
		t.Fatal("a disabled service's bad contract was accepted")
	}
	// Turning it back on serves the same contract.
	bindings.Services["shop"] = serviceBinding{Enabled: new(true)}
	shop = clusterContract("shop", "/items", "listShop", "http://shop", "/store")
	got, _ = compile([]registration{shop}, bindings, nil)
	wantPaths(t, got, "/store/items")
	if slices.Contains(got.unserved, "/store") {
		t.Fatalf("unserved %v", got.unserved)
	}
}

func TestReportShowsDisabledServices(t *testing.T) {
	regs, bindings := reportFixture(t)
	shop := bindings.Services["shop"]
	shop.Enabled = new(false)
	bindings.Services["shop"] = shop
	var out bytes.Buffer
	if _, err := writeReport(&out, regs, bindings); err != nil {
		t.Fatal(err)
	}
	report := out.String()
	if !strings.Contains(report, "service shop publish=true state=disabled") {
		t.Errorf("service line:\n%s", report)
	}
	for _, line := range strings.Split(report, "\n") {
		if fields := strings.Fields(line); len(fields) > 2 && fields[2] == "shop" && !strings.HasSuffix(line, "-> 503 disabled") {
			t.Errorf("shop line %q", line)
		}
	}
	if !strings.Contains(report, "503-disabled=") {
		t.Errorf("summary:\n%s", report)
	}
}
