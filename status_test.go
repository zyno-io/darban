package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestStatusReportsServiceStateWithoutGatingReadiness(t *testing.T) {
	g := newGateway(upstreamBindings{
		Authz: "http://authz.fixtures.svc.cluster.local:3000",
		Services: map[string]serviceBinding{
			"observatory": {Origin: "http://observatory.fixtures.svc.cluster.local:3000"},
		},
	})
	var active atomic.Pointer[snapshot]
	var draining atomic.Bool
	read := func(code int) statusResponse {
		t.Helper()
		response := httptest.NewRecorder()
		g.statusHandler(&active, &draining).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/status", nil))
		if response.Code != code || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("unexpected status response: %d %s", response.Code, response.Body.String())
		}
		var report statusResponse
		if err := json.Unmarshal(response.Body.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		return report
	}
	if report := read(http.StatusServiceUnavailable); report.Status != "starting" || report.Ready {
		t.Fatalf("unexpected startup status: %+v", report)
	}
	active.Store(&snapshot{revision: "test-revision"})
	report := read(http.StatusOK)
	if report.Status != "ready" || !report.Ready || report.ContractRevision != "test-revision" ||
		len(report.Upstreams) != 3 || report.Upstreams[0].State != endpointUnknown || report.Upstreams[2].State != endpointNotConfigured {
		t.Fatalf("unexpected status: %+v", report)
	}
	draining.Store(true)
	if report := read(http.StatusServiceUnavailable); report.Status != "draining" || report.Ready {
		t.Fatalf("unexpected draining status: %+v", report)
	}
}
