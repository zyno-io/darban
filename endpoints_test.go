package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/ptr"
)

func TestDebugServiceSelection(t *testing.T) {
	const (
		debugHost   = "observatory-debug.fixtures.svc.cluster.local:3000"
		debugOrigin = "http://" + debugHost
	)
	var primaryCalls, debugCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryCalls.Add(1)
		io.WriteString(w, "primary")
	}))
	defer primary.Close()
	debug := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		debugCalls.Add(1)
		if r.Host != debugHost || r.URL.Path != "/observatory/objects" {
			t.Errorf("unexpected debug request: %s%s", r.Host, r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != "request body" {
			t.Error("debug backend received the wrong request body")
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, "debug application response")
	}))
	defer debug.Close()
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Auth-Subject", "tenant")
		w.Header().Set("X-Auth-Account", "account")
		if r.Header.Get("Authorization") == "Bearer admin" {
			w.Header().Set("X-Auth-Debug-Allowed", "true")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer auth.Close()

	bindings := upstreamBindings{
		Authz: auth.URL, Hostname: "api.example.net", Authorization: fixtureAuthorization(),
		Debug:    debugConfig{RequestHeader: "X-Debug-Backend", RequiredHeader: "X-Auth-Debug-Allowed", RequiredValue: "true"},
		Services: map[string]serviceBinding{"observatory": {Origin: primary.URL, DebugOrigin: debugOrigin}},
	}
	g := newGateway(bindings)
	g.transports.base.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		var dialer net.Dialer
		if address == debugHost {
			address = debug.Listener.Addr().String()
		}
		return dialer.DialContext(ctx, network, address)
	}
	const path = "/observatory/objects"
	active := g.build(candidate{services: bindings.Services, routes: []compiledOperation{{
		key: operationKey{"POST", path}, service: "observatory", path: "/observatory/objects", protected: true,
	}}})
	send := func(account, wantBody string, wantStatus int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("request body"))
		req.Host = bindings.Hostname
		req.Header.Set("Authorization", "Bearer "+account)
		req.Header.Set("X-Debug-Backend", "true")
		req.Header.Set("X-Auth-Debug-Allowed", "true")
		response := httptest.NewRecorder()
		g.serve(active, response, req)
		if response.Code != wantStatus || response.Body.String() != wantBody {
			t.Fatalf("request returned %d %q, expected %d %q", response.Code, response.Body.String(), wantStatus, wantBody)
		}
	}
	send("admin", "primary", http.StatusOK)

	stream := watch.NewRaceFreeFake()
	t.Cleanup(stream.Stop)
	informer := newEndpointInformer(&cache.ListWatch{
		ListWithContextFunc: func(context.Context, metav1.ListOptions) (runtime.Object, error) {
			return &discoveryv1.EndpointSliceList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}}, nil
		},
		WatchFuncWithContext: func(_ context.Context, options metav1.ListOptions) (watch.Interface, error) {
			if options.SendInitialEvents != nil && *options.SendInitialEvents {
				stream.Action(watch.Bookmark, &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{
					ResourceVersion: "1", Annotations: map[string]string{"k8s.io/initial-events-end": "true"},
				}})
			}
			return stream, nil
		},
	})
	g.endpoints = endpointCatalog{"fixtures": informer}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	g.endpoints.run(ctx)
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		t.Fatal("EndpointSlice cache did not sync")
	}
	waitFor := func(predicate func() bool, message string) {
		t.Helper()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for !predicate() {
			select {
			case <-ctx.Done():
				t.Fatal(message)
			case <-ticker.C:
			}
		}
	}

	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: "observatory-debug-1", Namespace: "fixtures", Labels: map[string]string{discoveryv1.LabelServiceName: "observatory-debug"},
		},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"192.0.2.10"}, Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(false)}},
			{Addresses: []string{"192.0.2.11"}, Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true), Terminating: ptr.To(true)}},
		},
	}
	stream.Add(slice)
	waitFor(func() bool {
		_, exists, _ := informer.GetStore().GetByKey("fixtures/observatory-debug-1")
		return exists
	}, "unready EndpointSlice update was not observed")
	send("admin", "primary", http.StatusOK)

	ready := slice.DeepCopy()
	ready.Name = "observatory-debug-2"
	ready.Endpoints = []discoveryv1.Endpoint{{Addresses: []string{"192.0.2.12"}}}
	stream.Add(ready)
	waitFor(func() bool { return g.endpoints.state(debugOrigin) == endpointReady }, "ready endpoint was not observed")
	send("regular", "primary", http.StatusOK)
	send("admin", "debug application response", http.StatusServiceUnavailable)
	debug.Close()
	send("admin", "", http.StatusBadGateway)
	if primaryCalls.Load() != 3 || debugCalls.Load() != 1 {
		t.Fatal("a debug attempt was forwarded to the regular Service")
	}
	stream.Delete(ready)
	waitFor(func() bool { return g.endpoints.state(debugOrigin) == endpointEmpty }, "removed endpoint was still visible")
	send("admin", "primary", http.StatusOK)
}
