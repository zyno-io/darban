package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

type propertyOperation struct {
	method, path string
	// kind is selected (routed through the contract), unselected (left to the
	// direct route) or internal.
	kind string
}

// tsfSelect emulates TSF routing: the method must match exactly, a literal
// segment beats a :param, an in-segment {x} is the literal :x, and the first
// segment where two candidates differ decides.
func tsfSelect(operations []propertyOperation, method, path string) (propertyOperation, bool) {
	request := strings.Split(strings.TrimPrefix(path, "/"), "/")
	var best []string
	var chosen propertyOperation
	found := false
	for _, operation := range operations {
		segments := strings.Split(strings.TrimPrefix(operation.path, "/"), "/")
		if operation.method != method || len(segments) != len(request) {
			continue
		}
		ranks := make([]string, len(segments))
		matched := true
		for i, segment := range segments {
			if parameterSegment(segment) {
				ranks[i] = "1"
				matched = matched && request[i] != ""
				continue
			}
			literal := templateSegment.ReplaceAllStringFunc(segment, func(name string) string { return ":" + strings.Trim(name, "{}") })
			ranks[i] = "0"
			matched = matched && literal == request[i]
		}
		if matched && (!found || slices.Compare(ranks, best) < 0) {
			best, chosen, found = ranks, operation, true
		}
	}
	return chosen, found
}

// propertyRig serves the shop service on a direct route whose own policy
// leaves every path to the backend, while its selected operations need the
// gateway's authorization. An authorizer call shows which policy served a
// request.
type propertyRig struct {
	h          *skipHarness
	sent       string
	authorized bool
}

func newPropertyRig(t *testing.T, selection []operationSelection, publicPaths []string, openAPI string) *propertyRig {
	r := &propertyRig{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		r.sent = q.Method + " " + q.URL.Path
		w.WriteHeader(http.StatusTeapot)
	}))
	authz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		r.authorized = true
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	t.Cleanup(authz.Close)
	bindings := upstreamBindings{Hostname: "api.example.net", Authz: authz.URL,
		Services:      map[string]serviceBinding{"shop": {Prefix: "/shop", Operations: selection}},
		ServiceRoutes: map[string]serviceRoute{"/shop": {Origin: upstream.URL, PublicPaths: publicPaths}}}
	r.h = newSkipHarness(t, bindings)
	r.h.apply(registration{serviceName: "shop", rewrites: "[]", openAPI: openAPI})
	return r
}

func (r *propertyRig) do(method, path string) (int, bool, string) {
	r.sent, r.authorized = "", false
	req := httptest.NewRequest(method, path, nil)
	req.Host = "api.example.net"
	req.Header.Set("Authorization", "Bearer caller")
	res := httptest.NewRecorder()
	r.h.g.serve(r.h.active.Load(), res, req)
	return res.Code, r.authorized, r.sent
}

// TestProxiedRequestsReachTheOperationTSFRuns generates route sets that mix
// selected, unselected and internal operations, with literal, parameter and
// overlapping in-segment segments at several depths and two methods. For each
// request Darban proxies, it checks that a TSF-style router runs an operation
// on the same authorization path: a selected one when the gateway authorized
// it, and neither an internal nor a selected one when the route's own policy
// served it. Darban may refuse more than TSF (fail closed), never less.
func TestProxiedRequestsReachTheOperationTSFRuns(t *testing.T) {
	segments := []string{"v1", "items", "{a}", "items{batch}", "x{y}", "item{s}", "{b}"}
	requests := []string{"v1", "items", "itemsZ", "items:batch", "x:y", "xQ", "zz", "item:s", "itemZ"}
	methods := []string{http.MethodGet, http.MethodPost}
	random := rand.New(rand.NewSource(42))
	// The route's own policy leaves every path to the backend.
	var publicPaths []string
	for _, first := range requests {
		publicPaths = append(publicPaths, "/"+first, "/"+first+"/*")
	}
	counts := map[string]int{}
	for round := 0; round < 3000; round++ {
		var operations []propertyOperation
		seen := map[string]bool{}
		for range 2 + random.Intn(5) {
			parts := make([]string, 1+random.Intn(3))
			for i := range parts {
				parts[i] = segments[random.Intn(len(segments))]
				if parameterSegment(parts[i]) {
					parts[i] = fmt.Sprintf("{%s%d}", strings.Trim(parts[i], "{}"), i)
				}
			}
			operation := propertyOperation{methods[random.Intn(len(methods))], "/" + strings.Join(parts, "/"),
				[]string{"selected", "unselected", "internal"}[random.Intn(3)]}
			if seen[operation.method+operation.path] {
				continue
			}
			seen[operation.method+operation.path] = true
			if operation.kind == "selected" && !templatePath(operation.path) {
				operation.kind = "unselected"
			}
			operations = append(operations, operation)
		}
		byPath := map[string]string{}
		var order []string
		selection := []operationSelection{{Method: "get", Path: "/sel"}}
		for i, operation := range operations {
			method := strings.ToLower(operation.method)
			if _, ok := byPath[operation.path]; !ok {
				order = append(order, operation.path)
			}
			if operation.kind == "internal" {
				byPath[operation.path] += "    " + method + ":\n      x-darban-visibility: internal\n"
				continue
			}
			byPath[operation.path] += fmt.Sprintf("    %s:\n      operationId: op%d\n      security: [{account: []}]\n      responses: {'200': {description: OK}}\n", method, i)
			if operation.kind == "selected" {
				selection = append(selection, operationSelection{Method: method, Path: operation.path})
			}
		}
		openAPI := "openapi: 3.1.0\npaths:\n" + anonymousOperation("get", "/sel", "sel")
		for _, path := range order {
			openAPI += "  " + path + ":\n" + byPath[path]
		}
		openAPI += "components:\n  securitySchemes:\n    account: {type: http, scheme: bearer}\n"
		probe := upstreamBindings{Hostname: "api.example.net",
			Services:      map[string]serviceBinding{"shop": {Prefix: "/shop", Operations: selection}},
			ServiceRoutes: map[string]serviceRoute{"/shop": {Origin: "http://shop.fixtures.svc.cluster.local:80"}}}
		if _, report := compile([]registration{{serviceName: "shop", rewrites: "[]", openAPI: openAPI}}, probe, nil); report.services["shop"].rejection != "" {
			counts["rejected"]++ // for example, two operations of one shape
			continue
		}
		r := newPropertyRig(t, selection, publicPaths, openAPI)
		for range 15 {
			parts := make([]string, 1+random.Intn(3))
			for i := range parts {
				parts[i] = requests[random.Intn(len(requests))]
			}
			path, method := "/"+strings.Join(parts, "/"), methods[random.Intn(len(methods))]
			code, authorized, sent := r.do(method, "/shop"+path)
			chosen, found := tsfSelect(operations, method, path)
			counts["checked"]++
			switch {
			case code != http.StatusTeapot:
				counts["refused"]++
			case !authorized:
				counts["direct"]++
				if found && chosen.kind != "unselected" {
					t.Errorf("%s /shop%s took the route's own policy, but TSF runs %s %s %s; operations %v", method, path, chosen.kind, chosen.method, chosen.path, operations)
				}
			default:
				counts["contract"]++
				if !found || chosen.kind != "selected" || sent != method+" "+path {
					t.Errorf("%s /shop%s took the contract's policy as %q, but TSF runs %v %v; operations %v", method, path, sent, chosen, found, operations)
				}
			}
		}
	}
	if counts["checked"] < 10000 || counts["contract"] == 0 || counts["direct"] == 0 {
		t.Fatalf("too little coverage: %v", counts)
	}
	t.Logf("counts %v", counts)
}
