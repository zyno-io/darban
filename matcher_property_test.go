package main

import (
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"testing"
)

type propertyOperation struct {
	path string
	// kind is selected (routed through the contract), unselected (left to the
	// direct route) or internal.
	kind string
}

// tsfSelect emulates TSF routing: a literal segment beats a :param, an
// in-segment {x} is the literal :x, the first segment where two candidates
// differ decides, and the method must match exactly.
func tsfSelect(operations []propertyOperation, path string) (propertyOperation, bool) {
	request := strings.Split(strings.TrimPrefix(path, "/"), "/")
	var best []string
	var chosen propertyOperation
	found := false
	for _, operation := range operations {
		segments := strings.Split(strings.TrimPrefix(operation.path, "/"), "/")
		if len(segments) != len(request) {
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

// TestProxiedRequestsNeverReachInternalOperations checks, over generated
// route sets, that a request Darban proxies is one TSF would not give to an
// internal operation. Darban may refuse more than TSF (fail closed), never
// less.
func TestProxiedRequestsNeverReachInternalOperations(t *testing.T) {
	segments := []string{"v1", "items", "{a}", "items{batch}", "x{y}"}
	requests := []string{"v1", "items", "itemsZ", "items:batch", "x:y", "xQ", "zz"}
	random := rand.New(rand.NewSource(1))
	checked := 0
	for round := 0; round < 400; round++ {
		var operations []propertyOperation
		seen := map[string]bool{}
		for range 2 + random.Intn(4) {
			depth := 1 + random.Intn(3)
			parts := make([]string, depth)
			for i := range parts {
				parts[i] = segments[random.Intn(len(segments))]
				if parts[i] == "{a}" {
					parts[i] = fmt.Sprintf("{a%d}", i)
				}
			}
			path := "/" + strings.Join(parts, "/")
			if seen[path] {
				continue
			}
			seen[path] = true
			kind := []string{"selected", "unselected", "internal"}[random.Intn(3)]
			if kind == "selected" && !templatePath(path) {
				kind = "unselected"
			}
			operations = append(operations, propertyOperation{path, kind})
		}
		openAPI := "openapi: 3.1.0\npaths:\n" + anonymousOperation("get", "/sel", "sel")
		selection := []operationSelection{{Method: "get", Path: "/sel"}}
		for i, operation := range operations {
			if operation.kind == "internal" {
				openAPI += "  " + operation.path + ":\n    get:\n      x-darban-visibility: internal\n"
				continue
			}
			openAPI += anonymousOperation("get", operation.path, fmt.Sprintf("op%d", i))
			if operation.kind == "selected" {
				selection = append(selection, operationSelection{Method: "get", Path: operation.path})
			}
		}
		bindings := shopBindings()
		bindings.Services["shop"] = serviceBinding{Prefix: "/shop", Origin: "http://shop.fixtures.svc.cluster.local:80", Operations: selection}
		bindings.ServiceRoutes = map[string]serviceRoute{"/shop": {Origin: "http://shop.fixtures.svc.cluster.local:80", BackendAuth: true}}
		reg := registration{serviceName: "shop", rewrites: "[]", openAPI: openAPI}
		if _, report := compile([]registration{reg}, bindings, nil); report.services["shop"].rejection != "" {
			continue // for example, two operations of one shape
		}
		h := newTemplateHarness(t, bindings, strings.TrimPrefix(openAPI, "openapi: 3.1.0\npaths:\n"))
		for range 12 {
			parts := make([]string, 1+random.Intn(3))
			for i := range parts {
				parts[i] = requests[random.Intn(len(requests))]
			}
			path := "/" + strings.Join(parts, "/")
			code, _ := h.do("GET", "/shop"+path)
			checked++
			if code != 418 {
				continue
			}
			if chosen, found := tsfSelect(operations, path); found && chosen.kind == "internal" {
				t.Errorf("GET /shop%s was proxied, but TSF runs internal %s; operations %v", path, chosen.path, operations)
			}
		}
	}
	if checked < 1000 {
		t.Fatalf("only %d requests checked", checked)
	}
}
