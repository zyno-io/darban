package main

import (
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

var pathSegment = regexp.MustCompile(`^([A-Za-z0-9._~@-]+|\{[A-Za-z_][A-Za-z0-9_.-]*\})$`)

// templatePath reports whether path is a valid operation path: every segment
// is a literal (not . or ..) or a whole {name} parameter, and no parameter
// name repeats.
func templatePath(path string) bool {
	if !strings.HasPrefix(path, "/") || path == "/" {
		return false
	}
	var names []string
	for _, segment := range strings.Split(path[1:], "/") {
		if segment == "." || segment == ".." || !pathSegment.MatchString(segment) {
			return false
		}
		if parameterSegment(segment) {
			if slices.Contains(names, segment) {
				return false
			}
			names = append(names, segment)
		}
	}
	return true
}

// parameterSegment reports whether a template segment is a whole {name}.
func parameterSegment(segment string) bool {
	return strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") && strings.Count(segment, "{") == 1
}

// pathShape replaces every whole parameter of a template with {}, so two
// templates that match the same paths have the same shape.
func pathShape(template string) string {
	segments := strings.Split(template, "/")
	for i, segment := range segments {
		if parameterSegment(segment) {
			segments[i] = "{}"
		}
	}
	return strings.Join(segments, "/")
}

// routeTable matches a method and path against the public templates of the
// denied, routed and passed-through operations. Each segment tries a literal,
// then a pattern, then a parameter, and backtracks when the rest of the path
// does not match.
type routeTable map[string]*routeNode

type routeNode struct {
	literals map[string]*routeNode
	// patterns hold segments with a template inside them, such as
	// items{batch}. Only an internal or unselected operation can have one, so
	// it is never routed. Each template matches one or more characters.
	patterns []routePattern
	param    *routeNode
	entry    *routeEntry
}

type routePattern struct {
	source string
	match  *regexp.Regexp
	node   *routeNode
}

type routeEntryKind int

const (
	entryDenied routeEntryKind = iota
	entryRoute
	// entryPassthrough is an operation the service's bindings leave
	// unselected. It is not routed through the contract, but it keeps a
	// selected template from capturing its path.
	entryPassthrough
)

type routeEntry struct {
	key   operationKey
	kind  routeEntryKind
	route *registeredRoute
	// params names the parameter at each segment position, "" for others.
	params []string
}

func newRouteTable(routes map[operationKey]registeredRoute, denied, passthrough map[operationKey]bool) routeTable {
	table := make(routeTable)
	// Denials first: compilation rejects two operations of one shape, and a
	// denial wins wherever one could still overlap.
	for _, key := range slices.SortedFunc(maps.Keys(denied), compareOperationKeys) {
		table.add(&routeEntry{key: key, kind: entryDenied})
	}
	for _, key := range slices.SortedFunc(maps.Keys(routes), compareOperationKeys) {
		route := routes[key]
		table.add(&routeEntry{key: key, kind: entryRoute, route: &route})
	}
	for _, key := range slices.SortedFunc(maps.Keys(passthrough), compareOperationKeys) {
		table.add(&routeEntry{key: key, kind: entryPassthrough})
	}
	return table
}

var templateSegment = regexp.MustCompile(`\{[^{}]*\}`)

func (t routeTable) add(entry *routeEntry) {
	node := t[entry.key.method]
	if node == nil {
		node = &routeNode{}
		t[entry.key.method] = node
	}
	segments := strings.Split(strings.TrimPrefix(entry.key.path, "/"), "/")
	entry.params = make([]string, len(segments))
	for i, segment := range segments {
		switch {
		case parameterSegment(segment):
			entry.params[i] = strings.Trim(segment, "{}")
			if node.param == nil {
				node.param = &routeNode{}
			}
			node = node.param
		case strings.Contains(segment, "{"):
			index := slices.IndexFunc(node.patterns, func(p routePattern) bool { return p.source == segment })
			if index < 0 {
				parts := templateSegment.Split(segment, -1)
				for j, part := range parts {
					parts[j] = regexp.QuoteMeta(part)
				}
				node.patterns = append(node.patterns, routePattern{segment, regexp.MustCompile("^" + strings.Join(parts, ".+") + "$"), &routeNode{}})
				index = len(node.patterns) - 1
			}
			node = node.patterns[index].node
		default:
			if node.literals == nil {
				node.literals = make(map[string]*routeNode)
			}
			if node.literals[segment] == nil {
				node.literals[segment] = &routeNode{}
			}
			node = node.literals[segment]
		}
	}
	if node.entry == nil {
		node.entry = entry
	}
}

func (n *routeNode) match(segments []string) *routeEntry {
	if n == nil {
		return nil
	}
	if len(segments) == 0 {
		return n.entry
	}
	if entry := n.literals[segments[0]].match(segments[1:]); entry != nil {
		return entry
	}
	for _, pattern := range n.patterns {
		if pattern.match.MatchString(segments[0]) {
			if entry := pattern.node.match(segments[1:]); entry != nil {
				return entry
			}
		}
	}
	if segments[0] != "" {
		return n.param.match(segments[1:])
	}
	return nil
}

// lookup matches decoded path segments. HEAD falls back to GET.
func (t routeTable) lookup(method string, segments []string) *routeEntry {
	if entry := t[method].match(segments); entry != nil || method != http.MethodHead {
		return entry
	}
	return t[http.MethodGet].match(segments)
}

// routeMatch is the outcome of matching a request against the snapshot.
type routeMatch struct {
	denied bool
	// route is set for a routed operation, with its decoded parameters.
	route  *registeredRoute
	params map[string]string
	// invalid marks a routed match whose parameter decodes to ., .., or a
	// value with / or \.
	invalid bool
}

// matchRequest matches a request path, as sent (raw, without the query) and
// decoded, or a legacy host's path below its prefix. Only a canonical path
// (see canonicalPath) matches an operation.
func (t routeTable) matchRequest(method, raw, decoded, legacyPrefix string) routeMatch {
	if !canonicalPath(raw, decoded) {
		return routeMatch{}
	}
	if legacyPrefix != "" {
		raw = legacyPrefix + raw
	}
	rawSegments := strings.Split(strings.TrimPrefix(strings.TrimSuffix(raw, "/"), "/"), "/")
	segments := make([]string, len(rawSegments))
	for i, segment := range rawSegments {
		value, err := url.PathUnescape(segment)
		if err != nil {
			return routeMatch{}
		}
		segments[i] = value
	}
	entry := t.lookup(method, segments)
	switch {
	case entry == nil || entry.kind == entryPassthrough:
		return routeMatch{}
	case entry.kind == entryDenied:
		return routeMatch{denied: true}
	}
	match := routeMatch{route: entry.route}
	for i, name := range entry.params {
		if name == "" {
			continue
		}
		value := segments[i]
		if value == "." || value == ".." || strings.ContainsAny(value, `/\`) {
			return routeMatch{route: entry.route, invalid: true}
		}
		if match.params == nil {
			match.params = make(map[string]string)
		}
		match.params[name] = value
	}
	return match
}

// upstreamPath fills a route's upstream template with the matched, decoded
// parameters. The proxy escapes the result, so the upstream gets exactly the
// path that was matched, not the caller's spelling of it.
func upstreamPath(template string, params map[string]string) string {
	if len(params) == 0 {
		return template
	}
	segments := strings.Split(template, "/")
	for i, segment := range segments {
		if value, ok := params[strings.Trim(segment, "{}")]; ok && parameterSegment(segment) {
			segments[i] = value
		}
	}
	return strings.Join(segments, "/")
}
