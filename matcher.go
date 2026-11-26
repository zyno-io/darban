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
	// rest holds an extra route's trailing /*, which matches any remaining
	// segments, or none.
	rest  *routeNode
	entry *routeEntry
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

func newRouteTable(routes, extras map[operationKey]registeredRoute, denied, passthrough map[operationKey]bool) routeTable {
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
	// Extra routes last: an operation of the same shape keeps its path.
	for _, key := range slices.SortedFunc(maps.Keys(extras), compareOperationKeys) {
		route := extras[key]
		table.add(&routeEntry{key: key, kind: entryRoute, route: &route})
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
		case segment == "*" && i == len(segments)-1:
			entry.params[i] = "*"
			if node.rest == nil {
				node.rest = &routeNode{}
			}
			node = node.rest
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

// match finds the entry for the segments. patterned reports that a pattern
// segment was used on the way. With strict, a passthrough entry reached
// through a pattern does not count, so the search backtracks past it.
func (n *routeNode) match(segments []string, strict, patterned bool) (*routeEntry, bool) {
	if n == nil {
		return nil, false
	}
	if len(segments) == 0 {
		if n.entry == nil || strict && patterned && n.entry.kind == entryPassthrough {
			if n.rest != nil && n.rest.entry != nil {
				return n.rest.entry, patterned
			}
			return nil, false
		}
		return n.entry, patterned
	}
	if entry, via := n.literals[segments[0]].match(segments[1:], strict, patterned); entry != nil {
		return entry, via
	}
	for _, pattern := range n.patterns {
		if pattern.match.MatchString(segments[0]) {
			if entry, via := pattern.node.match(segments[1:], strict, true); entry != nil {
				return entry, via
			}
		}
	}
	if segments[0] != "" {
		if entry, via := n.param.match(segments[1:], strict, patterned); entry != nil {
			return entry, via
		}
	}
	if n.rest != nil && n.rest.entry != nil {
		return n.rest.entry, patterned
	}
	return nil, false
}

// lookup matches decoded path segments. HEAD falls back to GET.
//
// A pattern segment such as items{batch} is looser than the backend's
// literal (items:batch), so a passthrough entry reached through one is
// provisional: the backend may give the path to a parameter route instead.
// The path is matched again with such passthroughs set aside. If that reaches
// a denied entry, the denial wins. If it reaches a routed operation, the path
// is denied too: passing it through would skip that operation's
// authorization, and routing it could capture the unselected operation.
func (t routeTable) lookup(method string, segments []string) *routeEntry {
	find := func(method string) *routeEntry {
		entry, patterned := t[method].match(segments, false, false)
		if entry != nil && entry.kind == entryPassthrough && patterned {
			switch strict, _ := t[method].match(segments, true, false); {
			case strict == nil || strict.kind == entryPassthrough:
			case strict.kind == entryDenied:
				return strict
			default:
				return &routeEntry{key: strict.key, kind: entryDenied}
			}
		}
		return entry
	}
	if entry := find(method); entry != nil || method != http.MethodHead {
		return entry
	}
	return find(http.MethodGet)
}

// routeMatch is the outcome of matching a request against the snapshot.
type routeMatch struct {
	denied bool
	// passthrough marks an operation the bindings leave unselected.
	passthrough bool
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
	case entry == nil:
		return routeMatch{}
	case entry.kind == entryPassthrough:
		return routeMatch{passthrough: true}
	case entry.kind == entryDenied:
		return routeMatch{denied: true}
	}
	match := routeMatch{route: entry.route}
	for i, name := range entry.params {
		if name == "*" {
			// The rest of the path, already canonical.
			if match.params == nil {
				match.params = make(map[string]string)
			}
			match.params[name] = ""
			if i < len(segments) {
				match.params[name] = strings.Join(segments[i:], "/")
			}
			continue
		}
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
	if last := len(segments) - 1; segments[last] == "*" {
		segments[last] = params["*"]
		if segments[last] == "" {
			segments = segments[:last]
		}
	}
	return strings.Join(segments, "/")
}
