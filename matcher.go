package main

import (
	"maps"
	"net/http"
	"net/url"
	pathpkg "path"
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

// parameterSegment reports whether a template segment is a parameter. A
// segment that only contains a template, as an internal operation's path may,
// is treated as one too, so a denial covers every value it could stand for.
func parameterSegment(segment string) bool {
	return strings.Contains(segment, "{")
}

// pathShape replaces every parameter of a template with {}, so two templates
// that match the same paths have the same shape.
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
// routed and denied operations. Each segment tries a literal before a
// parameter and backtracks when the rest of the path does not match.
type routeTable map[string]*routeNode

type routeNode struct {
	literals map[string]*routeNode
	param    *routeNode
	entry    *routeEntry
}

type routeEntry struct {
	key    operationKey
	denied bool
	route  *registeredRoute
	// params names the parameter at each segment position, "" for a literal.
	params []string
}

func newRouteTable(routes map[operationKey]registeredRoute, denied map[operationKey]bool) routeTable {
	table := make(routeTable)
	for _, key := range slices.SortedFunc(maps.Keys(routes), compareOperationKeys) {
		route := routes[key]
		table.add(&routeEntry{key: key, route: &route})
	}
	for _, key := range slices.SortedFunc(maps.Keys(denied), compareOperationKeys) {
		table.add(&routeEntry{key: key, denied: true})
	}
	return table
}

func (t routeTable) add(entry *routeEntry) {
	node := t[entry.key.method]
	if node == nil {
		node = &routeNode{}
		t[entry.key.method] = node
	}
	segments := strings.Split(strings.TrimPrefix(entry.key.path, "/"), "/")
	entry.params = make([]string, len(segments))
	for i, segment := range segments {
		if parameterSegment(segment) {
			entry.params[i] = strings.Trim(segment, "{}")
			if node.param == nil {
				node.param = &routeNode{}
			}
			node = node.param
			continue
		}
		if node.literals == nil {
			node.literals = make(map[string]*routeNode)
		}
		if node.literals[segment] == nil {
			node.literals[segment] = &routeNode{}
		}
		node = node.literals[segment]
	}
	// Compilation rejects two operations of one shape. The one exception is an
	// internal operation whose path is not a valid template, such as
	// /files/{name}.txt on a direct route. It is denied as a parameter, but a
	// routed operation of that shape, added first, keeps it.
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

// routeParam is one matched path parameter, as sent and decoded.
type routeParam struct {
	raw, decoded string
}

// routeMatch is the outcome of matching a request against the snapshot.
type routeMatch struct {
	denied bool
	// route is set for a routed operation, with its parameters by name.
	route  *registeredRoute
	params map[string]routeParam
	// invalid marks a routed match whose parameter decodes to ., .., or a
	// value with / or \.
	invalid bool
}

// matchRequest matches a request path, or a legacy host's path below its
// prefix. Only a canonical path matches an operation: one that path.Clean
// changes in more than a trailing slash, or that encodes / or \, matches
// none. Such a path is still denied when its cleaned form names a denied
// operation, so a direct route cannot reach it.
func (t routeTable) matchRequest(method string, r *http.Request, legacyPrefix string) routeMatch {
	raw, decoded := r.URL.EscapedPath(), r.URL.Path
	if legacyPrefix != "" {
		raw, decoded = legacyPrefix+raw, legacyPrefix+decoded
	}
	cleaned := pathpkg.Clean(decoded)
	lower := strings.ToLower(raw)
	canonical := !strings.Contains(lower, "%2f") && !strings.Contains(lower, "%5c") &&
		(decoded == cleaned || decoded == cleaned+"/") && cleaned != "/"
	if !canonical {
		if entry := t.lookup(method, strings.Split(strings.TrimPrefix(cleaned, "/"), "/")); entry != nil && entry.denied {
			return routeMatch{denied: true}
		}
		return routeMatch{}
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
	case entry.denied:
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
			match.params = make(map[string]routeParam)
		}
		match.params[name] = routeParam{raw: rawSegments[i], decoded: value}
	}
	return match
}

// upstreamPath fills a route's upstream template with the matched
// parameters, as a decoded path and its escaped form.
func upstreamPath(template string, params map[string]routeParam) (string, string) {
	if len(params) == 0 {
		return template, ""
	}
	segments := strings.Split(template, "/")
	escaped := slices.Clone(segments)
	for i, segment := range segments {
		if param, ok := params[strings.Trim(segment, "{}")]; ok && parameterSegment(segment) {
			segments[i], escaped[i] = param.decoded, param.raw
		}
	}
	return strings.Join(segments, "/"), strings.Join(escaped, "/")
}
