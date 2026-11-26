package main

import (
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
)

// Shadow mode: a service with route: false keeps its traffic on its direct
// route, but each request on that route is also matched against the
// service's contract. The counts show what routing it would change, before a
// cutover.

const shadowSamplesPerKind = 20

// Shadow sample kinds.
const (
	shadowWouldDeny      = "wouldDeny"
	shadowUnmatched      = "unmatched"
	shadowWouldSkipAuth  = "wouldSkipAuth"
	shadowWouldAuthorize = "wouldAuthorize"
)

// shadowTable matches requests on one direct route against a docs-only
// contract.
type shadowTable struct {
	service  string
	table    routeTable
	counters *shadowCounters
}

func newShadowTable(service string, operations []shadowOperation, counters *shadowCounters) *shadowTable {
	routes := make(map[operationKey]registeredRoute)
	denied := make(map[operationKey]bool)
	for _, op := range operations {
		if op.internal {
			denied[op.key] = true
		} else {
			routes[op.key] = registeredRoute{key: op.key, protected: op.protected}
		}
	}
	return &shadowTable{service, newRouteTable(routes, nil, denied, nil), counters}
}

// shadowCounters survive snapshot changes. All fields are safe to use from
// concurrent requests.
type shadowCounters struct {
	matched, wouldDeny, unmatched, wouldSkipAuth, wouldAuthorize atomic.Uint64
	// sampled counts the samples taken, so a full set costs no lock.
	sampled atomic.Int32
	mu      sync.Mutex
	samples map[string][]string
}

type shadowRegistry struct {
	mu       sync.Mutex
	services map[string]*shadowCounters
}

func (r *shadowRegistry) counters(service string) *shadowCounters {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.services == nil {
		r.services = make(map[string]*shadowCounters)
	}
	counters := r.services[service]
	if counters == nil {
		counters = &shadowCounters{samples: make(map[string][]string)}
		r.services[service] = counters
	}
	return counters
}

// observe records one request on a direct route. backendAuth reports that the
// route leaves authorization to the backend.
func (s *shadowTable) observe(method, raw, decoded, legacyPrefix string, backendAuth bool) {
	counters := s.counters
	match := s.table.matchRequest(method, raw, decoded, legacyPrefix)
	var kind string
	var seen uint64
	switch {
	case match.denied:
		kind, seen = shadowWouldDeny, counters.wouldDeny.Add(1)
	case match.route == nil || match.invalid:
		kind, seen = shadowUnmatched, counters.unmatched.Add(1)
	default:
		counters.matched.Add(1)
		kind, seen = shadowWouldAuthorize, 0
		if !match.route.protected || backendAuth {
			kind, seen = shadowWouldSkipAuth, counters.wouldSkipAuth.Add(1)
		} else {
			seen = counters.wouldAuthorize.Add(1)
		}
	}
	// Sample the first requests of each kind, then one in 1024, until the
	// kind has its samples. Most requests take no lock and build no sample.
	if counters.sampled.Load() >= 4*shadowSamplesPerKind || seen > 64 && seen%1024 != 0 {
		return
	}
	template := match.key.path
	if kind == shadowUnmatched {
		template = redactPath(raw, legacyPrefix)
	}
	sample := kind + " " + method + " " + template
	counters.mu.Lock()
	defer counters.mu.Unlock()
	if samples := counters.samples[kind]; len(samples) < shadowSamplesPerKind && !slices.Contains(samples, sample) {
		counters.samples[kind] = append(samples, sample)
		counters.sampled.Add(1)
	}
}

var plainSegment = regexp.MustCompile(`^[a-z][a-z_.-]{0,31}$`)

// redactPath reduces a path no operation matched to a form that holds no
// identifiers: segments that are not plain lowercase words become {}, and only
// the first six segments are kept.
func redactPath(raw, legacyPrefix string) string {
	if legacyPrefix != "" {
		raw = legacyPrefix + raw
	}
	segments := strings.Split(strings.TrimPrefix(raw, "/"), "/")
	truncated := len(segments) > 6
	if truncated {
		segments = segments[:6]
	}
	for i, segment := range segments {
		if !plainSegment.MatchString(segment) {
			segments[i] = "{}"
		}
	}
	path := "/" + strings.Join(segments, "/")
	if truncated {
		path += "/..."
	}
	return path
}

// shadowStatus is a contract's shadow counts in /status.
type shadowStatus struct {
	Matched        uint64   `json:"matched"`
	WouldDeny      uint64   `json:"wouldDeny"`
	Unmatched      uint64   `json:"unmatched"`
	WouldSkipAuth  uint64   `json:"wouldSkipAuth"`
	WouldAuthorize uint64   `json:"wouldAuthorize"`
	Samples        []string `json:"samples,omitempty"`
}

func (r *shadowRegistry) status(service string) *shadowStatus {
	r.mu.Lock()
	counters := r.services[service]
	r.mu.Unlock()
	if counters == nil {
		return nil
	}
	status := &shadowStatus{
		Matched: counters.matched.Load(), WouldDeny: counters.wouldDeny.Load(), Unmatched: counters.unmatched.Load(),
		WouldSkipAuth: counters.wouldSkipAuth.Load(), WouldAuthorize: counters.wouldAuthorize.Load(),
	}
	counters.mu.Lock()
	for _, kind := range slices.Sorted(maps.Keys(counters.samples)) {
		status.Samples = append(status.Samples, counters.samples[kind]...)
	}
	counters.mu.Unlock()
	return status
}
