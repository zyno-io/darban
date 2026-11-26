package main

import (
	"cmp"
	"crypto/sha256"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
)

// Shadow mode: a service with route: false keeps its traffic on its direct
// route, but each request that route serves is also matched against the
// service's contract. The counts show what routing it would change, before a
// cutover.

const (
	// shadowSampleEntries bounds each kind's distinct samples. Others only
	// count as overflow.
	shadowSampleEntries = 256
	// shadowSamplesShown is how many of each kind /status shows, by count.
	shadowSamplesShown = 20
)

// Shadow sample kinds.
const (
	shadowWouldDeny      = "wouldDeny"
	shadowUnmatched      = "unmatched"
	shadowWouldSkipAuth  = "wouldSkipAuth"
	shadowWouldAuthorize = "wouldAuthorize"
)

var shadowKinds = []string{shadowWouldDeny, shadowUnmatched, shadowWouldSkipAuth, shadowWouldAuthorize}

// shadowContract is a docs-only service's operations, with the digest of the
// contract they come from.
type shadowContract struct {
	digest     [sha256.Size]byte
	operations []shadowOperation
}

// shadowTable matches requests on one direct route against a docs-only
// contract.
type shadowTable struct {
	service string
	table   routeTable
	// literals are the literal segments of the contract's templates, the only
	// segments an unmatched request's sample keeps.
	literals map[string]bool
	counters *shadowCounters
}

func newShadowTable(service string, contract shadowContract, counters *shadowCounters) *shadowTable {
	routes := make(map[operationKey]registeredRoute)
	denied := make(map[operationKey]bool)
	literals := make(map[string]bool)
	for _, op := range contract.operations {
		if op.internal {
			denied[op.key] = true
		} else {
			routes[op.key] = registeredRoute{key: op.key, protected: op.protected}
		}
		for _, segment := range strings.Split(strings.TrimPrefix(op.key.path, "/"), "/") {
			if !strings.Contains(segment, "{") {
				literals[segment] = true
			}
		}
	}
	return &shadowTable{service, newRouteTable(routes, nil, denied, nil), literals, counters}
}

// shadowCounters are a contract's counts. A new contract digest starts new
// ones. All fields are safe to use from concurrent requests.
type shadowCounters struct {
	digest [sha256.Size]byte
	// refusedToday counts requests the direct route's own rules refuse,
	// which the contract is not compared with.
	refusedToday                                                 atomic.Uint64
	matched, wouldDeny, unmatched, wouldSkipAuth, wouldAuthorize atomic.Uint64
	// nowAuthzWouldSkip and nowSkipWouldAuthorize count matched requests
	// whose authorization the cutover changes.
	nowAuthzWouldSkip, nowSkipWouldAuthorize atomic.Uint64
	samples                                  map[string]*sampleCounts
}

func newShadowCounters(digest [sha256.Size]byte) *shadowCounters {
	counters := &shadowCounters{digest: digest, samples: make(map[string]*sampleCounts, len(shadowKinds))}
	for _, kind := range shadowKinds {
		counters.samples[kind] = &sampleCounts{}
	}
	return counters
}

// sampleCounts counts distinct samples, up to shadowSampleEntries of them.
// A known sample costs no lock.
type sampleCounts struct {
	entries  sync.Map // string → *atomic.Uint64
	size     atomic.Int32
	overflow atomic.Uint64
	mu       sync.Mutex
}

func (s *sampleCounts) add(sample string) {
	if count, ok := s.entries.Load(sample); ok {
		count.(*atomic.Uint64).Add(1)
		return
	}
	if s.size.Load() >= shadowSampleEntries {
		s.overflow.Add(1)
		return
	}
	s.mu.Lock()
	count, loaded := s.entries.LoadOrStore(sample, new(atomic.Uint64))
	if !loaded {
		if s.size.Load() >= shadowSampleEntries {
			s.entries.Delete(sample)
			s.mu.Unlock()
			s.overflow.Add(1)
			return
		}
		s.size.Add(1)
	}
	s.mu.Unlock()
	count.(*atomic.Uint64).Add(1)
}

type shadowSample struct {
	Sample string `json:"sample"`
	Count  uint64 `json:"count"`
}

// top returns the most frequent samples, most frequent first.
func (s *sampleCounts) top(n int) []shadowSample {
	var samples []shadowSample
	s.entries.Range(func(key, value any) bool {
		samples = append(samples, shadowSample{key.(string), value.(*atomic.Uint64).Load()})
		return true
	})
	slices.SortFunc(samples, func(a, b shadowSample) int {
		if c := cmp.Compare(b.Count, a.Count); c != 0 {
			return c
		}
		return strings.Compare(a.Sample, b.Sample)
	})
	return samples[:min(n, len(samples))]
}

type shadowRegistry struct {
	mu       sync.Mutex
	services map[string]*shadowCounters
}

// counters returns the service's counts for a contract, new ones when its
// digest changed.
func (r *shadowRegistry) counters(service string, digest [sha256.Size]byte) *shadowCounters {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.services == nil {
		r.services = make(map[string]*shadowCounters)
	}
	counters := r.services[service]
	if counters == nil || counters.digest != digest {
		counters = newShadowCounters(digest)
		r.services[service] = counters
	}
	return counters
}

// shadowRequest is how the direct route serves a request today.
type shadowRequest struct {
	method, raw, decoded, legacyPrefix string
	// allowed reports that the route's path rules let the request through,
	// and skipAuth that they leave its authorization to the backend.
	allowed, skipAuth bool
	// backendAuth reports that the route is a backendAuth route, which skips
	// authorization under the contract too.
	backendAuth bool
}

var sampleMethods = []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
	http.MethodDelete, http.MethodOptions, http.MethodTrace}

// observe records one request the direct route serves.
func (s *shadowTable) observe(request shadowRequest) {
	counters := s.counters
	if !request.allowed {
		counters.refusedToday.Add(1)
		return
	}
	match := s.table.matchRequest(request.method, request.raw, request.decoded, request.legacyPrefix)
	var kind string
	switch {
	case match.denied:
		kind = shadowWouldDeny
		counters.wouldDeny.Add(1)
	case match.route == nil || match.invalid:
		kind = shadowUnmatched
		counters.unmatched.Add(1)
	default:
		counters.matched.Add(1)
		kind = shadowWouldAuthorize
		if !match.route.protected || request.backendAuth {
			kind = shadowWouldSkipAuth
		}
		switch {
		case kind == shadowWouldSkipAuth:
			counters.wouldSkipAuth.Add(1)
			if !request.skipAuth {
				counters.nowAuthzWouldSkip.Add(1)
			}
		default:
			counters.wouldAuthorize.Add(1)
			if request.skipAuth {
				counters.nowSkipWouldAuthorize.Add(1)
			}
		}
	}
	method := "OTHER"
	if slices.Contains(sampleMethods, request.method) {
		method = request.method
	}
	template := match.key.path
	if kind == shadowUnmatched {
		template = s.redact(request.raw, request.legacyPrefix)
	}
	counters.samples[kind].add(method + " " + template)
}

// redact reduces a path no operation matched to a form that holds no
// identifiers: a segment stays only when it is a literal of the contract's
// templates, any other becomes {}, and only the first six segments are kept.
func (s *shadowTable) redact(raw, legacyPrefix string) string {
	if legacyPrefix != "" {
		raw = legacyPrefix + raw
	}
	segments := strings.Split(strings.TrimPrefix(raw, "/"), "/")
	truncated := len(segments) > 6
	if truncated {
		segments = segments[:6]
	}
	for i, segment := range segments {
		if !s.literals[segment] {
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
	RefusedToday          uint64 `json:"refusedToday"`
	Matched               uint64 `json:"matched"`
	WouldDeny             uint64 `json:"wouldDeny"`
	Unmatched             uint64 `json:"unmatched"`
	WouldSkipAuth         uint64 `json:"wouldSkipAuth"`
	WouldAuthorize        uint64 `json:"wouldAuthorize"`
	NowAuthzWouldSkip     uint64 `json:"nowAuthzWouldSkip"`
	NowSkipWouldAuthorize uint64 `json:"nowSkipWouldAuthorize"`
	// Samples holds, by kind, the most frequent METHOD template samples, and
	// Overflow how many requests had a sample beyond the counted ones.
	Samples  map[string][]shadowSample `json:"samples,omitempty"`
	Overflow map[string]uint64         `json:"overflow,omitempty"`
}

func (r *shadowRegistry) status(service string) *shadowStatus {
	r.mu.Lock()
	counters := r.services[service]
	r.mu.Unlock()
	if counters == nil {
		return nil
	}
	status := &shadowStatus{
		RefusedToday: counters.refusedToday.Load(),
		Matched:      counters.matched.Load(), WouldDeny: counters.wouldDeny.Load(), Unmatched: counters.unmatched.Load(),
		WouldSkipAuth: counters.wouldSkipAuth.Load(), WouldAuthorize: counters.wouldAuthorize.Load(),
		NowAuthzWouldSkip: counters.nowAuthzWouldSkip.Load(), NowSkipWouldAuthorize: counters.nowSkipWouldAuthorize.Load(),
	}
	for _, kind := range shadowKinds {
		samples := counters.samples[kind]
		if top := samples.top(shadowSamplesShown); len(top) > 0 {
			if status.Samples == nil {
				status.Samples = make(map[string][]shadowSample)
			}
			status.Samples[kind] = top
		}
		if overflow := samples.overflow.Load(); overflow > 0 {
			if status.Overflow == nil {
				status.Overflow = make(map[string]uint64)
			}
			status.Overflow[kind] = overflow
		}
	}
	return status
}
