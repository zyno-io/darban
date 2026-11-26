package main

import (
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type upstreamStatus struct {
	Service string        `json:"service"`
	Role    string        `json:"role"`
	State   endpointState `json:"state"`
}

type contractRejection struct {
	Message string `json:"message"`
	Time    string `json:"time"`
}

// contractStatus reports one service's contract. Serving is current,
// last-good, or none. State is the explicit outcome: serving, serving_last_good,
// not_installed or closed, with the Reason. Rejected is true while the service's latest contract is
// being rejected; LastRejection stays after the contract is fixed. Publish is
// the service's binding setting. Routes, Documented and Denied
// count the public operation keys under the service's prefix that the active
// snapshot routes, documents and denies.
type contractStatus struct {
	Service       string             `json:"service"`
	Serving       string             `json:"serving"`
	Rejected      bool               `json:"rejected"`
	Missing       bool               `json:"missing,omitempty"`
	State         string             `json:"state"`
	Reason        string             `json:"reason,omitempty"`
	Enabled       bool               `json:"enabled"`
	Publish       bool               `json:"publish"`
	Routes        int                `json:"routes"`
	Documented    int                `json:"documented"`
	Denied        int                `json:"denied"`
	Warnings      []string           `json:"warnings,omitempty"`
	LastRejection *contractRejection `json:"lastRejection,omitempty"`
}

type contractStatusStore struct {
	mu       sync.RWMutex
	services map[string]contractStatus
}

func (s *contractStatusStore) update(report compileReport, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make(map[string]contractStatus, len(report.services))
	for name, outcome := range report.services {
		entry := contractStatus{Service: name, Serving: outcome.serving, Rejected: outcome.rejection != "", Missing: outcome.missing,
			State: outcome.state, Reason: outcome.reason, Enabled: outcome.enabled, Publish: outcome.publish,
			Routes: outcome.counts.routes, Documented: outcome.counts.documented, Denied: outcome.counts.denied,
			Warnings: outcome.warnings}
		previous := s.services[name]
		entry.LastRejection = previous.LastRejection
		if entry.Rejected && !(previous.Rejected && previous.LastRejection != nil && previous.LastRejection.Message == outcome.rejection) {
			entry.LastRejection = &contractRejection{Message: outcome.rejection, Time: now.UTC().Format(time.RFC3339)}
		}
		next[name] = entry
	}
	s.services = next
}

func (s *contractStatusStore) list() []contractStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.SortedFunc(maps.Values(s.services), func(a, b contractStatus) int {
		return strings.Compare(a.Service, b.Service)
	})
}

type statusResponse struct {
	Status            string             `json:"status"`
	Ready             bool               `json:"ready"`
	BindingsRevision  string             `json:"bindingsRevision,omitempty"`
	BindingsLoadedAt  string             `json:"bindingsLoadedAt,omitempty"`
	LastBindingsError *contractRejection `json:"lastBindingsError,omitempty"`
	ContractServices  []string           `json:"contractServices,omitempty"`
	ContractRevision  string             `json:"contractRevision,omitempty"`
	Contracts         []contractStatus   `json:"contracts,omitempty"`
	RouteCount        int                `json:"routeCount"`
	Upstreams         []upstreamStatus   `json:"upstreams"`
}

func (g *gateway) statusHandler(active *atomic.Pointer[snapshot], draining *atomic.Bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		snapshot := active.Load()
		g := g
		if snapshot != nil && snapshot.gateway != nil {
			g = snapshot.gateway
		}
		stopping := draining.Load()
		report := statusResponse{Status: "ready", Ready: snapshot != nil && !stopping}
		report.BindingsRevision, report.BindingsLoadedAt, report.LastBindingsError = g.bindingsStatus.read()
		report.Upstreams = append(report.Upstreams, upstreamStatus{"authz", "authorization", g.endpoints.state(g.bindings.Authz)})
		// Contracts can add upstreams at runtime, so merge the served ones.
		services := maps.Clone(g.bindings.Services)
		if snapshot != nil {
			if services == nil {
				services = make(map[string]serviceBinding)
			}
			maps.Copy(services, snapshot.services)
		}
		for _, name := range slices.Sorted(maps.Keys(services)) {
			binding := services[name]
			report.Upstreams = append(report.Upstreams,
				upstreamStatus{name, "primary", g.endpoints.state(binding.Origin)},
				upstreamStatus{name, "debug", g.endpoints.state(binding.DebugOrigin)},
			)
		}
		report.Contracts = g.contractStatus.list()
		if snapshot != nil {
			report.ContractRevision = snapshot.revision
			report.ContractServices = snapshot.contractServices
			report.RouteCount = len(snapshot.routes)
		}
		code := http.StatusOK
		if stopping {
			report.Status, code = "draining", http.StatusServiceUnavailable
		} else if snapshot == nil {
			report.Status, code = "starting", http.StatusServiceUnavailable
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(report)
	}
}
