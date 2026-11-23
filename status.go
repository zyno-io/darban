package main

import (
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"sync/atomic"
)

type upstreamStatus struct {
	Service string        `json:"service"`
	Role    string        `json:"role"`
	State   endpointState `json:"state"`
}

type statusResponse struct {
	Status           string           `json:"status"`
	Ready            bool             `json:"ready"`
	ContractServices []string         `json:"contractServices,omitempty"`
	ContractRevision string           `json:"contractRevision,omitempty"`
	RouteCount       int              `json:"routeCount"`
	Upstreams        []upstreamStatus `json:"upstreams"`
}

func (g *gateway) statusHandler(active *atomic.Pointer[snapshot], draining *atomic.Bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		snapshot := active.Load()
		stopping := draining.Load()
		report := statusResponse{Status: "ready", Ready: snapshot != nil && !stopping}
		report.Upstreams = append(report.Upstreams, upstreamStatus{"authz", "authorization", g.endpoints.state(g.bindings.Authz)})
		for _, name := range slices.Sorted(maps.Keys(g.bindings.Services)) {
			binding := g.bindings.Services[name]
			report.Upstreams = append(report.Upstreams,
				upstreamStatus{name, "primary", g.endpoints.state(binding.Origin)},
				upstreamStatus{name, "debug", g.endpoints.state(binding.DebugOrigin)},
			)
		}
		for _, prefix := range slices.Sorted(maps.Keys(g.bindings.ServiceRoutes)) {
			route := g.bindings.ServiceRoutes[prefix]
			report.Upstreams = append(report.Upstreams, upstreamStatus{prefix, "service", g.endpoints.state(route.Origin)})
		}
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
