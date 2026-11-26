package main

import (
	"context"
	"errors"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/yaml"
)

const contractNamePrefix = "api-contract-"

type localManifest struct {
	Contracts []struct {
		ServiceName       string               `json:"serviceName"`
		Upstream          string               `json:"upstream,omitempty"`
		Prefix            string               `json:"prefix,omitempty"`
		OpenAPIPath       string               `json:"openapi.yaml"`
		RewritesPath      string               `json:"rewrites.yaml"`
		DefaultVisibility *operationVisibility `json:"defaultVisibility,omitempty"`
	} `json:"contracts"`
}

func loadLocal(path string) ([]registration, error) {
	var manifest localManifest
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := yaml.UnmarshalStrict(raw, &manifest); err != nil {
		return nil, errors.New("invalid local contract manifest")
	}
	base := filepath.Dir(path)
	regs := make([]registration, 0, len(manifest.Contracts))
	for _, entry := range manifest.Contracts {
		spec, rewrites, err := readLocalContract(base, entry.OpenAPIPath, entry.RewritesPath)
		if err != nil {
			// A broken entry rejects its own service, like a broken GatewayContract.
			if !serviceName.MatchString(entry.ServiceName) {
				return nil, err
			}
			regs = append(regs, registration{serviceName: entry.ServiceName, invalid: err, local: true})
			continue
		}
		regs = append(regs, registration{
			serviceName: entry.ServiceName, openAPI: spec, rewrites: rewrites,
			upstream: entry.Upstream, prefix: entry.Prefix, local: true, defaultVisibility: entry.DefaultVisibility,
		})
	}
	return regs, nil
}

func readLocalContract(base, openAPIPath, rewritesPath string) (string, string, error) {
	for _, file := range []string{openAPIPath, rewritesPath} {
		if file == "" || !filepath.IsLocal(file) {
			return "", "", errors.New("contract paths must be relative to the manifest")
		}
	}
	spec, err := os.ReadFile(filepath.Join(base, openAPIPath))
	if err != nil {
		return "", "", err
	}
	rewrites, err := os.ReadFile(filepath.Join(base, rewritesPath))
	if err != nil {
		return "", "", err
	}
	return string(spec), string(rewrites), nil
}

// nameFromResource recovers the service name from an api-contract-<service>
// resource name so a broken resource is isolated to its own service.
func nameFromResource(name string) (string, bool) {
	service, found := strings.CutPrefix(name, contractNamePrefix)
	return service, found && serviceName.MatchString(service)
}

type reconciler struct {
	gateway   *gateway
	active    *atomic.Pointer[snapshot]
	lastError string
	// lastGood holds the units serving in the active snapshot, by service.
	lastGood map[string]*serviceUnit
	logged   map[string]string
	// warned holds the last logged warnings per service.
	warned map[string]string
	// overrides remembers the contract-over-binding messages already logged.
	overrides map[string]string
	now       func() time.Time
}

// classify sets each service's explicit state and reason. Services whose
// prefix has a direct service route fail closed (503) until a good contract
// arrives, including after the contract was deleted; every other unaccepted
// service is simply not installed.
func (r *reconciler) classify(report *compileReport) {
	bindings := r.gateway.bindings
	names := make(map[string]bool, len(report.services)+len(bindings.Services))
	for name := range report.services {
		names[name] = true
	}
	for name, binding := range bindings.Services {
		if binding.routed() && binding.Prefix != "" {
			names[name] = true
		}
	}
	for name := range names {
		outcome := report.services[name]
		reason := outcome.rejection
		if reason == "" && outcome.missing || reason == "" && report.accepted[name] == nil {
			reason = "no GatewayContract"
		}
		switch {
		case outcome.serving == servingCurrent:
			outcome.state, reason = stateServing, ""
		case outcome.serving == servingLastGood:
			outcome.state = stateServingLastGood
		default:
			outcome.state = stateNotInstalled
			binding := bindings.Services[name]
			if _, direct := bindings.ServiceRoutes[binding.Prefix]; direct && binding.routed() && binding.Prefix != "" {
				outcome.state = stateDirectRouteClosed
				reason += "; direct service route returns 503 until a good contract is seen"
			}
		}
		outcome.reason = reason
		report.services[name] = outcome
	}
}

func (r *reconciler) apply(load func() ([]registration, error)) {
	regs, err := load()
	if err != nil {
		// Nothing was loaded, so keep serving what is active.
		if message := err.Error(); message != r.lastError {
			log.Printf("contract candidate rejected: %s", strings.ReplaceAll(message, "\n", " "))
			r.lastError = message
		}
		return
	}
	r.lastError = ""
	compiled, report := compile(regs, r.gateway.bindings, r.lastGood)
	r.lastGood = report.accepted
	r.classify(&report)
	r.logRejections(report)
	r.logOverrides(report)
	now := time.Now
	if r.now != nil {
		now = r.now
	}
	r.gateway.contractStatus.update(report, now())
	old := r.active.Load()
	// The first apply always stores a snapshot, so a pod is ready once its
	// contracts are loaded whether or not any of them is valid.
	if old == nil || old.revision != compiled.revision {
		r.active.Store(r.gateway.build(compiled))
		log.Printf("contract snapshot active revision=%s", compiled.revision)
	}
}

// logRejections logs each service's rejection when its message changes.
func (r *reconciler) logRejections(report compileReport) {
	if r.logged == nil {
		r.logged = make(map[string]string)
	}
	for _, name := range slices.Sorted(maps.Keys(report.services)) {
		outcome := report.services[name]
		if outcome.rejection == "" {
			delete(r.logged, name)
			continue
		}
		if r.logged[name] != outcome.rejection {
			log.Printf("contract candidate rejected: %s (service=%s serving=%s)",
				strings.ReplaceAll(outcome.rejection, "\n", " "), name, outcome.serving)
			r.logged[name] = outcome.rejection
		}
	}
	for name := range r.logged {
		if _, present := report.services[name]; !present {
			delete(r.logged, name)
		}
	}
	if r.warned == nil {
		r.warned = make(map[string]string)
	}
	for _, name := range slices.Sorted(maps.Keys(report.services)) {
		warnings := report.services[name].warnings
		if len(warnings) == 0 {
			delete(r.warned, name)
			continue
		}
		if warning := strings.Join(warnings, "; "); r.warned[name] != warning {
			log.Printf("contract warning: %s (service=%s)", strings.ReplaceAll(warning, "\n", " "), name)
			r.warned[name] = warning
		}
	}
	for name := range r.warned {
		if _, present := report.services[name]; !present {
			delete(r.warned, name)
		}
	}
}

// logOverrides logs where a contract disagrees with its bindings entry, once
// per distinct message.
func (r *reconciler) logOverrides(report compileReport) {
	if r.overrides == nil {
		r.overrides = make(map[string]string)
	}
	for _, name := range slices.Sorted(maps.Keys(report.overrides)) {
		if r.overrides[name] != report.overrides[name] {
			log.Print(report.overrides[name])
			r.overrides[name] = report.overrides[name]
		}
	}
	for name := range r.overrides {
		if _, present := report.overrides[name]; !present {
			delete(r.overrides, name)
		}
	}
}

func (r *reconciler) watchLocal(ctx context.Context, path string) {
	load := func() ([]registration, error) { return loadLocal(path) }
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		r.apply(load)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (r *reconciler) watchCluster(ctx context.Context, current cache.SharedIndexInformer) error {
	changed := make(chan struct{}, 1)
	mark := func() {
		select {
		case changed <- struct{}{}:
		default:
		}
	}
	handler := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { mark() },
		UpdateFunc: func(any, any) { mark() },
		DeleteFunc: func(any) { mark() },
	}
	if _, err := current.AddEventHandler(handler); err != nil {
		return err
	}
	go current.RunWithContext(ctx)
	if !cache.WaitForCacheSync(ctx.Done(), current.HasSynced) {
		return nil
	}
	load := func() ([]registration, error) {
		return loadClusterRegistrations(current.GetStore())
	}
	r.apply(load)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-changed:
			r.apply(load)
		}
	}
}
