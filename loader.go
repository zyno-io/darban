package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/yaml"
)

const contractNamePrefix = "api-contract-"

type localManifest struct {
	Contracts []struct {
		ServiceName       string               `json:"serviceName"`
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
		for _, file := range []string{entry.OpenAPIPath, entry.RewritesPath} {
			if file == "" || !filepath.IsLocal(file) {
				return nil, errors.New("contract paths must be relative to the manifest")
			}
		}
		spec, err := os.ReadFile(filepath.Join(base, entry.OpenAPIPath))
		if err != nil {
			return nil, err
		}
		rewrites, err := os.ReadFile(filepath.Join(base, entry.RewritesPath))
		if err != nil {
			return nil, err
		}
		regs = append(regs, registration{serviceName: entry.ServiceName, openAPI: string(spec), rewrites: string(rewrites), defaultVisibility: entry.DefaultVisibility})
	}
	return regs, nil
}

// nameFromResource recovers the service name from an api-contract-<service>
// resource name so a broken resource is isolated to its own service.
func nameFromResource(name string) (string, bool) {
	service, found := strings.CutPrefix(name, contractNamePrefix)
	return service, found && serviceName.MatchString(service)
}

func registrationsFromStore(store cache.Store) ([]registration, error) {
	items := store.List()
	regs := make([]registration, 0, len(items))
	for _, item := range items {
		cm := item.(*corev1.ConfigMap)
		service, hasName := cm.Data["serviceName"]
		spec, hasSpec := cm.Data["openapi.yaml"]
		rewrites, hasRewrites := cm.Data["rewrites.yaml"]
		if len(cm.BinaryData) != 0 || len(cm.Data) != 3 || !hasName || !hasSpec || !hasRewrites ||
			cm.Name != contractNamePrefix+service {
			invalid := fmt.Errorf("invalid registration ConfigMap %s", cm.Name)
			if name, ok := nameFromResource(cm.Name); ok {
				regs = append(regs, registration{serviceName: name, invalid: invalid})
				continue
			}
			return nil, invalid
		}
		regs = append(regs, registration{serviceName: service, openAPI: spec, rewrites: rewrites, created: cm.CreationTimestamp.Time})
	}
	return regs, nil
}

func newConfigMapInformer(config *rest.Config, namespace, apiGroup string) (cache.SharedIndexInformer, error) {
	client, err := coreclient.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	api := cache.NewFilteredListWatchFromClient(client.RESTClient(), "configmaps", namespace, func(options *metav1.ListOptions) {
		options.LabelSelector = apiGroup + "/contract=true"
	})
	return cache.NewSharedIndexInformer(api, &corev1.ConfigMap{}, 0, cache.Indexers{}), nil
}

type reconciler struct {
	gateway   *gateway
	active    *atomic.Pointer[snapshot]
	lastError string
	// lastGood holds the units serving in the active snapshot, by service.
	lastGood map[string]*serviceUnit
	logged   map[string]string
	now      func() time.Time
	held     string
	// tombstones keep the deny list of a service whose contract was deleted, by
	// public prefix, so its internal operations stay denied without an outage.
	tombstones map[string][]operationKey
}

// applyTombstones records each serving service's deny list and, for a service
// that lost its contract after being served on this pod, restores that list and
// lets the direct service route keep proxying. Services never served stay
// unserved and fail closed.
func (r *reconciler) applyTombstones(compiled *candidate, report compileReport) {
	if r.tombstones == nil {
		r.tombstones = make(map[string][]operationKey)
	}
	var restored []string
	for _, name := range slices.Sorted(maps.Keys(r.gateway.bindings.Services)) {
		binding := r.gateway.bindings.Services[name]
		if binding.RegistrationOnly {
			continue
		}
		if report.accepted[name] != nil {
			r.tombstones[binding.Prefix] = slices.DeleteFunc(slices.Clone(compiled.denied), func(key operationKey) bool {
				return key.path != binding.Prefix && !strings.HasPrefix(key.path, binding.Prefix+"/")
			})
			continue
		}
		if denied, ok := r.tombstones[binding.Prefix]; ok {
			restored = append(restored, binding.Prefix)
			compiled.denied = append(compiled.denied, denied...)
		}
	}
	if len(restored) == 0 {
		return
	}
	slices.SortFunc(compiled.denied, compareOperationKeys)
	compiled.denied = slices.Compact(compiled.denied)
	compiled.unserved = slices.DeleteFunc(compiled.unserved, func(prefix string) bool { return slices.Contains(restored, prefix) })
	hash := sha256.New()
	fmt.Fprintf(hash, "%s tombstoned %v", compiled.revision, restored)
	for _, key := range compiled.denied {
		fmt.Fprintf(hash, " %s %s", key.method, key.path)
	}
	compiled.revision = hex.EncodeToString(hash.Sum(nil))
}

func (r *reconciler) firstSnapshotBlock(report compileReport) string {
	for _, name := range slices.Sorted(maps.Keys(r.gateway.bindings.Services)) {
		if r.gateway.bindings.Services[name].RegistrationOnly {
			continue
		}
		outcome := report.services[name]
		if outcome.missing {
			return fmt.Sprintf("service %s has no contract", name)
		}
		if outcome.rejection != "" {
			return outcome.rejection
		}
	}
	return ""
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
	r.applyTombstones(&compiled, report)
	r.logRejections(report)
	now := time.Now
	if r.now != nil {
		now = r.now
	}
	r.gateway.contractStatus.update(report, now())
	old := r.active.Load()
	if old == nil {
		// A new pod only becomes ready with a complete, valid contract set, so a
		// bad rollout never replaces serving pods. Once ready it keeps isolation.
		if reason := r.firstSnapshotBlock(report); reason != "" {
			if reason != r.held {
				log.Printf("contract snapshot not ready: %s", reason)
				r.held = reason
			}
			return
		}
		r.held = ""
	}
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

func (r *reconciler) watchCluster(ctx context.Context, legacy, current cache.SharedIndexInformer) error {
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
	for _, informer := range []cache.SharedIndexInformer{legacy, current} {
		if _, err := informer.AddEventHandler(handler); err != nil {
			return err
		}
		go informer.RunWithContext(ctx)
	}
	if !cache.WaitForCacheSync(ctx.Done(), legacy.HasSynced, current.HasSynced) {
		return nil
	}
	load := func() ([]registration, error) {
		return loadClusterRegistrations(legacy.GetStore(), current.GetStore())
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
