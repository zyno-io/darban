package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"reflect"
	"sync"
	"time"
)

// bindingsPollInterval is how often the bindings file is read. A ConfigMap
// volume swaps its ..data symlink atomically, so a change is detected by the
// content hash of the file, whatever its modification time.
const bindingsPollInterval = 2 * time.Second

// bindingsStatusStore holds the active bindings revision and the latest
// reload failure for /status.
type bindingsStatusStore struct {
	mu        sync.RWMutex
	revision  string
	loadedAt  time.Time
	lastError *contractRejection
}

func (s *bindingsStatusStore) loaded(revision string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revision, s.loadedAt = revision, now
}

func (s *bindingsStatusStore) failed(err error, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastError = &contractRejection{Message: err.Error(), Time: now.UTC().Format(time.RFC3339)}
}

func (s *bindingsStatusStore) read() (revision, loadedAt string, lastError *contractRejection) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.loadedAt.IsZero() {
		loadedAt = s.loadedAt.UTC().Format(time.RFC3339)
	}
	return s.revision, loadedAt, s.lastError
}

// hotSwappable reports why new bindings cannot replace the active ones
// without a restart: the contract API group selects the informer, the
// upstream TLS settings build the shared transports, and the EndpointSlice
// catalog watches the Services outside the watched namespace by name.
func hotSwappable(old, next upstreamBindings, watched string) error {
	if old.ContractAPIGroup != next.ContractAPIGroup {
		return errors.New("contractAPIGroup cannot change at runtime; restart the gateway to apply it")
	}
	if old.UpstreamTLS != next.UpstreamTLS {
		return errors.New("upstreamTLS cannot change at runtime; restart the gateway to apply it")
	}
	if watched != "" && !reflect.DeepEqual(externalServices(old, watched), externalServices(next, watched)) {
		return fmt.Errorf("the Services named outside namespace %s cannot change at runtime; restart the gateway to apply them", watched)
	}
	return nil
}

// reloadBindings makes new bindings active: it compiles the current
// contracts with them and swaps the snapshot, which carries the new gateway,
// in one store. On any error the active bindings and snapshot stay.
func (r *reconciler) reloadBindings(next upstreamBindings, revision string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	previous := r.gateway
	if err := hotSwappable(previous.bindings, next, r.watched); err != nil {
		return err
	}
	r.gateway = previous.withBindings(next)
	if r.load != nil {
		r.applyLocked()
		if active := r.active.Load(); active == nil || active.gateway != r.gateway {
			// The contracts could not be read, so nothing was compiled with the
			// new bindings.
			r.gateway = previous
			return errors.New("the contracts could not be read to compile the new bindings")
		}
	}
	r.gateway.bindingsStatus.loaded(revision, now)
	return nil
}

// watchBindings reads the bindings file every interval and reloads it when
// its content changes. A file that does not parse, validate or hot-swap is
// logged and reported once per revision, and the active bindings stay.
func (r *reconciler) watchBindings(ctx context.Context, path string, local bool, revision string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	current, failed := revision, ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		bindings, next, err := readBindings(path, local)
		if next == current || next != "" && next == failed {
			continue
		}
		now := time.Now()
		if err == nil {
			err = r.reloadBindings(bindings, next, now)
		}
		if err != nil {
			// A file that cannot be read has no revision; report it once per
			// message instead.
			key := next
			if key == "" {
				key = "unreadable: " + err.Error()
			}
			if key != failed {
				log.Printf("bindings reload rejected, keeping revision %s: %v", short(current), err)
				r.mu.Lock()
				r.gateway.bindingsStatus.failed(err, now)
				r.mu.Unlock()
			}
			failed = key
			continue
		}
		log.Printf("bindings reloaded revision=%s", short(next))
		current, failed = next, ""
	}
}

func short(revision string) string {
	if len(revision) > 12 {
		return revision[:12]
	}
	return revision
}
