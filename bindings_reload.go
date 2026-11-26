package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

// bindingsPollInterval is how often the bindings file is read. A ConfigMap
// volume swaps its ..data symlink atomically, so a change is detected by the
// content hash of the file, whatever its modification time.
const bindingsPollInterval = 2 * time.Second

// bindingsStatusStore is shared by every gateway. It holds the latest reload
// failure, the warnings of the latest successful reload, and the gateway of
// the latest accepted bindings, which /status reports before the first
// snapshot exists.
type bindingsStatusStore struct {
	mu       sync.RWMutex
	err      *bindingsError
	warnings []string
	current  atomic.Pointer[gateway]
}

// bindingsError is a rejected reload. Revision is the SHA-256 of the
// rejected content, empty when the file could not be read, so it can be told
// apart from the active bindingsRevision.
type bindingsError struct {
	Message  string `json:"message"`
	Time     string `json:"time"`
	Revision string `json:"revision,omitempty"`
}

func (s *bindingsStatusStore) failed(err error, revision string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = &bindingsError{Message: err.Error(), Time: now.UTC().Format(time.RFC3339), Revision: revision}
}

func (s *bindingsStatusStore) reloaded(warnings []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.warnings = warnings
}

func (s *bindingsStatusStore) read() (*bindingsError, []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.err, s.warnings
}

// retryableError is a reload failure that does not depend on the bindings
// content, such as contracts or a CA file that cannot be read, so the same
// content is tried again.
type retryableError struct{ error }

func (e retryableError) Unwrap() error { return e.error }

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
// in one store. On any error the active bindings and snapshot stay. The
// warnings name the services that lost their last good contract, which no
// longer compiles with the new bindings.
func (r *reconciler) reloadBindings(next upstreamBindings, revision string, now time.Time) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	previous := r.gateway
	if err := hotSwappable(previous.bindings, next, r.watched); err != nil {
		return nil, err
	}
	next.requireAuthz = previous.bindings.requireAuthz
	r.gateway = previous.withBindings(next, revision, now)
	r.lastDropped = nil
	if r.load != nil {
		r.applyLocked()
		if active := r.active.Load(); active == nil || active.gateway != r.gateway {
			// The contracts could not be read, so nothing was compiled with the
			// new bindings.
			r.gateway = previous
			return nil, retryableError{errors.New("the contracts could not be read to compile the new bindings")}
		}
	}
	r.gateway.bindingsStatus.current.Store(r.gateway)
	warnings := r.lastDropped
	r.gateway.bindingsStatus.reloaded(warnings)
	return warnings, nil
}

// watchBindings reads the bindings file every interval and reloads it when
// its content changes. A file that does not parse, validate or hot-swap is
// logged and reported once per revision, and the active bindings stay.
func (r *reconciler) watchBindings(ctx context.Context, path string, local bool, revision string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	r.mu.Lock()
	status := r.gateway.bindingsStatus
	r.mu.Unlock()
	// current is the active revision. failed is a revision whose content was
	// rejected, which is not tried again; reported is the last error logged.
	current, failed, reported := revision, "", ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		bindings, next, err := readBindings(path, local, false)
		if next == current || next != "" && next == failed {
			continue
		}
		now := time.Now()
		var warnings []string
		if err == nil {
			warnings, err = r.reloadBindings(bindings, next, now)
		}
		if err != nil {
			// A file that cannot be read has no revision, and a failure that
			// does not depend on the content is tried again; both are logged
			// once per message.
			var retry retryableError
			if next != "" && !errors.As(err, &retry) {
				failed = next
			}
			if message := next + " " + err.Error(); message != reported {
				log.Printf("bindings reload rejected, keeping revision %s: %v", short(current), err)
				status.failed(err, next, now)
				reported = message
			}
			continue
		}
		log.Printf("bindings reloaded revision=%s", short(next))
		for _, warning := range warnings {
			log.Printf("bindings reload warning: %s", warning)
		}
		current, failed, reported = next, "", ""
	}
}

func short(revision string) string {
	if len(revision) > 12 {
		return revision[:12]
	}
	return revision
}
