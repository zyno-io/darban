package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"sync/atomic"
	"time"
)

// upstreamTLSConfig is the top-level "upstreamTLS" bindings option.
type upstreamTLSConfig struct {
	CAFile             string
	InsecureSkipVerify bool
}

func (c upstreamTLSConfig) validate() error {
	if c.CAFile != "" && c.InsecureSkipVerify {
		return errors.New("upstreamTLS.caFile and upstreamTLS.insecureSkipVerify are mutually exclusive")
	}
	return nil
}

// upstreamVerifier builds the client TLS config shared by every upstream
// transport. With a CA file, the pool is swapped atomically on reload and
// verification runs in VerifyConnection against the current pool.
type upstreamVerifier struct {
	config  upstreamTLSConfig
	pool    atomic.Pointer[x509.CertPool]
	lastErr string
}

func loadCAPool(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return pool, nil
}

func newUpstreamVerifier(config upstreamTLSConfig) (*upstreamVerifier, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	v := &upstreamVerifier{config: config}
	if config.CAFile != "" {
		pool, err := loadCAPool(config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("upstreamTLS.caFile: %w", err)
		}
		v.pool.Store(pool)
	}
	if config.InsecureSkipVerify {
		log.Print("WARNING: upstreamTLS.insecureSkipVerify is set; upstream certificates are not verified")
	}
	return v, nil
}

// refresh reloads the CA bundle, keeping the previous pool on failure and
// logging each distinct error once.
func (v *upstreamVerifier) refresh() {
	if v.config.CAFile == "" {
		return
	}
	pool, err := loadCAPool(v.config.CAFile)
	if err != nil {
		if msg := err.Error(); msg != v.lastErr {
			log.Printf("could not refresh the upstream CA bundle: %s", msg)
			v.lastErr = msg
		}
		return
	}
	v.lastErr = ""
	v.pool.Store(pool)
}

// run reloads the CA bundle every 10 seconds, like refreshCertificate.
func (v *upstreamVerifier) run(ctx context.Context) {
	if v.config.CAFile == "" {
		return
	}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			v.refresh()
		}
	}
}

func (v *upstreamVerifier) tlsConfig() *tls.Config {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case v == nil:
	case v.config.InsecureSkipVerify:
		config.InsecureSkipVerify = true
	case v.config.CAFile != "":
		// Disable the built-in check and redo it, including hostname
		// verification, against the current pool.
		config.InsecureSkipVerify = true
		config.VerifyConnection = func(state tls.ConnectionState) error {
			// An empty name would skip hostname matching. The transports set
			// it from the dialed host (see dialVerified), IP literals included.
			if state.ServerName == "" {
				return errors.New("upstream hostname unknown, refusing to verify without a name")
			}
			if len(state.PeerCertificates) == 0 {
				return errors.New("upstream presented no certificate")
			}
			intermediates := x509.NewCertPool()
			for _, cert := range state.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
				Roots:         v.pool.Load(),
				DNSName:       state.ServerName,
				Intermediates: intermediates,
			})
			return err
		}
	}
	return config
}

// defaultPort returns the implicit port of an upstream URL scheme.
func defaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}

// effectivePort returns the explicit port of target, or the scheme default.
func effectivePort(target *url.URL) string {
	if port := target.Port(); port != "" {
		return port
	}
	return defaultPort(target.Scheme)
}
