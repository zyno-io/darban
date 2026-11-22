package main

import (
	"context"
	"crypto/tls"
	"log"
	"sync/atomic"
	"time"
)

func refreshCertificate(ctx context.Context, certPath, keyPath string, current *atomic.Pointer[tls.Certificate]) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	var failed bool
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			if !failed {
				log.Print("could not refresh the gateway TLS certificate")
			}
			failed = true
			continue
		}
		failed = false
		current.Store(&cert)
	}
}
