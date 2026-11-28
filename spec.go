package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
)

// specDocument is one combined OpenAPI document as served: its bytes and
// their gzip form, each with a strong ETag of its own.
type specDocument struct {
	body, gzipped  []byte
	etag, gzipETag string
	mediaType      string
}

func newSpecDocument(body []byte, mediaType string) specDocument {
	sum := sha256.Sum256(body)
	tag := hex.EncodeToString(sum[:16])
	var compressed bytes.Buffer
	writer, _ := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	writer.Write(body)
	writer.Close()
	return specDocument{body: body, gzipped: compressed.Bytes(), etag: `"` + tag + `"`, gzipETag: `"` + tag + `-gzip"`, mediaType: mediaType}
}

// spec returns the YAML or JSON document of the snapshot. Both are
// compressed once per snapshot, on first use.
func (s *snapshot) spec(json bool) specDocument {
	s.specsOnce.Do(func() {
		s.specs[0] = newSpecDocument(s.specYAML, "application/yaml")
		if s.specJSON != nil {
			s.specs[1] = newSpecDocument(s.specJSON, "application/json")
		}
	})
	if json {
		return s.specs[1]
	}
	return s.specs[0]
}

// serveSpec serves a combined OpenAPI document. It is public: any origin may
// read it, without credentials, so CORS allows every origin and never
// credentials. A client that accepts gzip gets the precompressed form, and
// one that has the current version gets 304.
func (g *gateway) serveSpec(active *snapshot, w http.ResponseWriter, r *http.Request, json bool) {
	headers := w.Header()
	headers.Set("Access-Control-Allow-Origin", "*")
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	case http.MethodOptions:
		headers.Set("Allow", "GET, HEAD, OPTIONS")
		if r.Header.Get("Access-Control-Request-Method") != "" {
			headers.Set("Access-Control-Allow-Methods", "GET, HEAD")
			if requested := r.Header.Get("Access-Control-Request-Headers"); requested != "" {
				headers.Set("Access-Control-Allow-Headers", requested)
			}
			headers.Set("Access-Control-Max-Age", "86400")
			headers.Add("Vary", "Access-Control-Request-Headers")
		}
		writeStatus(w, http.StatusNoContent)
		return
	default:
		headers.Set("Allow", "GET, HEAD, OPTIONS")
		writeStatus(w, http.StatusMethodNotAllowed)
		return
	}
	document := active.spec(json)
	body, etag := document.body, document.etag
	compressed := acceptsGzip(r.Header.Values("Accept-Encoding"))
	if compressed {
		body, etag = document.gzipped, document.gzipETag
	}
	headers.Set("Vary", "Accept-Encoding")
	headers.Set("Cache-Control", g.bindings.OpenAPI.cacheControl())
	headers.Set("ETag", etag)
	if noneMatch(r.Header.Values("If-None-Match"), etag) {
		writeStatus(w, http.StatusNotModified)
		return
	}
	headers.Set("Content-Type", document.mediaType)
	if compressed {
		headers.Set("Content-Encoding", "gzip")
	}
	headers.Set("Content-Length", strconv.Itoa(len(body)))
	writeStatus(w, http.StatusOK)
	if r.Method == http.MethodGet {
		w.Write(body)
	}
}

// acceptsGzip reports whether Accept-Encoding allows gzip: gzip or x-gzip
// with a nonzero quality, or * with one when gzip is not named.
func acceptsGzip(values []string) bool {
	named, wildcard := -1, -1
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			coding, params, _ := strings.Cut(strings.TrimSpace(item), ";")
			allowed := 1
			for _, param := range strings.Split(params, ";") {
				name, q, ok := strings.Cut(strings.TrimSpace(param), "=")
				if ok && strings.EqualFold(strings.TrimSpace(name), "q") {
					if quality, err := strconv.ParseFloat(strings.TrimSpace(q), 64); err != nil || quality <= 0 {
						allowed = 0
					}
				}
			}
			switch strings.ToLower(strings.TrimSpace(coding)) {
			case "gzip", "x-gzip":
				if named != 1 {
					named = allowed
				}
			case "*":
				if wildcard != 1 {
					wildcard = allowed
				}
			}
		}
	}
	if named >= 0 {
		return named == 1
	}
	return wildcard == 1
}

// noneMatch reports whether If-None-Match names the ETag, by the weak
// comparison RFC 9110 requires for it, or is *.
func noneMatch(values []string, etag string) bool {
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			item = strings.TrimPrefix(strings.TrimSpace(item), "W/")
			if item == "*" || item == etag {
				return true
			}
		}
	}
	return false
}
