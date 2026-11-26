package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"
)

// authorizationConfig locates the authorizer at authz+Path. RequestHeaders
// are forwarded to it, ResponseHeaders are the identity it returns and Darban
// projects upstream, and StripHeaderPrefixes are removed from every request.
type authorizationConfig struct {
	Path                string
	RequestHeaders      []string
	ResponseHeaders     []string
	StripHeaderPrefixes []string
}

type debugConfig struct {
	RequestHeader  string
	RequiredHeader string
	RequiredValue  string
}

// identity is the caller as the authorizer described it. authorized is false
// when the gateway did not authorize the request, whose Authorization then
// goes upstream unchanged.
type identity struct {
	authorized bool
	headers    http.Header
}

type identityKey struct{}

var forwardedMetadata = []string{"X-Original-Method", "X-Original-URI", "X-Original-URL"}

// hopByHopHeaders belong to one connection, so they are never copied to the
// authorizer or an upstream.
var hopByHopHeaders = []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Proxy-Connection", "Te",
	"Trailer", "Transfer-Encoding", "Upgrade"}

func (a *authorizationConfig) validate(origin string) error {
	if (origin != "" || a.Path != "") && (origin == "" || a.Path != "/" && !docPath.MatchString(a.Path)) {
		return errors.New("authorization requires a private origin and a path")
	}
	for _, headers := range [][]string{a.RequestHeaders, a.ResponseHeaders, a.StripHeaderPrefixes} {
		for i, name := range headers {
			if !httpguts.ValidHeaderFieldName(name) {
				return fmt.Errorf("invalid authorization header or prefix %q", name)
			}
			headers[i] = http.CanonicalHeaderKey(name)
		}
	}
	for _, name := range a.RequestHeaders {
		if slices.Contains(hopByHopHeaders, name) {
			return fmt.Errorf("authorization cannot forward hop-by-hop header %q", name)
		}
	}
	for _, name := range a.ResponseHeaders {
		if name == "Authorization" || name == "Host" || slices.Contains(forwardedMetadata, name) || !httpguts.ValidTrailerHeader(name) {
			return fmt.Errorf("authorization cannot project header %q", name)
		}
	}
	return nil
}

// identityHeader reports whether a header names an identity: one the
// authorizer returns, or one with a stripped prefix.
func (a authorizationConfig) identityHeader(name string) bool {
	return slices.Contains(a.ResponseHeaders, http.CanonicalHeaderKey(name)) ||
		slices.ContainsFunc(a.StripHeaderPrefixes, func(prefix string) bool {
			return len(name) >= len(prefix) && strings.EqualFold(name[:len(prefix)], prefix)
		})
}

func (d *debugConfig) validate(authorization authorizationConfig) error {
	if *d == (debugConfig{}) {
		return nil
	}
	d.RequestHeader = http.CanonicalHeaderKey(d.RequestHeader)
	d.RequiredHeader = http.CanonicalHeaderKey(d.RequiredHeader)
	if !httpguts.ValidHeaderFieldName(d.RequestHeader) || !slices.Contains(authorization.ResponseHeaders, d.RequiredHeader) || d.RequiredValue == "" {
		return errors.New("debug routing requires a request header and a value from a projected authorization header")
	}
	return nil
}

// authorize asks the authorizer about the caller's credentials as sent,
// whatever their scheme. A 2xx answer's identity headers are trusted as
// returned.
func (g *gateway) authorize(ctx context.Context, authorization string, original *http.Request) (identity, int, string) {
	settings := g.bindings.Authorization
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.bindings.Authz+settings.Path, nil)
	if err != nil {
		return identity{}, http.StatusServiceUnavailable, ""
	}
	for _, name := range settings.RequestHeaders {
		if value := original.Header.Get(name); value != "" {
			req.Header.Set(name, value)
		}
	}
	req.Header.Set("Authorization", authorization)
	setOriginalRequestHeaders(req.Header, original)
	res, err := g.authClient.Do(req)
	if err != nil {
		return identity{}, http.StatusServiceUnavailable, ""
	}
	defer res.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(res.Body, 65536)); err != nil {
		return identity{}, http.StatusServiceUnavailable, ""
	}
	switch code := res.StatusCode; {
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		return identity{}, code, ""
	case code == http.StatusTooManyRequests:
		return identity{}, code, res.Header.Get("Retry-After")
	case code >= 200 && code < 300:
		caller := identity{authorized: true, headers: make(http.Header)}
		for _, name := range settings.ResponseHeaders {
			values := res.Header.Values(name)
			if len(values) == 1 && values[0] != "" {
				caller.headers.Set(name, values[0])
			}
		}
		return caller, 0, ""
	}
	return identity{}, http.StatusServiceUnavailable, ""
}

func setOriginalRequestHeaders(headers http.Header, r *http.Request) {
	headers.Set("X-Original-Method", r.Method)
	headers.Set("X-Original-URI", r.RequestURI)
	headers.Set("X-Original-URL", "https://"+r.Host+r.RequestURI)
}

// authorizeRequest authorizes a request at the gateway. It needs exactly one
// non-empty Authorization header, which goes to the authorizer unchanged.
func (g *gateway) authorizeRequest(w http.ResponseWriter, r *http.Request) (identity, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
		writeStatus(w, http.StatusUnauthorized)
		return identity{}, false
	}
	authorization := values[0]
	if len(authorization) > 8192 {
		writeStatus(w, http.StatusRequestHeaderFieldsTooLarge)
		return identity{}, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	caller, status, retry := g.authorize(ctx, authorization, r)
	if status != 0 {
		if retry != "" {
			w.Header().Set("Retry-After", retry)
		}
		writeStatus(w, status)
		return identity{}, false
	}
	return caller, true
}
