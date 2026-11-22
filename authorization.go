package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"golang.org/x/net/http/httpguts"
)

type authorizationConfig struct {
	Path                string
	RequestHeaders      []string
	ResponseHeaders     []string
	StripHeaderPrefixes []string
	Profiles            map[string]credentialProfile
}

type credentialProfile struct {
	Scheme          string
	RequiredHeaders []string
}

type debugConfig struct {
	RequestHeader  string
	RequiredHeader string
	RequiredValue  string
}

type identity struct {
	headers http.Header
}

type identityKey struct{}

var forwardedMetadata = []string{"X-Original-Method", "X-Original-URI", "X-Original-URL"}

func (a *authorizationConfig) validate(origin string) error {
	if (origin != "" || len(a.Profiles) != 0) && (origin == "" || a.Path != "/" && !docPath.MatchString(a.Path)) {
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
	for _, name := range a.ResponseHeaders {
		if name == "Authorization" || name == "Host" || slices.Contains(forwardedMetadata, name) || !httpguts.ValidTrailerHeader(name) {
			return fmt.Errorf("authorization cannot project header %q", name)
		}
	}
	for name, profile := range a.Profiles {
		if !componentID.MatchString(name) || !httpguts.ValidHeaderFieldName(profile.Scheme) {
			return fmt.Errorf("invalid credential profile %q", name)
		}
		profile.Scheme = strings.ToLower(profile.Scheme)
		for i, header := range profile.RequiredHeaders {
			canonical := http.CanonicalHeaderKey(header)
			if !slices.Contains(a.ResponseHeaders, canonical) {
				return fmt.Errorf("credential profile %q requires an unprojected header %q", name, header)
			}
			profile.RequiredHeaders[i] = canonical
		}
		a.Profiles[name] = profile
	}
	return nil
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

func credentialScheme(authorization string) string {
	prefix, value, ok := strings.Cut(authorization, " ")
	if !ok || value == "" {
		return ""
	}
	return strings.ToLower(prefix)
}

func (g *gateway) authorize(ctx context.Context, profile credentialProfile, authorization string, original *http.Request) (identity, int, string) {
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
	req.Header.Set("X-Original-Method", original.Method)
	req.Header.Set("X-Original-URI", original.RequestURI)
	req.Header.Set("X-Original-URL", "https://"+g.bindings.Hostname+original.RequestURI)
	res, err := g.authClient.Do(req)
	if err != nil {
		return identity{}, http.StatusServiceUnavailable, ""
	}
	defer res.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(res.Body, 65536)); err != nil {
		return identity{}, http.StatusServiceUnavailable, ""
	}
	switch res.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return identity{}, res.StatusCode, ""
	case http.StatusTooManyRequests:
		return identity{}, res.StatusCode, res.Header.Get("Retry-After")
	case http.StatusOK, http.StatusNoContent:
		caller := identity{headers: make(http.Header)}
		for _, name := range settings.ResponseHeaders {
			values := res.Header.Values(name)
			if len(values) == 1 && values[0] != "" {
				caller.headers.Set(name, values[0])
			}
		}
		for _, name := range profile.RequiredHeaders {
			if caller.headers.Get(name) == "" {
				return identity{}, http.StatusServiceUnavailable, ""
			}
		}
		return caller, 0, ""
	}
	return identity{}, http.StatusServiceUnavailable, ""
}
