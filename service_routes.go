package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"
)

type serviceRoute struct {
	Origin       string
	UpstreamHost string
	AuthProfiles []string
	BackendAuth  bool
	PublicPaths  []string
	AllowedPaths []string
	DeniedPaths  []string
}

func (b *upstreamBindings) validateServiceRoutes(local bool) error {
	for prefix, route := range b.ServiceRoutes {
		if !prefixPath.MatchString(prefix) || route.BackendAuth == (len(route.AuthProfiles) > 0) {
			return fmt.Errorf("service route %q requires a prefix and exactly one authorization policy", prefix)
		}
		if _, err := upstreamOrigin(route.Origin, local); err != nil {
			return fmt.Errorf("service route %q: %w", prefix, err)
		}
		if route.UpstreamHost != "" && !dnsName.MatchString(route.UpstreamHost) {
			return fmt.Errorf("invalid upstream host for %q", prefix)
		}
		for _, profile := range route.AuthProfiles {
			if _, found := b.Authorization.Profiles[profile]; !found {
				return fmt.Errorf("unknown credential profile %q for %q", profile, prefix)
			}
		}
		for _, paths := range [][]string{route.PublicPaths, route.AllowedPaths, route.DeniedPaths} {
			for _, pattern := range paths {
				value := strings.TrimSuffix(pattern, "/*")
				if !strings.HasPrefix(value, "/") || path.Clean(value) != value ||
					strings.ContainsAny(value, "*%?#\\") {
					return fmt.Errorf("invalid path rule %q for %q", pattern, prefix)
				}
			}
		}
	}
	for _, origin := range b.BrowserOrigins {
		target, err := url.Parse(origin)
		if err != nil || !validBrowserOrigin(target, local || target.Scheme == "http") {
			return fmt.Errorf("invalid browser origin %q", origin)
		}
	}
	for i, header := range b.UpstreamRequestHeaders {
		if !httpguts.ValidHeaderFieldName(header) {
			return fmt.Errorf("invalid upstream request header %q", header)
		}
		header = http.CanonicalHeaderKey(header)
		if header == "Authorization" || header == "Host" || !httpguts.ValidTrailerHeader(header) ||
			slices.Contains(forwardedMetadata, header) || slices.Contains(b.Authorization.ResponseHeaders, header) ||
			strings.HasPrefix(header, "X-Forwarded-") || header == "Forwarded" || header == "X-Real-Ip" {
			return fmt.Errorf("cannot pass upstream request header %q", header)
		}
		b.UpstreamRequestHeaders[i] = header
	}
	return nil
}

func validBrowserOrigin(target *url.URL, local bool) bool {
	host := target.Hostname()
	loopback := local && (host == "localhost" || host == "127.0.0.1" || host == "::1")
	return (target.Scheme == "https" && dnsName.MatchString(host) || loopback && target.Scheme == "http") &&
		target.Path == "" && target.RawQuery == "" && !target.ForceQuery && target.User == nil &&
		target.Fragment == "" && target.Opaque == ""
}

func routePrefix(rawPath string) string {
	if !strings.HasPrefix(rawPath, "/") {
		return ""
	}
	prefix, _, _ := strings.Cut(rawPath[1:], "/")
	return "/" + prefix
}

func newServiceProxies(bindings upstreamBindings) map[string]*httputil.ReverseProxy {
	proxies := make(map[string]*httputil.ReverseProxy, len(bindings.ServiceRoutes))
	transport := newTransport()
	transport.ResponseHeaderTimeout = 60 * time.Second
	for prefix, route := range bindings.ServiceRoutes {
		target, _ := url.Parse(route.Origin)
		proxies[prefix] = serviceProxy(prefix, route, target, transport, bindings)
	}
	return proxies
}

func (g *gateway) serveService(w http.ResponseWriter, r *http.Request, rawPath, contractPath string, preflight bool, method string) {
	prefix := routePrefix(rawPath)
	route, found := g.bindings.ServiceRoutes[prefix]
	servicePath := stripServicePrefix(contractPath, prefix)
	if !found {
		writeStatus(w, http.StatusNotFound)
		return
	}
	backendAuthorization := route.BackendAuth || matchesServicePaths(route.PublicPaths, servicePath)
	originAllowed := slices.Contains(g.bindings.BrowserOrigins, r.Header.Get("Origin"))
	if preflight && (!backendAuthorization || originAllowed) {
		g.servePreflight(w, r, method)
		return
	}
	g.applyBrowserCORS(w, r)
	var caller identity
	if !backendAuthorization {
		var ok bool
		caller, ok = g.authorizeRequest(w, r, route.AuthProfiles)
		if !ok {
			return
		}
	}
	state := serviceRequest{identity: caller, backendAuthorization: backendAuthorization, originAllowed: originAllowed}
	g.serviceProxies[prefix].ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), serviceRequestKey{}, state)))
}

type serviceRequestKey struct{}

type serviceRequest struct {
	identity             identity
	backendAuthorization bool
	originAllowed        bool
}

func (r serviceRoute) allowsPath(value string) bool {
	return !matchesServicePaths(r.DeniedPaths, value) &&
		(len(r.AllowedPaths) == 0 || matchesServicePaths(r.AllowedPaths, value))
}

func matchesServicePaths(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if prefix, subtree := strings.CutSuffix(pattern, "/*"); subtree {
			if value == prefix || strings.HasPrefix(value, prefix+"/") {
				return true
			}
		} else if value == pattern {
			return true
		}
	}
	return false
}

func serviceProxy(prefix string, route serviceRoute, target *url.URL, transport http.RoundTripper, bindings upstreamBindings) *httputil.ReverseProxy {
	requestHeaders := slices.Clone(bindings.UpstreamRequestHeaders)
	if route.BackendAuth {
		requestHeaders = append(requestHeaders, bindings.Authorization.RequestHeaders...)
	}
	return &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			if route.UpstreamHost != "" {
				r.Out.Host = route.UpstreamHost
			}
			r.Out.URL.Path = stripServicePrefix(r.In.URL.Path, prefix)
			if r.In.URL.RawPath != "" {
				r.Out.URL.RawPath = stripServicePrefix(r.In.URL.RawPath, prefix)
			}
			stripForwardedIdentity(r.Out.Header, bindings.Authorization)
			for _, header := range requestHeaders {
				if values := r.In.Header.Values(header); len(values) > 0 {
					r.Out.Header[header] = values
				}
			}
			r.Out.Header.Del("X-Real-Ip")
			r.Out.Header.Del(bindings.Debug.RequestHeader)
			state := r.In.Context().Value(serviceRequestKey{}).(serviceRequest)
			if !state.backendAuthorization {
				r.Out.Header.Del("Authorization")
				for header, values := range state.identity.headers {
					r.Out.Header[header] = values
				}
			}
			if route.BackendAuth {
				setOriginalRequestHeaders(r.Out.Header, r.In, bindings.Hostname)
			}
		},
		ModifyResponse: func(response *http.Response) error {
			state := response.Request.Context().Value(serviceRequestKey{}).(serviceRequest)
			if state.originAllowed || !state.backendAuthorization && len(bindings.BrowserOrigins) != 0 {
				for _, name := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"} {
					response.Header.Del(name)
				}
			}
			rewriteServiceLocation(response, prefix, target, route.UpstreamHost)
			rewriteServiceCookies(response.Header, prefix)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			writeStatus(w, http.StatusBadGateway)
		},
	}
}

func stripServicePrefix(path, prefix string) string {
	suffix := strings.TrimPrefix(path, prefix)
	if suffix == "" {
		return "/"
	}
	return suffix
}

func rewriteServiceLocation(response *http.Response, prefix string, target *url.URL, upstreamHost string) {
	value := response.Header.Get("Location")
	if value == "" {
		return
	}
	ref, err := response.Request.URL.Parse(value)
	if err != nil {
		return
	}
	sameService := strings.EqualFold(ref.Host, target.Host) && ref.Scheme == target.Scheme
	legacyHost := upstreamHost != "" && strings.EqualFold(ref.Host, upstreamHost) && ref.Scheme == "https"
	if !sameService && !legacyHost {
		return
	}
	ref.Scheme, ref.Host, ref.User = "", "", nil
	ref.Path = prefix + ref.Path
	if ref.RawPath != "" {
		ref.RawPath = prefix + ref.RawPath
	}
	response.Header.Set("Location", ref.String())
}

func rewriteServiceCookies(headers http.Header, prefix string) {
	raw := headers.Values("Set-Cookie")
	if len(raw) == 0 {
		return
	}
	headers.Del("Set-Cookie")
	for _, value := range raw {
		cookie, err := http.ParseSetCookie(value)
		if err != nil || strings.HasPrefix(cookie.Name, "__Host-") {
			continue
		}
		cookie.Domain = ""
		if strings.HasPrefix(cookie.Path, "/") {
			cookie.Path = prefix + cookie.Path
		}
		headers.Add("Set-Cookie", cookie.String())
	}
}

func (g *gateway) applyBrowserCORS(w http.ResponseWriter, r *http.Request) bool {
	if len(g.bindings.BrowserOrigins) == 0 {
		return false
	}
	w.Header().Add("Vary", "Origin")
	origin := r.Header.Get("Origin")
	if !slices.Contains(g.bindings.BrowserOrigins, origin) {
		return false
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	return true
}

func (g *gateway) servePreflight(w http.ResponseWriter, r *http.Request, method string) {
	w.Header().Add("Vary", "Access-Control-Request-Method")
	w.Header().Add("Vary", "Access-Control-Request-Headers")
	if !g.applyBrowserCORS(w, r) {
		writeStatus(w, http.StatusForbidden)
		return
	}
	w.Header().Set("Access-Control-Allow-Methods", method)
	if headers := r.Header.Get("Access-Control-Request-Headers"); headers != "" {
		w.Header().Set("Access-Control-Allow-Headers", headers)
	}
	writeStatus(w, http.StatusNoContent)
}

func stripForwardedIdentity(headers http.Header, settings authorizationConfig) {
	for header := range headers {
		if slices.ContainsFunc(settings.StripHeaderPrefixes, func(prefix string) bool {
			return len(header) >= len(prefix) && strings.EqualFold(header[:len(prefix)], prefix)
		}) {
			headers.Del(header)
		}
	}
	for _, names := range [][]string{forwardedMetadata, settings.ResponseHeaders, settings.RequestHeaders} {
		for _, name := range names {
			headers.Del(name)
		}
	}
}

func matchesPathTemplate(template, path string) bool {
	templateParts, pathParts := strings.Split(template, "/"), strings.Split(path, "/")
	if len(templateParts) != len(pathParts) {
		return false
	}
	for i, part := range templateParts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") && pathParts[i] != "" {
			continue
		}
		if part != pathParts[i] {
			return false
		}
	}
	return true
}
