package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"maps"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"
)

type serviceRoute struct {
	Origin                    string
	UpstreamHost              string
	LegacyHosts               []string
	BackendAuth               bool
	BackendCORS               bool
	ForwardTrustedClientIP    bool
	PublicPaths               []string
	AllowedPaths              []string
	DeniedPaths               []string
	LongResponsePaths         []string
	LongResponseHeaderTimeout string
	// ForwardRequestHeaders are caller headers a backendAuth route sends
	// upstream although they name an identity, such as tenant selectors.
	ForwardRequestHeaders []string
}

func (b *upstreamBindings) validateServiceRoutes(local bool) error {
	hosts := map[string]bool{b.Hostname: true}
	for prefix, route := range b.ServiceRoutes {
		if !prefixPath.MatchString(prefix) {
			return fmt.Errorf("invalid service route prefix %q", prefix)
		}
		if !route.BackendAuth && b.Authz == "" {
			return fmt.Errorf("service route %q authorizes at the gateway, which needs authz (or set backendAuth)", prefix)
		}
		if _, err := upstreamOrigin(route.Origin, local); err != nil {
			return fmt.Errorf("service route %q: %w", prefix, err)
		}
		if route.UpstreamHost != "" && !dnsName.MatchString(route.UpstreamHost) {
			return fmt.Errorf("invalid upstream host for %q", prefix)
		}
		for _, host := range route.LegacyHosts {
			if !dnsName.MatchString(host) || hosts[host] {
				return fmt.Errorf("invalid or duplicate legacy host %q for %q", host, prefix)
			}
			hosts[host] = true
		}
		if route.LongResponseHeaderTimeout != "" || len(route.LongResponsePaths) > 0 {
			timeout, err := time.ParseDuration(route.LongResponseHeaderTimeout)
			if err != nil || timeout <= 0 || len(route.LongResponsePaths) == 0 {
				return fmt.Errorf("service route %q requires a positive duration and paths for extended responses", prefix)
			}
		}
		for i, header := range route.ForwardRequestHeaders {
			canonical := http.CanonicalHeaderKey(header)
			if !route.BackendAuth || !httpguts.ValidHeaderFieldName(header) || canonical == "Authorization" || canonical == "Host" ||
				slices.Contains(forwardedMetadata, canonical) || strings.HasPrefix(canonical, "X-Forwarded-") || canonical == "Forwarded" ||
				canonical == "X-Real-Ip" || slices.Contains(route.ForwardRequestHeaders[:i], header) {
				return fmt.Errorf("service route %q cannot forward request header %q (forwardRequestHeaders needs backendAuth)", prefix, header)
			}
			route.ForwardRequestHeaders[i] = canonical
		}
		for _, paths := range [][]string{route.PublicPaths, route.AllowedPaths, route.DeniedPaths, route.LongResponsePaths} {
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

// canonicalPath reports whether a request path, as sent and as decoded, has
// one meaning: no empty, . or .. segment (also when encoded), no encoded / or
// \, no \, and nothing that path.Clean changes other than one trailing slash.
func canonicalPath(raw, decoded string) bool {
	lower := strings.ToLower(raw)
	if strings.Contains(raw, "//") || strings.Contains(raw, `\`) ||
		strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return false
	}
	for _, segment := range strings.Split(raw, "/") {
		if value, err := url.PathUnescape(segment); err != nil || value == "." || value == ".." {
			return false
		}
	}
	cleaned := path.Clean(decoded)
	return decoded == cleaned || decoded == cleaned+"/"
}

func routePrefix(rawPath string) string {
	if !strings.HasPrefix(rawPath, "/") {
		return ""
	}
	prefix, _, _ := strings.Cut(rawPath[1:], "/")
	return "/" + prefix
}

func newServiceProxies(bindings upstreamBindings, tlsConfig *tls.Config) map[string]*httputil.ReverseProxy {
	proxies := make(map[string]*httputil.ReverseProxy, len(bindings.ServiceRoutes))
	transport := newTransport(tlsConfig)
	transport.ResponseHeaderTimeout = 60 * time.Second
	for prefix, route := range bindings.ServiceRoutes {
		target, _ := url.Parse(route.Origin)
		var roundTripper http.RoundTripper = transport
		if len(route.LongResponsePaths) > 0 {
			longResponse := transport.Clone()
			longResponse.ResponseHeaderTimeout, _ = time.ParseDuration(route.LongResponseHeaderTimeout)
			roundTripper = serviceTransport{normal: transport, longResponse: longResponse, longPaths: route.LongResponsePaths}
		}
		proxies[prefix] = serviceProxy(prefix, route, target, roundTripper, bindings)
	}
	return proxies
}

type serviceTransport struct {
	normal, longResponse *http.Transport
	longPaths            []string
}

func (t serviceTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if matchesServicePaths(t.longPaths, path.Clean(r.URL.Path)) {
		return t.longResponse.RoundTrip(r)
	}
	return t.normal.RoundTrip(r)
}

// serveService proxies a request through a direct route's transport. With
// backendAuthorization the backend authorizes the request and gets its
// Authorization; otherwise the gateway does and the backend gets the identity.
// upstreamMethod, when set, replaces the method sent upstream.
func (g *gateway) serveService(w http.ResponseWriter, r *http.Request, prefix string, backendAuthorization, preflight bool, method, upstreamMethod string) {
	route, found := g.bindings.ServiceRoutes[prefix]
	if !found {
		writeStatus(w, http.StatusNotFound)
		return
	}
	originAllowed := false
	if !route.BackendCORS {
		originAllowed = slices.Contains(g.bindings.BrowserOrigins, r.Header.Get("Origin"))
		if preflight && (!backendAuthorization || originAllowed) {
			g.servePreflight(w, r, method)
			return
		}
		g.applyBrowserCORS(w, r)
	}
	var clientIP string
	if route.ForwardTrustedClientIP {
		values := r.Header.Values("X-Real-IP")
		if len(values) != 1 {
			writeStatus(w, http.StatusServiceUnavailable)
			return
		}
		address, err := netip.ParseAddr(strings.TrimSpace(values[0]))
		if err != nil || address.Zone() != "" {
			writeStatus(w, http.StatusServiceUnavailable)
			return
		}
		clientIP = address.Unmap().String()
	}
	var caller identity
	if !backendAuthorization {
		var ok bool
		caller, ok = g.authorizeRequest(w, r)
		if !ok {
			return
		}
	}
	state := serviceRequest{
		identity: caller, backendAuthorization: backendAuthorization, originAllowed: originAllowed,
		legacy: r.Host != g.bindings.Hostname, clientIP: clientIP, method: upstreamMethod,
	}
	g.serviceProxies[prefix].ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), serviceRequestKey{}, state)))
}

type serviceRequestKey struct{}

type serviceRequest struct {
	identity             identity
	backendAuthorization bool
	originAllowed        bool
	legacy               bool
	clientIP             string
	method               string
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
		// The backend authenticates, so it gets the authorizer's request
		// headers, but a caller's copy of an identity header only when the
		// route lists it.
		for _, header := range bindings.Authorization.RequestHeaders {
			if !bindings.Authorization.identityHeader(header) {
				requestHeaders = append(requestHeaders, header)
			}
		}
		requestHeaders = append(requestHeaders, route.ForwardRequestHeaders...)
	}
	return &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			state := r.In.Context().Value(serviceRequestKey{}).(serviceRequest)
			if state.method != "" {
				r.Out.Method = state.method
			}
			if state.legacy {
				r.Out.Host = r.In.Host
				r.Out.URL.RawQuery = r.In.URL.RawQuery
			} else {
				if route.UpstreamHost != "" {
					r.Out.Host = route.UpstreamHost
				}
				r.Out.URL.Path = stripServicePrefix(r.In.URL.Path, prefix)
			}
			// Send the decoded path that was gated, re-encoded by Go's url.URL
			// path escaping, rather than the caller's spelling of it. A backend
			// that routes on the encoded path would otherwise see /m%65 where
			// the gateway checked /me.
			r.Out.URL.RawPath = ""
			stripForwardedIdentity(r.Out.Header, bindings.Authorization)
			for _, header := range requestHeaders {
				if values := r.In.Header.Values(header); len(values) > 0 {
					r.Out.Header[header] = values
				}
			}
			r.Out.Header.Del("X-Real-Ip")
			if state.clientIP != "" {
				r.Out.Header.Set("X-Real-Ip", state.clientIP)
			}
			r.Out.Header.Del(bindings.Debug.RequestHeader)
			if !state.backendAuthorization {
				r.Out.Header.Del("Authorization")
				for header, values := range state.identity.headers {
					r.Out.Header[header] = values
				}
			}
			if route.BackendAuth {
				setOriginalRequestHeaders(r.Out.Header, r.In)
			}
		},
		ModifyResponse: func(response *http.Response) error {
			state := response.Request.Context().Value(serviceRequestKey{}).(serviceRequest)
			if !route.BackendCORS && (state.originAllowed || !state.backendAuthorization && len(bindings.BrowserOrigins) != 0) {
				for _, name := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"} {
					response.Header.Del(name)
				}
			}
			if !state.legacy {
				rewriteServiceLocation(response, prefix, target, route.UpstreamHost)
				rewriteServiceCookies(response.Header, prefix)
			}
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
			// Auth may use the content type to validate a signed request. The
			// backend must still receive the content type of the original body.
			if name != "Content-Type" {
				headers.Del(name)
			}
		}
	}
}

// omitRefusedOperations removes the documented operations of a docs-only
// service that its direct route would refuse, so the document does not promise
// them, and returns a warning for each. A template is judged against every
// path it stands for: a denied pattern refuses it when it may match one of
// them, and an allowed or public pattern admits it only when it covers all.
func omitRefusedOperations(native map[operationKey]sourceOperation, route serviceRoute) []string {
	var warnings []string
	for _, key := range slices.SortedFunc(maps.Keys(native), compareOperationKeys) {
		op := native[key]
		if op.visibility != visibilityPublic {
			continue
		}
		var reason string
		switch {
		case templateMatches(route.DeniedPaths, op.path, false):
			reason = "the direct route's deniedPaths refuse its path"
		case len(route.AllowedPaths) > 0 && !templateMatches(route.AllowedPaths, op.path, true):
			reason = "the direct route's allowedPaths do not cover its path"
		case len(op.requirements) == 0 && !route.BackendAuth && !templateMatches(route.PublicPaths, op.path, true):
			reason = "it is anonymous, but the direct route's publicPaths do not cover its path"
		default:
			continue
		}
		delete(native, key)
		warnings = append(warnings, fmt.Sprintf("%s %s omitted from the document: %s", key.method, key.path, reason))
	}
	return warnings
}

// templateMatches reports whether one of the service path patterns matches
// every path the template stands for (all), or at least one of them.
func templateMatches(patterns []string, template string, all bool) bool {
	segments := func(path string) []string {
		if path == "/" {
			return nil
		}
		return strings.Split(path[1:], "/")
	}
	have := segments(template)
	for _, pattern := range patterns {
		prefix, subtree := strings.CutSuffix(pattern, "/*")
		want := segments(prefix)
		if len(have) < len(want) || !subtree && len(have) != len(want) {
			continue
		}
		matched := true
		for i, segment := range want {
			parameter := strings.HasPrefix(have[i], "{")
			if parameter && all || !parameter && have[i] != segment {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}
