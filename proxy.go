package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http/httpguts"
)

// clientIPConfig says where the caller's IP comes from. Header, X-Real-IP by
// default, is read only from a peer in TrustedProxies, every peer by default,
// which suits a listener only an ingress that overwrites the header can
// reach. A request from any other peer, or without exactly one valid address
// in the header, gets the peer's own address.
type clientIPConfig struct {
	Header         string
	TrustedProxies []string
	proxies        []netip.Prefix
}

func (c clientIPConfig) header() string {
	if c.Header == "" {
		return "X-Real-Ip"
	}
	return http.CanonicalHeaderKey(c.Header)
}

func (c *clientIPConfig) validate() error {
	if c.Header != "" {
		header := http.CanonicalHeaderKey(c.Header)
		if !httpguts.ValidHeaderFieldName(c.Header) || header == "Authorization" || header == "Host" || header == "Forwarded" {
			return fmt.Errorf("invalid clientIP.header %q", c.Header)
		}
	}
	c.proxies = nil
	for _, value := range c.TrustedProxies {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addressErr := netip.ParseAddr(value)
			if addressErr != nil {
				return fmt.Errorf("invalid clientIP.trustedProxies entry %q", value)
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		c.proxies = append(c.proxies, prefix.Masked())
	}
	return nil
}

// clientIP returns the caller's address for a request.
func (c clientIPConfig) clientIP(r *http.Request) string {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	var address netip.Addr
	if err == nil {
		address = peer.Addr().Unmap()
	} else if parsed, err := netip.ParseAddr(r.RemoteAddr); err == nil {
		address = parsed.Unmap()
	}
	trusted := len(c.proxies) == 0 || slices.ContainsFunc(c.proxies, func(prefix netip.Prefix) bool { return prefix.Contains(address) })
	if values := r.Header.Values(c.header()); trusted && len(values) == 1 {
		if sent, err := netip.ParseAddr(strings.TrimSpace(values[0])); err == nil && sent.Zone() == "" {
			return sent.Unmap().String()
		}
	}
	if !address.IsValid() {
		return ""
	}
	return address.String()
}

// validateRequestHeaders checks the browser origins and the request headers
// every upstream gets.
func (b *upstreamBindings) validateRequestHeaders(local bool) error {
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
		if !httpguts.ValidTrailerHeader(header) || managedHeader(header, *b) || slices.Contains(b.Authorization.ResponseHeaders, header) {
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

// serviceProxy sends a service's requests upstream: its own operations, its
// extra routes, and the rewrites that target it. debug sends them to its
// debug origin, with the same settings.
type serviceProxy struct {
	binding serviceBinding
	proxy   *httputil.ReverseProxy
	debug   *httputil.ReverseProxy
}

// transports shares one upstream transport per kind and response-header
// timeout, so a new snapshot reuses open connections.
type transports struct {
	mu    sync.Mutex
	base  *http.Transport
	byKey map[string]*http.Transport
}

const regularResponseHeaderTimeout = 60 * time.Second

func (t *transports) get(timeout time.Duration, debug bool) *http.Transport {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := fmt.Sprintf("%v %v", timeout, debug)
	if transport := t.byKey[key]; transport != nil {
		return transport
	}
	transport := t.base.Clone()
	transport.ResponseHeaderTimeout = timeout
	// Avoid implicit retries of debug requests with an Idempotency-Key.
	transport.DisableKeepAlives = debug
	if t.byKey == nil {
		t.byKey = make(map[string]*http.Transport)
	}
	t.byKey[key] = transport
	return transport
}

// roundTripper picks the regular or the long-response transport by upstream
// path.
type roundTripper struct {
	regular, long *http.Transport
	longPaths     []string
}

func (t roundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.long != nil && matchesServicePaths(t.longPaths, path.Clean(r.URL.Path)) {
		return t.long.RoundTrip(r)
	}
	return t.regular.RoundTrip(r)
}

func (g *gateway) newServiceProxy(binding serviceBinding) *serviceProxy {
	build := func(origin string, debug bool) *httputil.ReverseProxy {
		// Validated when the contract or the bindings were loaded.
		target, _ := url.Parse(origin)
		transport := roundTripper{regular: g.transports.get(regularResponseHeaderTimeout, debug), longPaths: binding.LongResponsePaths}
		if len(binding.LongResponsePaths) > 0 {
			timeout, _ := time.ParseDuration(binding.LongResponseHeaderTimeout)
			transport.long = g.transports.get(timeout, debug)
		}
		return g.reverseProxy(binding, target, transport)
	}
	proxy := &serviceProxy{binding: binding, proxy: build(binding.Origin, false)}
	if binding.DebugOrigin != "" {
		proxy.debug = build(binding.DebugOrigin, true)
	}
	return proxy
}

type serviceRequestKey struct{}

// serviceRequest is how one request goes upstream.
type serviceRequest struct {
	identity             identity
	backendAuthorization bool
	originAllowed        bool
	legacy               bool
	clientIP             string
	// method, when set, replaces the method sent upstream. path is the
	// decoded upstream path.
	method string
	path   string
}

func (g *gateway) reverseProxy(binding serviceBinding, target *url.URL, transport http.RoundTripper) *httputil.ReverseProxy {
	bindings := g.bindings
	requestHeaders := slices.Clone(bindings.UpstreamRequestHeaders)
	if binding.BackendAuth {
		// The backend authenticates, so it gets the authorizer's request
		// headers, but a caller's copy of an identity header only when the
		// service lists it.
		for _, header := range bindings.Authorization.RequestHeaders {
			if !bindings.Authorization.identityHeader(header) {
				requestHeaders = append(requestHeaders, header)
			}
		}
		requestHeaders = append(requestHeaders, binding.ForwardRequestHeaders...)
	}
	clientIPHeader := bindings.ClientIP.header()
	return &httputil.ReverseProxy{
		Transport: transport,
		// ReverseProxy removes Forwarded and some X-Forwarded-* before Rewrite;
		// Rewrite removes the rest and every other client-address header.
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			state := r.In.Context().Value(serviceRequestKey{}).(serviceRequest)
			if state.method != "" {
				r.Out.Method = state.method
			}
			switch {
			case state.legacy:
				r.Out.Host = r.In.Host
			case binding.UpstreamHost != "":
				r.Out.Host = binding.UpstreamHost
			}
			// Send the decoded path that was matched, re-encoded by Go's url.URL
			// path escaping, rather than the caller's spelling of it.
			r.Out.URL.Path, r.Out.URL.RawPath = state.path, ""
			r.Out.URL.RawQuery = r.In.URL.RawQuery
			stripForwardedIdentity(r.Out.Header, bindings.Authorization)
			for _, header := range requestHeaders {
				if values := r.In.Header.Values(header); len(values) > 0 {
					r.Out.Header[header] = values
				}
			}
			r.Out.Header.Del(bindings.Debug.RequestHeader)
			if !state.backendAuthorization {
				r.Out.Header.Del("Authorization")
				for header, values := range state.identity.headers {
					r.Out.Header[header] = values
				}
			}
			if binding.BackendAuth {
				setOriginalRequestHeaders(r.Out.Header, r.In)
			}
			// Last, so that no copied or projected header can set it.
			stripClientAddress(r.Out.Header, clientIPHeader)
			if state.clientIP != "" {
				r.Out.Header.Set("X-Real-Ip", state.clientIP)
			}
		},
		ModifyResponse: func(response *http.Response) error {
			state := response.Request.Context().Value(serviceRequestKey{}).(serviceRequest)
			if !binding.BackendCORS && (state.originAllowed || !state.backendAuthorization && len(bindings.BrowserOrigins) != 0) {
				for _, name := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"} {
					response.Header.Del(name)
				}
			}
			if !state.legacy {
				rewriteServiceLocation(response, binding, target)
				rewriteServiceCookies(response.Header, binding)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			writeStatus(w, http.StatusBadGateway)
		},
	}
}

// serveService sends a matched request to its service. backendAuthorization
// leaves authorization to the backend, which then gets the caller's
// Authorization; otherwise the gateway authorizes and the backend gets the
// identity. upstreamMethod, when set, replaces the method sent upstream.
func (g *gateway) serveService(w http.ResponseWriter, r *http.Request, proxy *serviceProxy, upstreamPath string,
	backendAuthorization, preflight bool, method, upstreamMethod string) {
	binding := proxy.binding
	originAllowed := false
	if !binding.BackendCORS {
		originAllowed = slices.Contains(g.bindings.BrowserOrigins, r.Header.Get("Origin"))
		if preflight && (!backendAuthorization || originAllowed) {
			g.servePreflight(w, r, method)
			return
		}
		g.applyBrowserCORS(w, r)
	}
	var caller identity
	if !backendAuthorization {
		var ok bool
		if caller, ok = g.authorizeRequest(w, r); !ok {
			return
		}
	}
	upstream := proxy.proxy
	debug := g.bindings.Debug
	requested := r.Header.Values(debug.RequestHeader)
	if proxy.debug != nil && debug.RequestHeader != "" && len(requested) == 1 && requested[0] == "true" &&
		caller.headers.Get(debug.RequiredHeader) == debug.RequiredValue {
		if state := g.endpoints.state(binding.DebugOrigin); state == endpointReady || state == endpointLocal {
			upstream = proxy.debug
		}
	}
	state := serviceRequest{
		identity: caller, backendAuthorization: backendAuthorization, originAllowed: originAllowed,
		legacy: r.Host != g.bindings.Hostname, clientIP: g.bindings.ClientIP.clientIP(r),
		method: upstreamMethod, path: upstreamPath,
	}
	upstream.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), serviceRequestKey{}, state)))
}

// matchesServicePaths reports whether an upstream path is one of the patterns,
// where a trailing /* matches a subtree and its root.
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

// publicFromUpstream maps an upstream path to the public path: the mount
// becomes the prefix. A path outside the mount has no public form.
func publicFromUpstream(binding serviceBinding, upstream string) (string, error) {
	suffix, ok := strings.CutPrefix(upstream, binding.Mount)
	if !ok || suffix != "" && !strings.HasPrefix(suffix, "/") {
		return "", errors.New("outside the mount")
	}
	return binding.Prefix + suffix, nil
}

func rewriteServiceLocation(response *http.Response, binding serviceBinding, target *url.URL) {
	value := response.Header.Get("Location")
	if value == "" {
		return
	}
	ref, err := response.Request.URL.Parse(value)
	if err != nil {
		return
	}
	sameService := strings.EqualFold(ref.Host, target.Host) && ref.Scheme == target.Scheme
	legacyHost := binding.UpstreamHost != "" && strings.EqualFold(ref.Host, binding.UpstreamHost) && ref.Scheme == "https"
	if !sameService && !legacyHost {
		return
	}
	public, err := publicFromUpstream(binding, ref.Path)
	if err != nil {
		return
	}
	if ref.RawPath != "" {
		if ref.RawPath, err = publicFromUpstream(binding, ref.RawPath); err != nil {
			ref.RawPath = ""
		}
	}
	ref.Scheme, ref.Host, ref.User = "", "", nil
	ref.Path = public
	response.Header.Set("Location", ref.String())
}

func rewriteServiceCookies(headers http.Header, binding serviceBinding) {
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
			if public, err := publicFromUpstream(binding, cookie.Path); err == nil {
				cookie.Path = public
			} else {
				cookie.Path = binding.Prefix
			}
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

// clientAddressHeaders are the headers proxies commonly use for the client
// address, besides X-Forwarded-* and Forwarded.
var clientAddressHeaders = []string{"X-Real-Ip", "Client-Ip", "True-Client-Ip", "X-Client-Ip", "X-Cluster-Client-Ip", "X-Original-Forwarded-For"}

// stripClientAddress removes every header that could carry a client address
// or a proxy's view of the request: X-Forwarded-*, Forwarded, the common
// client-address headers and the configured clientIP header.
func stripClientAddress(headers http.Header, clientIPHeader string) {
	for header := range headers {
		if strings.HasPrefix(http.CanonicalHeaderKey(header), "X-Forwarded-") {
			headers.Del(header)
		}
	}
	headers.Del("Forwarded")
	headers.Del(clientIPHeader)
	for _, header := range clientAddressHeaders {
		headers.Del(header)
	}
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
