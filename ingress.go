package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"
)

func (b *upstreamBindings) validateIngressRoutes(local bool) error {
	for prefix, address := range b.IngressRoutes {
		target, err := url.Parse(address)
		if err != nil || !prefixPath.MatchString(prefix) || !validIngressOrigin(target, local) ||
			strings.EqualFold(target.Hostname(), b.Hostname) {
			return fmt.Errorf("invalid ingress route for %q", prefix)
		}
	}
	for _, origin := range b.BrowserOrigins {
		target, err := url.Parse(origin)
		if err != nil || !validIngressOrigin(target, local || target.Scheme == "http") {
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

func validIngressOrigin(target *url.URL, local bool) bool {
	host := target.Hostname()
	loopback := local && (host == "localhost" || host == "127.0.0.1" || host == "::1")
	return (target.Scheme == "https" && dnsName.MatchString(host) || loopback && target.Scheme == "http") &&
		target.Path == "" && target.RawQuery == "" && !target.ForceQuery && target.User == nil &&
		target.Fragment == "" && target.Opaque == ""
}

func ingressRoutePrefix(rawPath string) string {
	if !strings.HasPrefix(rawPath, "/") {
		return ""
	}
	prefix, _, _ := strings.Cut(rawPath[1:], "/")
	return "/" + prefix
}

func newIngressProxies(bindings upstreamBindings) map[string]*httputil.ReverseProxy {
	proxies := make(map[string]*httputil.ReverseProxy, len(bindings.IngressRoutes))
	transport := newTransport()
	transport.ResponseHeaderTimeout = 60 * time.Second
	transport.ForceAttemptHTTP2 = true
	for prefix, address := range bindings.IngressRoutes {
		target, _ := url.Parse(address)
		proxies[prefix] = ingressProxy(prefix, target, transport, bindings)
	}
	return proxies
}

func (g *gateway) serveIngress(w http.ResponseWriter, r *http.Request, rawPath string) {
	proxy := g.ingressRoutes[ingressRoutePrefix(rawPath)]
	if proxy == nil {
		writeStatus(w, http.StatusNotFound)
		return
	}
	proxy.ServeHTTP(w, r)
}

func ingressProxy(prefix string, target *url.URL, transport http.RoundTripper, bindings upstreamBindings) *httputil.ReverseProxy {
	requestHeaders := append(slices.Clone(bindings.Authorization.RequestHeaders), bindings.UpstreamRequestHeaders...)
	return &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = target.Host
			r.Out.URL.Path = stripIngressPrefix(r.In.URL.Path, prefix)
			if r.In.URL.RawPath != "" {
				r.Out.URL.RawPath = stripIngressPrefix(r.In.URL.RawPath, prefix)
			}
			// Keep the caller's credentials and public request inputs. The ingress still
			// authenticates the request and projects its own trusted identity.
			stripForwardedIdentity(r.Out.Header, bindings.Authorization)
			for _, header := range requestHeaders {
				if values := r.In.Header.Values(header); len(values) > 0 {
					r.Out.Header[header] = values
				}
			}
			r.Out.Header.Del("X-Real-Ip")
		},
		ModifyResponse: func(response *http.Response) error {
			rewriteIngressLocation(response, prefix, target)
			rewriteIngressCookies(response.Header, prefix)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			writeStatus(w, http.StatusBadGateway)
		},
	}
}

func stripIngressPrefix(path, prefix string) string {
	suffix := strings.TrimPrefix(path, prefix)
	if suffix == "" {
		return "/"
	}
	return suffix
}

func rewriteIngressLocation(response *http.Response, prefix string, target *url.URL) {
	value := response.Header.Get("Location")
	if value == "" {
		return
	}
	ref, err := response.Request.URL.Parse(value)
	if err != nil || !strings.EqualFold(ref.Host, target.Host) || ref.Scheme != target.Scheme {
		return
	}
	ref.Scheme, ref.Host, ref.User = "", "", nil
	ref.Path = prefix + ref.Path
	if ref.RawPath != "" {
		ref.RawPath = prefix + ref.RawPath
	}
	response.Header.Set("Location", ref.String())
}

func rewriteIngressCookies(headers http.Header, prefix string) {
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
