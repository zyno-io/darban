package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	pathpkg "path"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

type operationKey struct {
	method, path string
}

type registeredRoute struct {
	credentials []string
	proxy       *httputil.ReverseProxy
	debugProxy  *httputil.ReverseProxy
	debugOrigin string
}

var (
	literalPath = regexp.MustCompile(`^(/([a-z0-9-]+|\.well-known))+$`)
	serviceDNS  = regexp.MustCompile(`^[a-z0-9-]+\.[a-z0-9-]+\.svc\.cluster\.local$`)
	dnsName     = regexp.MustCompile("^[a-z0-9-]+([.][a-z0-9-]+)+$")
)

func readJSON(path string, value any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, value)
}

func upstreamOrigin(address string, local bool) (*url.URL, error) {
	target, err := url.Parse(address)
	if err != nil {
		return nil, err
	}
	host := target.Hostname()
	clusterHost := serviceDNS.MatchString(host)
	localHost := local && (host == "localhost" || net.ParseIP(host).IsLoopback())
	if (target.Scheme != "http" && target.Scheme != "https") || (!clusterHost && !localHost) || target.Port() == "" ||
		target.Path != "" || target.RawQuery != "" || target.User != nil || target.Fragment != "" {
		return nil, errors.New("expected a private Kubernetes Service origin or local loopback")
	}
	return target, nil
}

// dialVerified dials a TLS upstream when the config does its own verification.
// The TLS state carries no server name for an IP literal (no SNI is sent), so
// the dialed host is supplied to the verifier explicitly.
func dialVerified(transport *http.Transport, base *tls.Config) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		conn, err := transport.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		config := base.Clone()
		config.ServerName = host
		config.VerifyConnection = func(state tls.ConnectionState) error {
			state.ServerName = host
			return base.VerifyConnection(state)
		}
		client := tls.Client(conn, config)
		// DialTLSContext bypasses TLSHandshakeTimeout, so bound it here.
		if timeout := transport.TLSHandshakeTimeout; timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		if err := client.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		return client, nil
	}
}

func newTransport(tlsConfig *tls.Config) *http.Transport {
	transport := newBaseTransport(tlsConfig)
	if tlsConfig != nil && tlsConfig.VerifyConnection != nil {
		transport.DialTLSContext = dialVerified(transport, tlsConfig)
	}
	return transport
}

func newBaseTransport(tlsConfig *tls.Config) *http.Transport {
	return &http.Transport{
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: 2 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          192,
		MaxIdleConnsPerHost:   64,
		MaxConnsPerHost:       64,
		IdleConnTimeout:       10 * time.Second,
		ResponseHeaderTimeout: 2 * time.Second,
		DisableCompression:    true,
	}
}

func newDebugTransport(tlsConfig *tls.Config) *http.Transport {
	transport := newTransport(tlsConfig)
	transport.DialContext = (&net.Dialer{Timeout: 350 * time.Millisecond}).DialContext
	transport.TLSHandshakeTimeout = 350 * time.Millisecond
	transport.ResponseHeaderTimeout = 600 * time.Millisecond
	// Avoid implicit retries of debug requests with an Idempotency-Key.
	transport.DisableKeepAlives = true
	return transport
}

func writeStatus(w http.ResponseWriter, status int) {
	w.WriteHeader(status)
}

func (g *gateway) reverseProxy(route compiledOperation, target *url.URL, transport http.RoundTripper) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			if r.In.Host != g.bindings.Hostname {
				r.Out.Host = r.In.Host
			}
			r.Out.URL.Path, r.Out.URL.RawPath = route.path, ""
			r.Out.URL.RawQuery = r.In.URL.RawQuery
			stripForwardedIdentity(r.Out.Header, g.bindings.Authorization)
			for _, header := range g.bindings.UpstreamRequestHeaders {
				if values := r.In.Header.Values(header); len(values) > 0 {
					r.Out.Header[header] = values
				}
			}
			r.Out.Header.Del("Authorization")
			r.Out.Header.Del(g.bindings.Debug.RequestHeader)
			caller := r.In.Context().Value(identityKey{}).(identity)
			for name, values := range caller.headers {
				r.Out.Header[name] = values
			}
		},
		ModifyResponse: func(response *http.Response) error {
			if len(g.bindings.BrowserOrigins) > 0 {
				for header := range response.Header {
					if strings.HasPrefix(header, "Access-Control-") {
						response.Header.Del(header)
					}
				}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			writeStatus(w, http.StatusBadGateway)
		},
	}
}

type snapshot struct {
	contractServices []string
	// services holds the effective binding of each served contract service.
	services        map[string]serviceBinding
	unserved        map[string]bool
	deniedTemplates []operationKey
	denied          map[operationKey]bool
	revision        string
	specYAML        []byte
	specJSON        []byte
	routes          map[operationKey]registeredRoute
}

type gateway struct {
	contractStatus contractStatusStore
	serviceProxies map[string]*httputil.ReverseProxy
	legacyPrefixes map[string]string
	bindings       upstreamBindings
	transport      *http.Transport
	debugTransport *http.Transport
	authClient     *http.Client
	upstreamTLS    *upstreamVerifier
	endpoints      endpointCatalog
}

func newGateway(bindings upstreamBindings) *gateway {
	legacyPrefixes := make(map[string]string)
	for prefix, route := range bindings.ServiceRoutes {
		for _, host := range route.LegacyHosts {
			legacyPrefixes[host] = prefix
		}
	}
	verifier, err := newUpstreamVerifier(bindings.UpstreamTLS)
	if err != nil {
		// loadBindings already validated the options.
		log.Fatal(err)
	}
	tlsConfig := verifier.tlsConfig()
	return &gateway{
		upstreamTLS:    verifier,
		serviceProxies: newServiceProxies(bindings, tlsConfig),
		legacyPrefixes: legacyPrefixes,
		bindings:       bindings,
		transport:      newTransport(tlsConfig),
		debugTransport: newDebugTransport(tlsConfig),
		authClient: &http.Client{
			Transport:     newTransport(tlsConfig),
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (g *gateway) build(compiled candidate) *snapshot {
	active := &snapshot{
		contractServices: compiled.contractServices,
		services:         compiled.services,
		unserved:         make(map[string]bool, len(compiled.unserved)),
		denied:           make(map[operationKey]bool, len(compiled.denied)),
		revision:         compiled.revision,
		specYAML:         compiled.specYAML,
		specJSON:         compiled.specJSON,
		routes:           make(map[operationKey]registeredRoute, len(compiled.routes)),
	}
	for _, prefix := range compiled.unserved {
		active.unserved[prefix] = true
	}
	for _, key := range compiled.denied {
		if strings.Contains(key.path, "{") {
			active.deniedTemplates = append(active.deniedTemplates, key)
		} else {
			active.denied[key] = true
		}
	}
	for _, route := range compiled.routes {
		binding, found := compiled.services[route.service]
		if !found {
			binding = g.bindings.Services[route.service]
		}
		// Validated when the contract or the bindings were loaded.
		target, _ := url.Parse(binding.Origin)
		registered := registeredRoute{
			credentials: route.credentials,
			proxy:       g.reverseProxy(route, target, g.transport),
		}
		if binding.DebugOrigin != "" {
			alternate, _ := url.Parse(binding.DebugOrigin)
			registered.debugOrigin = binding.DebugOrigin
			registered.debugProxy = g.reverseProxy(route, alternate, g.debugTransport)
		}
		active.routes[route.key] = registered
	}
	return active
}

func (g *gateway) serve(active *snapshot, w http.ResponseWriter, r *http.Request) {
	path, _, _ := strings.Cut(r.RequestURI, "?")
	legacyPrefix := g.legacyPrefixes[r.Host]
	if r.Host != g.bindings.Hostname && legacyPrefix == "" {
		writeStatus(w, http.StatusNotFound)
		return
	}
	if active == nil {
		writeStatus(w, http.StatusServiceUnavailable)
		return
	}
	if legacyPrefix == "" && path != "" && (path == g.bindings.OpenAPI.YAMLPath || path == g.bindings.OpenAPI.JSONPath) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeStatus(w, http.StatusMethodNotAllowed)
			return
		}
		body, mediaType := active.specYAML, "application/yaml"
		if path == g.bindings.OpenAPI.JSONPath {
			body, mediaType = active.specJSON, "application/json"
		}
		w.Header().Set("Content-Type", mediaType)
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		if r.Method == http.MethodGet {
			w.Write(body)
		}
		return
	}
	method := r.Method
	preflight := len(g.bindings.BrowserOrigins) > 0 && r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""
	if preflight {
		method = r.Header.Get("Access-Control-Request-Method")
	}
	contractPath := path
	prefix := routePrefix(path)
	if legacyPrefix != "" {
		prefix = legacyPrefix
	}
	servicePath := ""
	if service, found := g.bindings.ServiceRoutes[prefix]; found {
		// Apply the same policy to alternate spellings of the same path.
		contractPath = pathpkg.Clean(r.URL.Path)
		if legacyPrefix != "" {
			contractPath = prefix + contractPath
		}
		servicePath = stripServicePrefix(contractPath, prefix)
		if routePrefix(contractPath) != prefix || !service.allowsPath(servicePath) {
			writeStatus(w, http.StatusNotFound)
			return
		}
		// A contract-bound service with no serving contract has no deny list, so
		// do not proxy its prefix.
		if active.unserved[prefix] {
			writeStatus(w, http.StatusServiceUnavailable)
			return
		}
	}
	key := operationKey{method, contractPath}
	if active.denied[key] {
		writeStatus(w, http.StatusNotFound)
		return
	}
	route, ok := active.routes[key]
	if !ok {
		for _, blocked := range active.deniedTemplates {
			if blocked.method == method && matchesPathTemplate(blocked.path, contractPath) {
				writeStatus(w, http.StatusNotFound)
				return
			}
		}
		g.serveService(w, r, prefix, servicePath, preflight, method)
		return
	}
	if preflight {
		g.servePreflight(w, r, method)
		return
	}
	g.applyBrowserCORS(w, r)
	caller, ok := g.authorizeRequest(w, r, route.credentials)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	proxy := route.proxy
	debug := g.bindings.Debug
	requested := r.Header.Values(debug.RequestHeader)
	if route.debugProxy != nil && debug.RequestHeader != "" && len(requested) == 1 && requested[0] == "true" &&
		caller.headers.Get(debug.RequiredHeader) == debug.RequiredValue {
		state := g.endpoints.state(route.debugOrigin)
		if state == endpointReady || state == endpointLocal {
			proxy = route.debugProxy
		}
	}
	proxy.ServeHTTP(w, r.WithContext(context.WithValue(ctx, identityKey{}, caller)))
}

func main() {
	manifest := flag.String("manifest", "", "local contract manifest YAML")
	namespace := flag.String("namespace", "", "namespace of GatewayContracts")
	printSpec := flag.Bool("print-spec", false, "compile local manifest once and print public OpenAPI")
	bindingsPath := flag.String("bindings", "/config/bindings.json", "private service bindings")
	cert := flag.String("cert", "/tls/tls.crt", "gateway TLS certificate")
	key := flag.String("key", "/tls/tls.key", "gateway TLS key")
	flag.Parse()

	if (*manifest == "") == (*namespace == "") || (*printSpec && *manifest == "") {
		log.Fatal("specify exactly one of -manifest or -namespace; -print-spec requires -manifest")
	}
	bindings, err := loadBindings(*bindingsPath, *manifest != "")
	if err != nil {
		log.Fatal(err)
	}
	if *printSpec {
		regs, err := loadLocal(*manifest)
		if err != nil {
			log.Fatal(err)
		}
		compiled, err := compileStrict(regs, bindings)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := os.Stdout.Write(compiled.specYAML); err != nil {
			log.Fatal(err)
		}
		return
	}
	gateway := newGateway(bindings)
	var active atomic.Pointer[snapshot]
	reload := &reconciler{gateway: gateway, active: &active}
	var current cache.SharedIndexInformer
	if *namespace != "" {
		config, err := rest.InClusterConfig()
		if err != nil {
			log.Fatal(err)
		}
		current, err = newGatewayContractInformer(config, *namespace, bindings.ContractAPIGroup)
		if err != nil {
			log.Fatal(err)
		}
		gateway.endpoints, err = newEndpointCatalog(config, bindings, *namespace)
		if err != nil {
			log.Fatal(err)
		}
	}
	certificate, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		log.Fatal(err)
	}
	var currentCertificate atomic.Pointer[tls.Certificate]
	currentCertificate.Store(&certificate)
	traffic, err := net.Listen("tcp", ":8443")
	if err != nil {
		log.Fatal(err)
	}
	admin, err := net.Listen("tcp", ":8081")
	if err != nil {
		log.Fatal(err)
	}
	var draining atomic.Bool
	var requests atomic.Uint64

	probes := http.NewServeMux()
	probes.HandleFunc("GET /status", gateway.statusHandler(&active, &draining))
	probes.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	probes.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		snapshot := active.Load()
		if snapshot == nil || draining.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, snapshot.revision)
	})
	probes.HandleFunc("GET /drain", func(w http.ResponseWriter, _ *http.Request) {
		draining.Store(true)
		log.Print("gateway draining")
		time.Sleep(3 * time.Second)
		w.WriteHeader(http.StatusOK)
	})
	probes.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		var usage syscall.Rusage
		if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		cpu := (usage.Utime.Sec+usage.Stime.Sec)*1_000_000 + usage.Utime.Usec + usage.Stime.Usec
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, "{\"requests\":%d,\"cpuMicros\":%d}\n", requests.Load(), cpu)
	})

	apiServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			snapshot := active.Load()
			gateway.serve(snapshot, w, r)
		}),
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return currentCertificate.Load(), nil
			},
		},
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       20 * time.Second,
	}
	adminServer := &http.Server{Handler: probes, ReadHeaderTimeout: 2 * time.Second}
	stopping, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go refreshCertificate(stopping, *cert, *key, &currentCertificate)
	go gateway.upstreamTLS.run(stopping)
	gateway.endpoints.run(stopping)
	failures := make(chan error, 3)
	go func() { failures <- apiServer.ServeTLS(traffic, "", "") }()
	go func() { failures <- adminServer.Serve(admin) }()
	if current == nil {
		go reload.watchLocal(stopping, *manifest)
	} else {
		go func() {
			if err := reload.watchCluster(stopping, current); err != nil {
				failures <- err
			}
		}()
	}

	select {
	case <-stopping.Done():
	case err := <-failures:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Printf("server stopped: %v", err)
		}
	}
	draining.Store(true)
	shutdown, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := apiServer.Shutdown(shutdown); err != nil {
		log.Printf("gateway drain ended: %v", err)
	}
	if err := adminServer.Shutdown(shutdown); err != nil {
		log.Printf("admin drain ended: %v", err)
	}
}
