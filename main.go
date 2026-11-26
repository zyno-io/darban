package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
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
	"sync"
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
	key operationKey
	// service is the service whose upstream serves the route.
	service string
	// protected reports that the gateway authorizes the operation.
	protected bool
	// direct names the serviceRoutes prefix whose transport serves the route.
	// Otherwise proxy does.
	direct      string
	proxy       *httputil.ReverseProxy
	debugProxy  *httputil.ReverseProxy
	debugOrigin string
}

var (
	literalPath = regexp.MustCompile(`^(/([a-z0-9-]+|\.well-known))+$`)
	serviceDNS  = regexp.MustCompile(`^[a-z0-9-]+\.[a-z0-9-]+\.svc\.cluster\.local$`)
	dnsName     = regexp.MustCompile("^[a-z0-9-]+([.][a-z0-9-]+)+$")
)

// readJSON decodes one JSON value strictly: unknown fields at any depth and
// trailing data are errors.
func readJSON(path string, value any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("%s: unexpected data after the JSON value", path)
	}
	return nil
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
			params, _ := r.In.Context().Value(routeParamsKey{}).(map[string]string)
			r.Out.URL.Path, r.Out.URL.RawPath = upstreamPath(route.path, params), ""
			// HEAD can match a GET operation. Backends need not route HEAD, so
			// send GET; the server drops the body for the HEAD caller.
			if r.In.Method == http.MethodHead && route.key.method == http.MethodGet {
				r.Out.Method = http.MethodGet
			}
			r.Out.URL.RawQuery = r.In.URL.RawQuery
			stripForwardedIdentity(r.Out.Header, g.bindings.Authorization)
			for _, header := range g.bindings.UpstreamRequestHeaders {
				if values := r.In.Header.Values(header); len(values) > 0 {
					r.Out.Header[header] = values
				}
			}
			r.Out.Header.Del(g.bindings.Debug.RequestHeader)
			// A request the gateway authorized carries the identity instead of
			// the credentials. Any other keeps its Authorization.
			if caller := r.In.Context().Value(identityKey{}).(identity); caller.authorized {
				r.Out.Header.Del("Authorization")
				for name, values := range caller.headers {
					r.Out.Header[name] = values
				}
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
	services map[string]serviceBinding
	unserved map[string]bool
	// routes, extras, denied and passthrough are keyed by public path
	// template. table matches requests against them; it is built on first use.
	denied      map[operationKey]bool
	passthrough map[operationKey]bool
	routes      map[operationKey]registeredRoute
	extras      map[operationKey]registeredRoute
	// shadow holds, by direct route prefix, the contract of a service with
	// route: false to compare its traffic with.
	shadow map[string]*shadowTable
	// routed holds the prefixes of routed services with an accepted contract.
	// Their contract and extra routes decide which requests pass.
	routed    map[string]bool
	table     routeTable
	tableOnce sync.Once
	revision  string
	specYAML  []byte
	specJSON  []byte
}

func (s *snapshot) routeTable() routeTable {
	s.tableOnce.Do(func() { s.table = newRouteTable(s.routes, s.extras, s.denied, s.passthrough) })
	return s.table
}

func (s *snapshot) match(method, raw, decoded, legacyPrefix string) routeMatch {
	return s.routeTable().matchRequest(method, raw, decoded, legacyPrefix)
}

type routeParamsKey struct{}

type gateway struct {
	contractStatus contractStatusStore
	shadow         shadowRegistry
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
		active.denied[key] = true
	}
	active.passthrough = make(map[operationKey]bool, len(compiled.passthrough))
	for _, key := range compiled.passthrough {
		active.passthrough[key] = true
	}
	active.shadow = make(map[string]*shadowTable)
	for service, contract := range compiled.shadow {
		if prefix := compiled.services[service].Prefix; prefix != "" {
			if _, direct := g.bindings.ServiceRoutes[prefix]; direct {
				active.shadow[prefix] = newShadowTable(service, contract, g.shadow.counters(service, contract.digest))
			}
		}
	}
	active.routed = make(map[string]bool)
	for _, binding := range compiled.services {
		if binding.routed() && binding.Prefix != "" {
			active.routed[binding.Prefix] = true
		}
	}
	register := func(route compiledOperation) registeredRoute {
		binding, found := compiled.services[route.service]
		if !found {
			binding = g.bindings.Services[route.service]
		}
		registered := registeredRoute{key: route.key, service: route.service, protected: route.protected}
		// A service's own operations on its direct route use that route's
		// transport, which forwards the request path below the prefix. A
		// rewrite, even within the prefix, forwards its target's path through
		// the target's origin.
		if _, direct := g.bindings.ServiceRoutes[binding.Prefix]; direct && route.key.path == binding.Prefix+route.path {
			registered.direct = binding.Prefix
			return registered
		}
		// Validated when the contract or the bindings were loaded.
		target, _ := url.Parse(binding.Origin)
		registered.proxy = g.reverseProxy(route, target, g.transport)
		if binding.DebugOrigin != "" {
			alternate, _ := url.Parse(binding.DebugOrigin)
			registered.debugOrigin = binding.DebugOrigin
			registered.debugProxy = g.reverseProxy(route, alternate, g.debugTransport)
		}
		return registered
	}
	for _, route := range compiled.routes {
		active.routes[route.key] = register(route)
	}
	active.extras = make(map[operationKey]registeredRoute, len(compiled.extras))
	for _, extra := range compiled.extras {
		active.extras[extra.key] = register(extra)
	}
	active.routeTable()
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
	requested := r.Header.Get("Access-Control-Request-Method")
	preflight := len(g.bindings.BrowserOrigins) > 0 && r.Method == http.MethodOptions && requested != ""
	if preflight {
		method = requested
	}
	// A real preflight asks about another method. On a backendCORS route the
	// backend answers it, without authorization, since it carries no
	// credentials.
	corsPreflight := r.Method == http.MethodOptions && requested != "" && requested != http.MethodOptions
	prefix := routePrefix(path)
	if legacyPrefix != "" {
		prefix = legacyPrefix
	} else if routePrefix(r.URL.Path) != prefix {
		// An encoded prefix would skip the policy keyed by its decoded form:
		// direct routes are keyed by the prefix as sent, but the operation
		// matcher decodes it, so /sh%6Fp/x would reach a contract operation
		// under /shop without that prefix's direct-route policy.
		writeStatus(w, http.StatusNotFound)
		return
	}
	route, direct := g.bindings.ServiceRoutes[prefix]
	servicePath := ""
	if direct {
		// The policy below checks path.Clean of the decoded path, but the route
		// forwards the decoded path uncleaned, and backends resolve dot
		// segments differently than path.Clean. Refuse any path where the two
		// could disagree.
		if !canonicalPath(path, r.URL.Path) {
			writeStatus(w, http.StatusNotFound)
			return
		}
		cleaned := pathpkg.Clean(r.URL.Path)
		if legacyPrefix != "" {
			cleaned = prefix + cleaned
		}
		servicePath = stripServicePrefix(cleaned, prefix)
		if routePrefix(cleaned) != prefix {
			writeStatus(w, http.StatusNotFound)
			return
		}
		// A routed service with no accepted contract has no operations to
		// allow, so do not proxy its prefix.
		if active.unserved[prefix] {
			writeStatus(w, http.StatusServiceUnavailable)
			return
		}
		// Without a routed service, the route's own path policy decides.
		if !active.routed[prefix] {
			// Shadow mode compares what the route does today with the contract.
			// A preflight is about another request, so it is not compared.
			if shadow := active.shadow[prefix]; shadow != nil && !(r.Method == http.MethodOptions && requested != "") {
				shadow.observe(shadowRequest{
					method: r.Method, raw: path, decoded: r.URL.Path, legacyPrefix: legacyPrefix,
					allowed:     route.allowsPath(servicePath),
					skipAuth:    route.BackendAuth || matchesServicePaths(route.PublicPaths, servicePath),
					backendAuth: route.BackendAuth,
				})
			}
			g.serveByRoutePolicy(w, r, prefix, servicePath, preflight, method, route.BackendCORS && corsPreflight)
			return
		}
	}
	// A routed service serves only its contract operations and extra routes.
	match := active.match(method, path, r.URL.Path, legacyPrefix)
	backendPreflight := false
	if direct && route.BackendCORS && corsPreflight {
		// An OPTIONS operation is served as itself, with its own policy. Any
		// other preflight goes to the backend for a path the contract serves.
		if options := active.match(http.MethodOptions, path, r.URL.Path, legacyPrefix); options.route != nil || options.denied || options.invalid || options.passthrough {
			match, method = options, http.MethodOptions
		} else {
			match, method, backendPreflight = active.match(requested, path, r.URL.Path, legacyPrefix), requested, true
		}
	}
	switch {
	case match.denied || match.invalid:
		writeStatus(w, http.StatusNotFound)
		return
	case match.passthrough && direct:
		// An operation the bindings leave unselected keeps the route's own
		// policy until the selection is removed.
		g.serveByRoutePolicy(w, r, prefix, servicePath, preflight, method, backendPreflight)
		return
	case match.route == nil:
		writeStatus(w, http.StatusNotFound)
		return
	}
	registered := *match.route
	upstreamMethod := ""
	if r.Method == http.MethodHead && registered.key.method == http.MethodGet {
		// Backends need not route HEAD, so send GET. The server drops the body
		// for the HEAD caller.
		upstreamMethod = http.MethodGet
	}
	if registered.direct != "" {
		// Anonymous operations and backendAuth routes leave authorization to
		// the backend, with the caller's Authorization.
		backendAuthorization := !registered.protected || g.bindings.ServiceRoutes[registered.direct].BackendAuth || backendPreflight
		g.serveService(w, r, registered.direct, backendAuthorization, preflight, method, upstreamMethod)
		return
	}
	if preflight {
		g.servePreflight(w, r, method)
		return
	}
	g.applyBrowserCORS(w, r)
	var caller identity
	if registered.protected {
		var ok bool
		if caller, ok = g.authorizeRequest(w, r); !ok {
			return
		}
	}
	proxy := registered.proxy
	debug := g.bindings.Debug
	debugRequested := r.Header.Values(debug.RequestHeader)
	if registered.debugProxy != nil && debug.RequestHeader != "" && len(debugRequested) == 1 && debugRequested[0] == "true" &&
		caller.headers.Get(debug.RequiredHeader) == debug.RequiredValue {
		state := g.endpoints.state(registered.debugOrigin)
		if state == endpointReady || state == endpointLocal {
			proxy = registered.debugProxy
		}
	}
	ctx := context.WithValue(context.WithValue(r.Context(), identityKey{}, caller), routeParamsKey{}, match.params)
	proxy.ServeHTTP(w, r.WithContext(ctx))
}

// serveByRoutePolicy serves a direct route by its own path rules: deniedPaths
// and allowedPaths gate the path, and publicPaths leave authorization to the
// backend.
// A backendPreflight is a real preflight on a backendCORS route.
func (g *gateway) serveByRoutePolicy(w http.ResponseWriter, r *http.Request, prefix, servicePath string, preflight bool, method string, backendPreflight bool) {
	route := g.bindings.ServiceRoutes[prefix]
	if !route.allowsPath(servicePath) {
		writeStatus(w, http.StatusNotFound)
		return
	}
	backendAuthorization := route.BackendAuth || matchesServicePaths(route.PublicPaths, servicePath) || backendPreflight
	g.serveService(w, r, prefix, backendAuthorization, preflight, method, "")
}

func main() {
	manifest := flag.String("manifest", "", "local contract manifest YAML")
	namespace := flag.String("namespace", "", "namespace of GatewayContracts")
	contracts := flag.String("contracts", "", "GatewayContract list JSON, as kubectl get gatewaycontracts -o json prints it; one-shot only")
	printSpec := flag.Bool("print-spec", false, "compile the contracts once and print the public OpenAPI")
	printReport := flag.Bool("report", false, "compile the contracts once, print what the gateway does with each operation, and exit 1 on a rejection")
	bindingsPath := flag.String("bindings", "/config/bindings.json", "private service bindings")
	cert := flag.String("cert", "/tls/tls.crt", "gateway TLS certificate")
	key := flag.String("key", "/tls/tls.key", "gateway TLS key")
	flag.Parse()

	sources := 0
	for _, source := range []string{*manifest, *namespace, *contracts} {
		if source != "" {
			sources++
		}
	}
	oneShot := *printSpec || *printReport
	switch {
	case sources != 1:
		log.Fatal("specify exactly one of -manifest, -namespace or -contracts")
	case *printSpec && *printReport:
		log.Fatal("specify at most one of -print-spec and -report")
	case oneShot && *namespace != "":
		log.Fatal("-print-spec and -report need -manifest or -contracts")
	case *contracts != "" && !oneShot:
		log.Fatal("-contracts needs -print-spec or -report")
	}
	bindings, err := loadBindings(*bindingsPath, *manifest != "")
	if err != nil {
		log.Fatal(err)
	}
	if oneShot {
		var regs []registration
		if *contracts != "" {
			regs, err = loadContractList(*contracts)
		} else {
			regs, err = loadLocal(*manifest)
		}
		if err != nil {
			log.Fatal(err)
		}
		if *printReport {
			ok, err := writeReport(os.Stdout, regs, bindings)
			if err != nil {
				log.Fatal(err)
			}
			if !ok {
				os.Exit(1)
			}
			return
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
		cpu := int64(usage.Utime.Sec+usage.Stime.Sec)*1_000_000 + int64(usage.Utime.Usec) + int64(usage.Stime.Usec)
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
