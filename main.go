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
	"net/url"
	"os"
	"os/signal"
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
	// service is the service whose upstream serves the route: the owner, or
	// a rewrite's target. path is the upstream path template.
	service string
	path    string
	// protected reports that the gateway authorizes the operation.
	protected bool
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

func writeStatus(w http.ResponseWriter, status int) {
	w.WriteHeader(status)
}

type snapshot struct {
	contractServices []string
	// services holds the effective binding of each served contract service,
	// and proxies how its requests go upstream.
	services map[string]serviceBinding
	proxies  map[string]*serviceProxy
	// owners maps each served prefix to its service, and legacyHosts each
	// legacy host to its service's prefix.
	owners      map[string]string
	legacyHosts map[string]string
	// unserved holds the prefixes of bound services with no accepted
	// contract, which fail closed.
	unserved map[string]bool
	// routes, extras, denied and passthrough are keyed by public path
	// template. table matches requests against them; it is built on first use.
	denied      map[operationKey]bool
	passthrough map[operationKey]bool
	routes      map[operationKey]registeredRoute
	extras      map[operationKey]registeredRoute
	table       routeTable
	tableOnce   sync.Once
	revision    string
	specYAML    []byte
	specJSON    []byte
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
	bindings       upstreamBindings
	transports     *transports
	authClient     *http.Client
	upstreamTLS    *upstreamVerifier
	endpoints      endpointCatalog
}

func newGateway(bindings upstreamBindings) *gateway {
	verifier, err := newUpstreamVerifier(bindings.UpstreamTLS)
	if err != nil {
		// loadBindings already validated the options.
		log.Fatal(err)
	}
	tlsConfig := verifier.tlsConfig()
	return &gateway{
		upstreamTLS: verifier,
		bindings:    bindings,
		transports:  &transports{base: newTransport(tlsConfig)},
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
		proxies:          make(map[string]*serviceProxy, len(compiled.services)),
		owners:           make(map[string]string, len(compiled.services)),
		unserved:         make(map[string]bool, len(compiled.unserved)),
		denied:           make(map[operationKey]bool, len(compiled.denied)),
		passthrough:      make(map[operationKey]bool, len(compiled.passthrough)),
		routes:           make(map[operationKey]registeredRoute, len(compiled.routes)),
		extras:           make(map[operationKey]registeredRoute, len(compiled.extras)),
		revision:         compiled.revision,
		specYAML:         compiled.specYAML,
		specJSON:         compiled.specJSON,
	}
	// A legacy host follows its service's prefix, which a contract can set,
	// and fails closed with it while the service has no accepted contract.
	active.legacyHosts = make(map[string]string)
	for name, binding := range g.bindings.Services {
		prefix := binding.Prefix
		if prefix == "" {
			prefix = "/" + name
		}
		for _, host := range binding.LegacyHosts {
			active.legacyHosts[host] = prefix
		}
	}
	for name, binding := range compiled.services {
		active.proxies[name] = g.newServiceProxy(binding)
		active.owners[binding.Prefix] = name
		for _, host := range binding.LegacyHosts {
			active.legacyHosts[host] = binding.Prefix
		}
	}
	for _, prefix := range compiled.unserved {
		active.unserved[prefix] = true
	}
	for _, key := range compiled.denied {
		active.denied[key] = true
	}
	for _, key := range compiled.passthrough {
		active.passthrough[key] = true
	}
	register := func(route compiledOperation) registeredRoute {
		return registeredRoute{key: route.key, service: route.service, path: route.path, protected: route.protected}
	}
	for _, route := range compiled.routes {
		active.routes[route.key] = register(route)
	}
	for _, extra := range compiled.extras {
		active.extras[extra.key] = register(extra)
	}
	active.routeTable()
	return active
}

// serve verifies a request before it routes it. It must match a contract
// operation or an extra route of the service its prefix (or legacy host)
// names, by method and path, or it gets 404. A bound service without an
// accepted contract gets 503.
func (g *gateway) serve(active *snapshot, w http.ResponseWriter, r *http.Request) {
	path, _, _ := strings.Cut(r.RequestURI, "?")
	if active == nil {
		writeStatus(w, http.StatusServiceUnavailable)
		return
	}
	legacyPrefix := ""
	if r.Host != g.bindings.Hostname {
		if legacyPrefix = active.legacyHosts[r.Host]; legacyPrefix == "" {
			writeStatus(w, http.StatusNotFound)
			return
		}
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
	// A real preflight asks about another method. On a backendCORS service the
	// backend answers it, without authorization, since it carries no
	// credentials.
	corsPreflight := r.Method == http.MethodOptions && requested != "" && requested != http.MethodOptions
	prefix := routePrefix(path)
	if legacyPrefix != "" {
		prefix = legacyPrefix
	} else if routePrefix(r.URL.Path) != prefix {
		// The matcher decodes the path, so an encoded prefix such as
		// /sh%6Fp/x would otherwise reach a service under /shop.
		writeStatus(w, http.StatusNotFound)
		return
	}
	// Backends resolve dot segments, empty segments and encoded separators
	// their own way, so only a path with one meaning is matched.
	if !canonicalPath(path, r.URL.Path) {
		writeStatus(w, http.StatusNotFound)
		return
	}
	if active.unserved[prefix] {
		writeStatus(w, http.StatusServiceUnavailable)
		return
	}
	owner := active.services[active.owners[prefix]]
	match := active.match(method, path, r.URL.Path, legacyPrefix)
	backendPreflight := false
	if corsPreflight {
		// On a backendCORS owner an OPTIONS operation is served as itself,
		// with its own policy. Any other preflight goes to the backend for a
		// path it serves, when the service that serves the path, which a
		// rewrite can make another one, is backendCORS too.
		options := active.match(http.MethodOptions, path, r.URL.Path, legacyPrefix)
		if owner.BackendCORS && (options.route != nil || options.denied || options.invalid || options.passthrough) {
			match, method = options, http.MethodOptions
		} else if target := active.match(requested, path, r.URL.Path, legacyPrefix); target.route != nil &&
			!target.denied && !target.invalid && active.services[target.route.service].BackendCORS {
			match, method, backendPreflight = target, requested, true
		}
	}
	// Internal operations, and operations the service's selection leaves out,
	// are refused like any path no operation declares.
	if match.denied || match.invalid || match.route == nil {
		writeStatus(w, http.StatusNotFound)
		return
	}
	registered := *match.route
	proxy := active.proxies[registered.service]
	upstreamMethod := ""
	if r.Method == http.MethodHead && registered.key.method == http.MethodGet {
		// Backends need not route HEAD, so send GET. The server drops the body
		// for the HEAD caller.
		upstreamMethod = http.MethodGet
	}
	target := upstreamPath(registered.path, match.params)
	if strings.HasSuffix(r.URL.Path, "/") && !strings.HasSuffix(target, "/") {
		// The matcher allows one trailing slash, and the backend still sees
		// it, as it did on the direct routes.
		target += "/"
	}
	// Anonymous operations and backendAuth services leave authorization to
	// the backend, with the caller's Authorization.
	backendAuthorization := !registered.protected || proxy.binding.BackendAuth || backendPreflight
	g.serveService(w, r, proxy, target, backendAuthorization, preflight, method, upstreamMethod)
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
	bindings.requireAuthz = true
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
