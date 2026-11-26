package main

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var (
	// dns1035 is a Kubernetes Service name.
	dns1035 = regexp.MustCompile(`^[a-z]([-a-z0-9]*[a-z0-9])?$`)
	// dns1123 is a Kubernetes namespace name.
	dns1123 = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
)

// parseContractUpstream validates a GatewayContract spec.upstream URL and
// returns the normalised origin, with the port explicit, and the upstream mount
// taken from the URL path. In Kubernetes mode the Service must live in the
// contract's own namespace. In local manifest mode (local) loopback hosts are
// allowed and any namespace is accepted.
func parseContractUpstream(raw, namespace string, local bool) (origin, mount string, err error) {
	if strings.ContainsAny(raw, "?#") {
		return "", "", errors.New("must not have a query or fragment")
	}
	target, err := url.Parse(raw)
	if err != nil {
		return "", "", errors.New("invalid URL")
	}
	switch {
	case target.Scheme != "http" && target.Scheme != "https":
		return "", "", errors.New("scheme must be http or https")
	case target.User != nil || strings.Contains(raw, "@"):
		return "", "", errors.New("must not have userinfo")
	case target.Opaque != "" || target.Hostname() == "":
		return "", "", errors.New("must be an absolute URL with a host")
	}
	if port := target.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return "", "", errors.New("invalid port")
		}
	}
	host := strings.ToLower(target.Hostname())
	// Local manifests may name a loopback process.
	if loopback := local && (host == "localhost" || net.ParseIP(host).IsLoopback()); !loopback {
		if host, err = serviceHost(host, namespace, local); err != nil {
			return "", "", err
		}
	}
	if path := target.Path; path != "" {
		switch {
		case target.EscapedPath() != path:
			return "", "", errors.New("path must not contain escapes")
		case strings.HasSuffix(path, "/"):
			return "", "", errors.New("path must not end with /")
		case !literalPath.MatchString(path):
			return "", "", fmt.Errorf("path %q is not a literal path", path)
		}
		mount = path
	}
	origin = target.Scheme + "://" + net.JoinHostPort(host, effectivePort(target))
	if _, err := upstreamOrigin(origin, local); err != nil {
		return "", "", err
	}
	return origin, mount, nil
}

// serviceHost expands <svc>, <svc>.<ns>, <svc>.<ns>.svc and
// <svc>.<ns>.svc.cluster.local to the full Service DNS name and checks that
// the namespace is the contract's own.
func serviceHost(host, namespace string, local bool) (string, error) {
	parts := strings.Split(host, ".")
	var service, ns string
	switch {
	case len(parts) == 1:
		service, ns = parts[0], namespace
	case len(parts) == 2:
		service, ns = parts[0], parts[1]
	case len(parts) == 3 && parts[2] == "svc":
		service, ns = parts[0], parts[1]
	case len(parts) == 5 && parts[2] == "svc" && parts[3] == "cluster" && parts[4] == "local":
		service, ns = parts[0], parts[1]
	default:
		return "", fmt.Errorf("host %q is not a Kubernetes Service name", host)
	}
	if ns == "" {
		return "", errors.New("a Service host without a namespace needs a Kubernetes contract")
	}
	if !dns1035.MatchString(service) || len(service) > 63 {
		return "", fmt.Errorf("%q is not a valid Service name", service)
	}
	if !local && ns != namespace {
		return "", fmt.Errorf("Service namespace %q must be the contract's namespace %q", ns, namespace)
	}
	if !dns1123.MatchString(ns) || len(ns) > 63 {
		return "", fmt.Errorf("%q is not a valid namespace", ns)
	}
	return service + "." + ns + ".svc.cluster.local", nil
}

// resolveBinding merges a contract with its optional bindings entry into the
// effective per-service binding. The contract wins; the bindings entry is the
// transition fallback. The second result describes fields the contract
// overrides, for logging.
func resolveBinding(reg registration, bindings upstreamBindings) (serviceBinding, string, error) {
	name := reg.serviceName
	static, hasStatic := bindings.Services[name]
	binding := static
	if reg.prefix != "" && !prefixPath.MatchString(reg.prefix) {
		return binding, "", fmt.Errorf("spec.prefix %q is invalid", reg.prefix)
	}
	if reg.upstream != "" {
		origin, mount, err := parseContractUpstream(reg.upstream, reg.namespace, reg.local)
		if err != nil {
			return binding, "", fmt.Errorf("spec.upstream: %w", err)
		}
		binding.Origin, binding.Mount, binding.Prefix = origin, mount, reg.prefix
		if binding.Prefix == "" {
			binding.Prefix = "/" + name
		}
	} else {
		if !hasStatic {
			return binding, "", fmt.Errorf("no upstream: set spec.upstream or bindings.services.%s.origin", name)
		}
		if reg.prefix != "" {
			binding.Prefix = reg.prefix
		} else if binding.Prefix == "" {
			binding.Prefix = "/" + name
		}
		// A routed service on a direct route falls back to the route's origin.
		// A service with route: false routes nothing through its contract.
		if route, direct := bindings.ServiceRoutes[binding.Prefix]; direct && binding.Origin == "" && binding.routed() {
			binding.Origin = route.Origin
		}
		if binding.Origin == "" && binding.routed() {
			return binding, "", fmt.Errorf("no upstream: set spec.upstream or bindings.services.%s.origin", name)
		}
	}
	// A routed service on a direct route uses the route's transport, so its
	// upstream must be the route's origin.
	if route, direct := bindings.ServiceRoutes[binding.Prefix]; direct && binding.routed() && binding.Origin != "" && !sameOrigin(binding.Origin, route.Origin) {
		return binding, "", fmt.Errorf("upstream %s differs from the serviceRoutes origin %s of %s", binding.Origin, route.Origin, binding.Prefix)
	}

	// Ownership of a direct serviceRoutes prefix comes from the bindings entry.
	if _, direct := bindings.ServiceRoutes[binding.Prefix]; direct && !(hasStatic && static.Prefix == binding.Prefix) {
		return binding, "", fmt.Errorf("prefix %s belongs to a serviceRoutes entry this service does not own", binding.Prefix)
	}
	if _, owns := bindings.ServiceRoutes[static.Prefix]; owns && static.Prefix != "" && binding.Prefix != static.Prefix {
		return binding, "", fmt.Errorf("service owns the serviceRoutes prefix %s, so spec.prefix must match it", static.Prefix)
	}
	// A direct route proxies Prefix+X to upstream X, so a mount would make the
	// deny keys (computed from the upstream paths) miss the public paths.
	if _, direct := bindings.ServiceRoutes[binding.Prefix]; direct && binding.Mount != "" {
		return binding, "", fmt.Errorf("prefix %s has a serviceRoutes direct route, which cannot be combined with an upstream path or mount %q", binding.Prefix, binding.Mount)
	}
	// A bindings entry reserves its prefix for its own service, with or
	// without a contract.
	for _, other := range slices.Sorted(maps.Keys(bindings.Services)) {
		reserved := bindings.Services[other].Prefix
		if reserved == "" {
			reserved = "/" + other
		}
		if other != name && reserved == binding.Prefix {
			return binding, "", fmt.Errorf("prefix %s is reserved by bindings.services.%s", binding.Prefix, other)
		}
	}
	if reason, reserved := reservedPrefixes(bindings)[binding.Prefix]; reserved {
		return binding, "", fmt.Errorf("prefix %s collides with %s", binding.Prefix, reason)
	}
	if err := binding.validate(name, bindings, reg.local, false); err != nil {
		return binding, "", err
	}

	var differences []string
	if static.Origin != "" && static.Origin != binding.Origin {
		differences = append(differences, fmt.Sprintf("upstream %s (bindings origin %s)", binding.Origin, static.Origin))
	}
	if static.Prefix != "" && static.Prefix != binding.Prefix {
		differences = append(differences, fmt.Sprintf("prefix %s (bindings prefix %s)", binding.Prefix, static.Prefix))
	}
	if reg.upstream != "" && hasStatic && static.Mount != binding.Mount {
		differences = append(differences, fmt.Sprintf("mount %q (bindings mount %q)", binding.Mount, static.Mount))
	}
	note := ""
	if len(differences) > 0 {
		note = fmt.Sprintf("service %s: contract overrides bindings: %s", name, strings.Join(differences, "; "))
	}
	return binding, note, nil
}

// sameOrigin compares two validated origins by scheme, host and port, ignoring
// case.
func sameOrigin(a, b string) bool {
	x, errX := url.Parse(a)
	y, errY := url.Parse(b)
	return errX == nil && errY == nil && strings.EqualFold(x.Scheme, y.Scheme) &&
		strings.EqualFold(x.Hostname(), y.Hostname()) && effectivePort(x) == effectivePort(y)
}

// reservedPrefixes maps each first path segment Darban serves itself to a
// description: the OpenAPI document endpoints, which gateway.serve answers
// before service routing, and the authorizer path.
func reservedPrefixes(bindings upstreamBindings) map[string]string {
	reserved := make(map[string]string)
	add := func(path, reason string) {
		if prefix := routePrefix(path); path != "" && path != "/" && prefix != "" {
			reserved[prefix] = reason
		}
	}
	add(bindings.OpenAPI.YAMLPath, "the OpenAPI YAML path "+bindings.OpenAPI.YAMLPath)
	add(bindings.OpenAPI.JSONPath, "the OpenAPI JSON path "+bindings.OpenAPI.JSONPath)
	if bindings.Authz != "" {
		add(bindings.Authorization.Path, "the authorization path "+bindings.Authorization.Path)
	}
	return reserved
}
