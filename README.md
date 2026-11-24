# Darban

Darban is an OpenAPI-driven HTTP reverse proxy by Zyno Consulting. It routes
HTTP APIs through one hostname. It watches service
contracts, compiles routes and combined OpenAPI into one immutable snapshot,
and keeps each service's last accepted contract if an update fails validation.

## Development

```bash
go test ./...
go vet ./...
go run . -manifest testdata/local.yaml -bindings testdata/bindings.json -print-spec
```

Set `-namespace` for Kubernetes discovery or `-manifest` for local files.
The gateway reads bindings JSON from `/config/bindings.json` and its TLS
certificate and key from `/tls/` by default. The local manifest points to
OpenAPI YAML and rewrite YAML. Kubernetes registers the same information in
namespaced `GatewayContract` resources under `contractAPIGroup`. A contract
names its own upstream (see [Contract upstreams](#contract-upstreams)), so a
backend can join the gateway without a bindings entry.

`bindings.services` entries are optional overrides. A contract that sets
`spec.upstream` needs none. Use an entry for what only bindings carry:
`operations` (with `legacy`), `debugOrigin` and `registrationOnly`. Its
`origin`, `prefix` and `mount` are the transition fallback for contracts
that do not yet set `spec.upstream`, and are validated when present.

Set `registrationOnly: true` on a service binding to accept the backend's
contract ahead of routing migration. The contract is optional at startup, and
Darban validates its OpenAPI document and reports the loaded service under
`contractServices` on the status endpoint. Existing service routes continue
to handle traffic. Operation selections and rewrites require an active
contract binding.

An operation selection can carry a `legacy` block with the `source` security
requirements and the target credential `profiles`. Darban replaces the source
security with the target profiles. If the operation already declares exactly
the target requirements, in any order, Darban accepts it unchanged, so a
service can switch to the target security before the bindings drop `legacy`.
Any other security is rejected as a legacy security mismatch.

## Public paths and SDK names

Set `prefix` to one public service segment, such as `/catalog`. If the
upstream already uses a mount, set `mount` to strip it before adding the
prefix. For example, `mount: /inventory` and `prefix: /catalog` publish
`/inventory/v2/items` as `/catalog/v2/items`. Upstream paths determine the
version segments.

The composed OpenAPI preserves upstream `operationId` values and rejects
duplicates among published operations. A rewrite keeps the ID of the
original route when it has one.

`openapi.prefixTags` controls how Darban groups operations for SDK generation.
The default `all` prefixes every tag with the lower-camel-case service name
and capitalizes the first letter of the upstream tag. For example, `items`
in `book-catalog` becomes `bookCatalogItems`. Set `firstOnly` to prefix the
first tag and leave the rest as written. Set `openapi.populateEmptyTags` to
`true` to add the service name as the tag when an operation has none. This
setting defaults to `false`.

## Operation visibility

Set `x-darban-visibility` on the OpenAPI operation, such as `paths./example.get`.

| Value | Routing | Combined OpenAPI |
| --- | --- | --- |
| `public` | Callable with the operation's credential policy | Included |
| `unlisted` | Callable with the operation's credential policy | Omitted |
| `internal` | Excluded from the gateway's route table | Omitted |

An operation tag overrides `GatewayContract.spec.defaultVisibility` or the
local contract entry's `defaultVisibility`. The service setting overrides
`defaultVisibility` in the proxy bindings, which defaults to `public`.

### Authorization and debug routing

Use `authz` for the private origin and `authorization.path` for the HTTP
authorizer path. Each `authorization.profiles` entry names an OpenAPI HTTP
security scheme and specifies its `scheme` and `requiredHeaders`. The gateway
forwards credentials, original request metadata, and `authorization.requestHeaders`
to the authorizer. It projects only `authorization.responseHeaders` upstream
and requires the configured identity headers before forwarding. It strips
caller-supplied copies and any `authorization.stripHeaderPrefixes`.

Use `security` to select the credential policy on each operation. To allow
anonymous requests, set `security: []` and `x-gateway-policy: anonymous`.
Rewrites use the destination's credentials and schema. An internal source or
destination suppresses the alias. An unlisted source or destination keeps it
out of the document.

To enable an alternate backend, configure the service's `debugOrigin` and
`debug.requestHeader`, `debug.requiredHeader`, and `debug.requiredValue` in the
bindings. A request opts in by setting the debug header to `true`. The
authorizer must return the required value in a projected header. The
alternate Service must have a ready EndpointSlice. Otherwise the gateway
uses the primary Service. A failure after dispatch is returned to the caller.

### Combined OpenAPI endpoints

Each configured endpoint serves bytes generated when the gateway accepts a
contract snapshot. `GET` returns the document and `HEAD` returns its headers.
Omit `openapi` to disable publication or configure either path independently.
Configure `omitOperationExtensionPrefixes` to remove selected source vendor
extensions from published operations.

```json
{
  "defaultVisibility": "public",
  "openapi": {
    "yamlPath": "/openapi.yaml",
    "jsonPath": "/openapi.json"
  }
}
```

## Direct Service routes

`serviceRoutes` binds a single-segment path prefix to a private Kubernetes
Service. A route chooses credential profiles for the gateway's authorization
subrequest or explicitly sets `backendAuth` for an origin that authenticates
requests itself. `publicPaths` lists exceptions to gateway authorization.
`allowedPaths` can restrict the exposed surface and `deniedPaths` can exclude
paths within it. A trailing `/*` matches a path subtree. Registered operations
and internal-route exclusions take precedence.

`browserOrigins` lists the exact origins for gateway CORS, and
`upstreamRequestHeaders` allows safe request metadata. Protected service
routes receive the identity returned by the authorizer. Backend-authenticated
routes receive the original credentials and request metadata.
Same-service redirects and cookie paths are scoped to the gateway prefix.

Set `backendCORS` to let a direct Service handle its own CORS responses,
including preflight. Set `forwardTrustedClientIP` only when the HTTP listener
is reachable exclusively through an ingress that overwrites `X-Real-IP` with
the verified connection address. On those Service routes, Darban forwards a
single valid IP address and returns 503 if the header is missing or invalid.

During a hostname migration, set a service route's `legacyHosts` to the
exact DNS names it previously served. Each name belongs to one service.
Requests on a legacy host use the same path rules and authorization
as the equivalent prefixed route. Darban uses the original URL for
authorization and preserves the legacy hostname. Direct Service routes also
preserve the upstream cookie scope, path, and redirects. The combined OpenAPI
stays on the canonical hostname.

For long-running service requests, set `longResponsePaths` and
`longResponseHeaderTimeout` together. The timeout covers the wait for the
upstream's response headers after sending the request body. Other paths
keep the regular timeout.

## Kubernetes discovery and status

Install the [GatewayContract CRD](deploy/gateway-contract-crd.yaml) before
deploying Darban. The Helm chart and CRD use `darban.zyno.io` by default.
For a different group, install the same CRD with that group and set
`bindings.contractAPIGroup` to match. Name each contract
`api-contract-<serviceName>`. Specify `spec.serviceName`, `spec.upstream`, `spec.rewrites`, and
one of `spec.openapi.yaml` or `spec.openapi.gzipBase64`. Set `spec.openapi.sha256`
to the SHA-256 of the original YAML. The gateway caps the inline field at
1,400,000 bytes and decoded gzip at 16 MiB. Kubernetes and Helm storage limits
also apply.

### Contract upstreams

Every `GatewayContract` in the watched namespace is a candidate. It names
its backend with `spec.upstream`, a URL, and its public path with the optional
`spec.prefix`:

```yaml
apiVersion: darban.zyno.io/v1alpha1
kind: GatewayContract
metadata:
  name: api-contract-hosting
spec:
  serviceName: hosting
  upstream: http://hosting-manager.zyno-alpha.svc.cluster.local/hosting
  prefix: /hosting
  openapi: { yaml: "...", sha256: "..." }
  rewrites: []
```

- Scheme is `http` or `https`. The host must be a Service in the contract's own
  namespace: `<svc>`, `<svc>.<ns>`, `<svc>.<ns>.svc` or
  `<svc>.<ns>.svc.cluster.local`, with `<ns>` equal to that namespace and `<svc>`
  a DNS-1035 label. Darban normalises to the full form. The port defaults to
  80 for `http` and 443 for `https`, and is stored explicitly.
- A path is the upstream mount. It replaces the bindings `mount`, must be
  literal, and must not end with `/`. Query, fragment and userinfo are rejected.
- `spec.prefix` defaults to `/<serviceName>` and is one public segment.
  `https` upstreams use the `upstreamTLS` settings below.
- Without `spec.upstream`, the contract uses `bindings.services.<name>`'s
  `origin`, `prefix` and `mount`. With neither, it is rejected. When both
  exist, the contract wins and Darban logs the disagreement once per
  distinct value.
- In a local manifest, a contract entry may set `upstream` and `prefix` and
  may use loopback hosts. There is no namespace check.

Each contract is admitted or rejected on its own, with the reason in
`/status` and the logs. A contract is rejected, and keeps its last good
version if it had one, when:

- its upstream URL is invalid or in another namespace;
- its prefix collides with another contract: the older `creationTimestamp`
  keeps serving, then the lower service name;
- its prefix is a `serviceRoutes` prefix that the service does not own.
  Ownership means a bindings entry for the same service name with that
  prefix, and that service's `spec.prefix` must stay on it;
- its prefix is reserved by a `bindings.services` entry of another service
  (its `prefix`, or `/<name>` when it has none, `registrationOnly` included),
  whether or not that service has a contract yet;
- its prefix has a `serviceRoutes` direct route and its upstream (or bindings
  `mount`) has a path. A direct route proxies `<prefix>/X` to upstream `X`, so
  a mount would make its `internal` deny list miss the public paths. A
  `bindings.services` entry that combines a `mount` with a `serviceRoutes`
  prefix is a startup error;
- its prefix is the first path segment of `openapi.yamlPath`,
  `openapi.jsonPath` or `authorization.path`, which Darban serves or reserves.

### Installing the chart

Build the image from the repository's Dockerfile and make it available to
your cluster. Supply the TLS certificate and key in a Secret named
`<release-name>-backend-tls`. Use Helm values to supply the image and
bindings. This example configures a catalog API and publishes both
OpenAPI formats.

```yaml
image: registry.example.net/darban:dev
bindings:
  hostname: api.example.net
  openapi:
    yamlPath: /openapi.yaml
    jsonPath: /openapi.json
  services:
    catalog:
      origin: http://catalog.darban.svc.cluster.local:8080
      prefix: /catalog
```

```bash
kubectl apply --server-side -f deploy/gateway-contract-crd.yaml
helm upgrade --install darban ./charts/darban --namespace darban -f values.local.yaml
```

Register `api-contract-catalog` in the same namespace. The example API
must declare anonymous operations explicitly. To serve protected operations,
configure an authorizer and credential profiles as described above. The
chart creates a ClusterIP Service. Set `ingress.enabled`, `ingress.namespace`,
and `ingress.gatewayName` to restrict its traffic port to a Gateway API
controller's labeled pods.

### HTTPS upstreams

Service origins (`services[*].origin`, `debugOrigin`, `serviceRoutes[*].origin`)
and `authz` accept `http://` or `https://`. The host rules, the required port
and the ban on path, query, userinfo and fragment are unchanged. Upstream TLS
uses TLS 1.2 or later and applies to every upstream transport.

```json
"upstreamTLS": { "caFile": "/etc/darban/upstream-ca/ca.crt", "insecureSkipVerify": false }
```

- With neither option, Darban verifies upstreams against the system roots.
  The image ships the CA bundle at `/etc/ssl/certs/ca-certificates.crt`.
- `caFile` verifies against only the certificates in that PEM bundle,
  replacing the system roots. Hostname verification stays on, including for
  IP targets, which must appear in the certificate's IP SANs. The file must
  parse at startup or Darban exits. It is re-read every 10 seconds, like the
  serving certificate. A bundle that fails to parse keeps the last good one
  and logs each distinct error once. New connections use the current bundle.
- `insecureSkipVerify: true` disables verification and logs a warning at
  startup. Setting it together with `caFile` is a configuration error.

In the chart, set `upstreamTLS.caSecretName` or `upstreamTLS.caConfigMapName`
(not both) and optionally `upstreamTLS.key` (default `ca.crt`). The chart
mounts it at `/etc/darban/upstream-ca` and sets `bindings.upstreamTLS.caFile`
to match. Leaving them unset changes nothing.

### Contract isolation

Darban compiles each service's contract on its own, so one service cannot
block the others once the gateway is running.

- A contract for a service that is not in `bindings.services` is admitted
  when it sets `spec.upstream`. Without an upstream or a bindings origin it is
  rejected, logged, and reported in `/status`.
- If a service's contract fails to compile (invalid OpenAPI or visibility,
  legacy security mismatch, bad rewrites, unreadable `GatewayContract`), Darban
  keeps that service's last good compiled contract. Without one, the service
  is omitted. The other services update normally.
- A service with no accepted contract is not installed: its public prefix
  returns `404` like any unknown path. That covers a bad first contract, a
  `bindings.services` entry with no contract, and a deleted `GatewayContract`.
  Only a bad **update** keeps the service's last good unit in memory; deleting
  the contract removes the service.
- A service whose prefix has a `serviceRoutes` direct route (proxy-all minus
  the `internal` operations) needs its contract to know those operations.
  With no good contract, including after the contract was deleted, only that
  direct route fails closed with `503` until a good contract arrives, exactly
  as on a fresh pod. Rewrites into a service that is not installed are denied.
  Registration-only services keep proxying through `serviceRoutes`.
- Checks across services still apply: duplicate `operationId` values, routes
  that shadow the OpenAPI endpoints, and prefix collisions. Darban first keeps every service's last good contract, then tries
  each changed contract and keeps the last good one when the change conflicts.
  After each rejection the selection restarts from the last good contracts, so a
  service with a last good contract is only ever current or last-good.
  A rewrite whose served target lacks the destination (missing or rewritten
  operation, or a path outside the target's mount) is denied and reported as a
  `warning` on the owner in `/status`. It never rejects either service, so the
  outcome does not depend on arrival order. A service
  that was never good is admitted after the established ones. Two contracts
  that claim one prefix conflict the same way. Among new or
  changed contracts, the `GatewayContract` with the older
  `metadata.creationTimestamp` wins, then the lower service name. A running
  pod keeps an established contract against a changed conflicting one even
  when the changed one is older, so a fresh pod can pick differently in that
  case.
- Rejections log `contract candidate rejected` with the service name once per
  distinct message. A failure to read the contract sources at all keeps the
  whole active snapshot. A `GatewayContract` whose name does not map to a
  service is logged and skipped. In local manifest mode an entry with an
  unreadable file is rejected on its own the same way.

Readiness never waits on contracts. A new pod is ready once the
`GatewayContract` informer has synced and the first snapshot is built,
whatever contracts are valid: a bad contract, a missing contract or no
contracts at all. A manifest that cannot be parsed at all keeps the pod unready.

Last-good state lives in memory, per pod. A restarted or new pod treats every
contract as first-seen, so during a Darban rollout a service whose current
contract is bad is not installed on the new pods (`404`, or `503` on its direct
route) while old pods still serve their last good unit. Darban writes nothing
to Kubernetes.

Darban has no Prometheus registry, so the rejections appear in `/status` only.

### Status

`GET /status` on the private admin port (8081) reports the active revision,
route count, and EndpointSlice state for the authorizer and each backend,
including the upstreams that contracts add at runtime. Darban watches every
EndpointSlice in its own namespace, and the Services named in `bindings` in
other namespaces.
`contracts` lists each service with a contract, a rejected contract, or no
contract. `serving` is `current`, `last-good` (the current contract was
rejected), or `none`. `rejected` is true while the current contract is being
rejected. `lastRejection` holds the latest message and its RFC3339 time and
remains after the contract is fixed. `missing` marks a bound service with no
contract. `state` is the explicit outcome per service, with a `reason`:
`serving`, `serving_last_good` (the current contract was rejected),
`not_installed` (no accepted contract: never accepted, or deleted; the
prefix returns `404`), or `direct_route_closed` (no accepted contract and the
service has a direct route, which returns `503` until a good contract
arrives). The endpoint returns `503` during startup or drain. The chart's Role covers its own namespace. Allow the gateway's
ServiceAccount to list and watch EndpointSlices in every other namespace named
in its bindings.

## License

Darban is available under the [MIT License](LICENSE).
