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

The bindings file is parsed strictly. An unknown key at any depth, or any
data after the JSON object, fails startup.

`bindings.services` entries are optional overrides. A contract that sets
`spec.upstream` needs none. Use an entry for what only bindings carry:
`operations`, `extraRoutes`, `debugOrigin`, `route` and `publish`. Its
`origin`, `prefix` and `mount` are the transition fallback for contracts
that do not yet set `spec.upstream`, and are validated when present.

## The proxy model

For a routed service, Darban is a route-aware reverse proxy that authorizes
before it routes:

1. **Match.** The method and path must match one of the service's contract
   operations (see [Operation paths](#operation-paths)) or one of its
   [`extraRoutes`](#extra-routes).
2. **Deny.** Anything else, and any `internal` operation, returns `404`.
   Nothing falls through to a prefix proxy.
3. **Authorize.** An operation with `x-darban-policy: anonymous`, and every
   operation of a service whose direct route sets `backendAuth`, goes to the
   backend with the caller's `Authorization` unchanged. Any other operation
   goes to the [authorizer](#authorization-and-debug-routing) first, with the
   caller's credentials as sent, whatever their scheme. A `2xx` answer
   proceeds, and `401`, `403` and `429` pass back to the caller. The
   contract's `security` and `securitySchemes` are documentation only: they
   must say what the operation needs, but Darban decides nothing from them.
4. **Proxy.** The upstream gets the identity headers the authorizer
   returned, trusted as returned, instead of the credentials. Caller copies
   of those headers and of `stripHeaderPrefixes` are always removed. Darban
   does not validate bodies, queries or schemas.
5. **Transport.** A service whose prefix has a
   [direct route](#direct-service-routes) is served with that route's
   transport. Otherwise it uses its contract upstream.

A service with `route: false` keeps its traffic on its direct route instead
(see [Route and publish](#route-and-publish)).

### Extra routes

`extraRoutes` on a routed service's binding lists paths it serves that its
contract cannot declare, such as probes, static assets and event streams:

```json
"extraRoutes": [
  {"method": "GET", "path": "/healthz", "auth": "none"},
  {"method": "GET", "path": "/assets/*", "auth": "none"},
  {"method": "GET", "path": "/events/{channel}", "auth": "gateway"}
]
```

- `method` is one of `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE` or
  `OPTIONS`, in capitals. `HEAD` matches a `GET` route as for operations.
- `path` is an upstream path like an operation's, under the mount, and may
  end in `/*` for a subtree, which also matches the path without it.
- `auth` is `gateway` (the authorizer decides, which needs `authz`) or
  `none` (the backend does).

They use the same matcher and guards as operations. An operation of the same
shape keeps its own path. Unknown keys, duplicates, a route on a
`route: false` service and an invalid method, path or `auth` fail startup.
They count as `routes` in `/status`, and never appear in the document.

### Route and publish

Two service binding booleans, both `true` by default, decide what a contract
does:

| `route` | `publish` | Traffic | Combined OpenAPI |
| --- | --- | --- | --- |
| `true` | `true` | Routed by the contract | Public operations included |
| `true` | `false` | Routed by the contract | Omitted, as if every operation were `unlisted` |
| `false` | `true` | Stays on the `serviceRoutes` entry | Public operations the direct route accepts |
| `false` | `false` | Stays on the `serviceRoutes` entry | Omitted |

With `route: false` the contract is docs-only. Darban validates its operations
in full, as it would for a routed contract, and reports it in `/status` and
under `contractServices`. It has no traffic effect: it adds no routes and no
denials, and the service's direct route keeps its own gating. The contract is
optional, and a rejected one changes only the document. Such a service cannot
select `operations` or define rewrites, and rewrites into it are denied with a
warning on their owner. Its component references are checked only when it
publishes.

`route: false` with `publish: true` documents the service's public operations
while its traffic stays on the direct route. It needs an explicit `prefix` that
has a `serviceRoutes` entry, and no `mount`. Darban leaves out, with a warning
in `/status`, every operation the direct route would refuse: one that its
`deniedPaths` may match, one that its `allowedPaths` do not cover, or an
anonymous operation that its `publicPaths` do not cover on a route without
`backendAuth`. A template is covered only when every path it stands for is.
Omissions never reject the contract.

A docs-only contract never costs a routed contract its place. When the two
conflict, for example on an `operationId` or a prefix, Darban rejects the
docs-only one, even when it has a last good contract.

With `publish: false` a routed service's operations, and the rewrites into or
out of it, are callable but left out of the document.

## Public paths and SDK names

Set `prefix` to one public service segment, such as `/catalog`. If the
upstream already uses a mount, set `mount` to strip it before adding the
prefix. For example, `mount: /inventory` and `prefix: /catalog` publish
`/inventory/v2/items` as `/catalog/v2/items`. Upstream paths determine the
version segments.

The composed OpenAPI preserves upstream `operationId` values and rejects
duplicates among published operations. A rewrite keeps the ID of the
original route when it has one.

A schema's `discriminator` is imported with it. Each `mapping` value, a
`#/components/schemas/X` reference or a bare `X`, imports `X` and is renamed
like a `$ref`, to `#/components/schemas/<service>.X` or `<service>.X`. A
discriminator has a string `propertyName`, an optional `mapping` of strings
and `x-` extensions, whose references are renamed too. Any other shape is
rejected. A property named `discriminator` is a name, not a discriminator, and
is imported as a schema. Without a full `mapping`, a discriminator infers a
value from each schema's name, which renaming would change. Darban therefore
adds a `mapping` entry, under the original name, for each `oneOf` or `anyOf`
schema that no mapping value targets. For a base schema without `oneOf` or
`anyOf`, it does the same for each schema that extends it with `allOf` and
that a published operation already references. It never publishes an
extender for this alone.

Values under `example`, `default`, `const` and `enum`, an Example Object's
`value` and a schema's list of `examples` are data and are copied as written. Where those words are names instead, such as a property called
`default`, the `default` response or a `default` entry under `examples`,
their objects are imported and their references renamed.

`openapi.prefixTags` controls how Darban groups operations for SDK generation.
The default `all` prefixes every tag with the lower-camel-case service name
and capitalizes the first letter of the upstream tag. For example, `items`
in `book-catalog` becomes `bookCatalogItems`. Set `firstOnly` to prefix the
first tag and leave the rest as written. Set `openapi.populateEmptyTags` to
`true` to add the service name as the tag when an operation has none. This
setting defaults to `false`.

## Operation paths

An operation path below the mount is a sequence of segments. Each is a
literal of `A-Z a-z 0-9 . _ ~ @ -` (but not `.` or `..`) or a whole
`{name}` parameter, such as `/items/{id}/reviews`. A template within a segment,
such as `/files/{name}.txt`, a repeated parameter name, an empty segment and a
trailing `/` are rejected, as are two operations with the same method and path
shape, such as `GET /items/{id}` and `GET /items/{itemId}`. That includes
`internal` operations. An `internal` operation may have any path: it is
denied as written, with a template inside a segment matching one or more
characters, so `/items{batch}` denies `/items:batch`. That also denies
`/itemsX`, which fails closed.

A request matches one segment at a time: a literal, then an `internal`
operation's in-segment template, then a parameter. It backtracks when the
rest of the path does not match. So `GET /items/new` wins over
`GET /items/{id}`, and `/items/new/reviews` still matches
`/items/{id}/reviews`. A parameter matches one non-empty segment. The
upstream receives the operation's upstream path with the decoded parameters,
re-encoded by Go's `url.URL` path escaping: the path that was matched, not the
caller's spelling of it. `HEAD` matches a `GET` operation unless the contract declares
`HEAD` for the path, and is then sent upstream as `GET`, so a backend need not
route `HEAD`. The caller gets the response headers without the body.

When a service's bindings select `operations`, the unselected ones still
take part in matching, as written like `internal` ones, so a selected template
cannot capture their paths. A template inside an unselected operation's
segment may claim more than the backend's literal does, so a match through
one is provisional. If the path, matched again without such templates,
reaches an `internal` or a selected operation at any depth, it returns
`404`. The direct route would skip a selected operation's authorization, and
routing the path to it could capture the unselected one. With an unselected
`/v1/items{batch}` and an internal `/{ver}/{id}`, or a selected `/v1/{c}`,
`/v1/itemsZ` and `/v1/items:batch` both return `404`.
On a prefix with a [direct Service route](#direct-service-routes) they go to
that route with its own policy, and elsewhere they return `404`.

Only a canonical path matches an operation (see
[Direct Service routes](#direct-service-routes)), and a path whose first
segment is encoded returns `404`. On a direct route a non-canonical path
returns `404`, and elsewhere it matches no operation, so it also returns
`404`. A parameter that decodes to `.`, `..`, or a value with `/` or `\`
returns `404`.

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

Set `authz` to the authorizer's private origin and `authorization` to how
Darban talks to it:

```json
"authorization": {
  "path": "/authz",
  "requestHeaders": ["Content-Type", "X-Tenant"],
  "responseHeaders": ["X-Identity", "X-Account"],
  "stripHeaderPrefixes": ["X-Identity-"]
}
```

- `path` is the authorizer path, requested with `GET`.
- `requestHeaders` are copied from the request to the authorizer, with the
  caller's `Authorization` and the original request as `X-Original-Method`,
  `X-Original-URI` and `X-Original-URL`. A request without exactly one
  non-empty `Authorization` header returns `401` without a call.
- `responseHeaders` are the identity the authorizer returns. Darban sends
  each single, non-empty one upstream, and removes caller copies of them
  from every request.
- `stripHeaderPrefixes` removes every request header with one of these
  prefixes.

Use `security` to state the credential policy on each operation. To allow
anonymous requests, set `security: []` and `x-darban-policy: anonymous`.
Rewrites use the destination's policy and schema. An internal source or
destination suppresses the alias. An unlisted source or destination keeps it
out of the document.

To enable an alternate backend, configure the service's `debugOrigin` and
`debug.requestHeader`, `debug.requiredHeader`, and `debug.requiredValue` in the
bindings. A request opts in by setting the debug header to `true`. The
authorizer must return the required value in a projected header. The
alternate Service must have a ready EndpointSlice. Otherwise the gateway
uses the primary Service. A failure after dispatch is returned to the caller.
A routed service on a direct route uses that route's transport, so it cannot
have a `debugOrigin`.

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
Service. By default the gateway authorizes its requests, which needs `authz`.
Set `backendAuth` for an origin that authenticates requests itself.

A routed service whose prefix has a direct route is served by its contract
(see [The proxy model](#the-proxy-model)) with the route's transport: its
`origin` and `upstreamHost`, timeouts and `longResponsePaths`, CORS mode,
cookie and `Location` rewriting, `forwardTrustedClientIP`, `X-Original-*`
headers and `legacyHosts`. Its contract upstream must have the route's
origin (scheme, host and port, ignoring case), and without one it uses the
route's origin. Gateway CORS applies to the operations the gateway
authorizes. Anonymous operations, `backendAuth` routes and `backendCORS`
routes leave CORS to the backend, so a preflight from an origin outside
`browserOrigins` reaches the backend. The route's path rules below do not
apply to it, except for the operations its `operations` selection leaves
out, which keep the route's own policy until the selection is removed.

For a service with `route: false`, or a prefix with no routed service, the
route's own policy decides. `publicPaths` lists exceptions to gateway
authorization. `allowedPaths` can restrict the exposed surface and
`deniedPaths` can exclude paths within it. A trailing `/*` matches a path
subtree. The rules see the decoded path. A direct route returns `404` for a path that is not canonical:
one with an empty, `.` or `..` segment (also when encoded), an encoded `/` or
`\` (`%2F`, `%5C`), a `\`, or anything else `path.Clean` changes beyond one
trailing `/`. It forwards the decoded path, re-encoded by Go's `url.URL` path
escaping, not the caller's spelling, so `/sdk/m%65` reaches the backend as
`/sdk/me` and `/a(1)` as `/a%281%29`.
Darban also returns `404` for a request whose first path segment is encoded.

`browserOrigins` lists the exact origins for gateway CORS, and
`upstreamRequestHeaders` allows safe request metadata. Requests the gateway
authorizes carry the identity returned by the authorizer. Others carry the
original credentials, and those on `backendAuth` routes also the original
request metadata.
Same-service redirects and cookie paths are scoped to the gateway prefix.

Set `backendCORS` to let a direct Service handle its own CORS responses,
including preflight. A preflight then reaches the backend without
authorization, since it carries no credentials. Set `forwardTrustedClientIP` only when the HTTP listener
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
  (its `prefix`, or `/<name>` when it has none, `route: false` included),
  whether or not that service has a contract yet;
- its prefix has a `serviceRoutes` direct route and its upstream (or bindings
  `mount`) has a path. A direct route proxies `<prefix>/X` to upstream `X`,
  so it cannot add a mount. A `bindings.services` entry that combines a
  `mount` with a `serviceRoutes` prefix is a startup error;
- it is routed, its prefix has a `serviceRoutes` direct route, and its
  upstream is not that route's origin;
- its prefix is the first path segment of `openapi.yamlPath`,
  `openapi.jsonPath` or `authorization.path`, which Darban serves or reserves.

### Installing the chart

CI publishes a multi-arch (`linux/amd64`, `linux/arm64`) image for every
push to `main`: `ghcr.io/zyno-io/darban:<short-sha>`, plus `:main` for the
newest commit. Pin the short-sha tag in deployments. You can also build the
image from the repository's Dockerfile. Supply the TLS certificate and key in a Secret named
`<release-name>-backend-tls`. Use Helm values to supply the image and
bindings. This example configures a catalog API and publishes both
OpenAPI formats.

```yaml
image: ghcr.io/zyno-io/darban:<short-sha>
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
configure an authorizer as described above. The
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
  missing credential policy, bad rewrites, unreadable `GatewayContract`), Darban
  keeps that service's last good compiled contract. Without one, the service
  is omitted. The other services update normally.
- A service with no accepted contract is not installed: its public prefix
  returns `404` like any unknown path. That covers a bad first contract, a
  `bindings.services` entry with no contract, and a deleted `GatewayContract`.
  Only a bad **update** keeps the service's last good unit in memory; deleting
  the contract removes the service.
- A routed service whose prefix has a `serviceRoutes` direct route serves
  only what its contract declares. With no good contract, including after
  the contract was deleted, only that direct route fails closed with `503`
  until a good contract arrives, exactly as on a fresh pod. Rewrites into a service that is not installed are denied.
  Services with `route: false` keep proxying through `serviceRoutes`.
- Checks across services still apply: duplicate `operationId` values, routes
  that shadow the OpenAPI endpoints, and prefix collisions. Darban first keeps every service's last good contract, then tries
  each changed contract and keeps the last good one when the change conflicts.
  After each rejection the selection restarts from the last good contracts, so a
  service with a last good contract is only ever current or last-good, unless
  it is docs-only and conflicts with a routed service (see
  [Route and publish](#route-and-publish)).
  A rewrite whose served target lacks the destination (missing or rewritten
  operation, or a path outside the target's mount) is denied and reported as a
  warning on the owner in `/status`. It never rejects either service, so the
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
arrives). For a service with `route: false` the state describes only its
contract: its traffic stays on the direct route either way.
`route` and `publish` are the service's binding settings. `routes`,
`documented` and `denied` count the public operation keys under the service's
prefix, including the rewrites it owns, that the active snapshot routes,
documents and denies. `warnings` lists the service's rewrites that are denied
although their target is served, and the operations a publish-only service
leaves out of the document. The endpoint returns `503` during startup or drain. The chart's Role covers its own namespace. Allow the gateway's
ServiceAccount to list and watch EndpointSlices in every other namespace named
in its bindings.

## License

Darban is available under the [MIT License](LICENSE).
