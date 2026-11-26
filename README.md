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

### Pre-flight checks

`-contracts FILE` reads a `GatewayContract` list, as
`kubectl get gatewaycontracts -o json` prints it, and decodes each item
exactly as cluster mode does. It is one-shot only, with `-print-spec` or
`-report`:

```bash
kubectl get gatewaycontracts -n zyno-alpha -o json > contracts.json
darban -contracts contracts.json -bindings bindings.json -print-spec
darban -contracts contracts.json -bindings bindings.json -report
```

`-report` prints a stable, diffable table of what the gateway does, and exits
`1` when a contract is rejected or a rewrite targets a service without a
contract:

- a line per service with `publish`, its state and its counts, then its
  transport (origin, mount, `upstreamHost`, `legacyHosts`, long-response
  settings, `backendAuth`, `backendCORS`, `forwardRequestHeaders`,
  `debugOrigin` and `enabled`), and any rejection or warning. A bindings entry without a contract shows as
  `state=missing`, and a disabled service as `state=disabled`;
- a line per contract operation:
  `METHOD path service visibility documented=yes|no -> outcome`;
- a line per rewrite and per extra route;
- a summary of the outcomes.

The outcome is `404 internal`, `404 unselected` (left out by the service's
`operations`), `404 unmatched`, `503 closed` (a bound service without an
accepted contract), `503 disabled` (a service with `enabled: false`) or
`proxy auth=authz|none|backend`. `authz` is the
gateway's authorizer, `none` an anonymous operation or extra route, and
`backend` a `backendAuth` service. `-print-spec` fails on the same rejections
and rewrites, but not on a missing contract, which only closes that service.

## Services

Every service is described by its contract, and optionally by an entry under
`bindings.services.<name>`. There is no other way to route traffic.

- **Discovery.** A contract that sets `spec.upstream` needs no entry. It is
  served at `spec.prefix`, or `/<serviceName>` without one, with the defaults
  below.
- **Overrides.** An entry with the contract's service name overrides the
  fields it sets, one at a time, and leaves the others to the contract. Its
  `origin` and `mount` replace those of `spec.upstream`, and its `prefix`
  replaces `spec.prefix`. Darban logs each disagreement once per distinct
  value. Fields only bindings carry, such as `extraRoutes`, `backendAuth` or
  `legacyHosts`, are added to the contract's.
- **Origins.** Without an entry `origin`, the contract chooses its own
  upstream: whoever can edit the `GatewayContract` decides where the
  service's traffic goes, with its credentials, forwarded headers and legacy
  hosts. Pin `origin` in bindings for every sensitive service, such as one
  with `backendAuth`, `forwardRequestHeaders` or `legacyHosts`. A contract
  whose `spec.upstream` names another origin is then still served at the
  pinned one, and the disagreement is logged.
- **No contract.** An entry whose service has no accepted contract serves
  nothing: its prefix and its legacy hosts return `503` for every request,
  extra routes included, until a good contract arrives. A contract with
  neither `spec.upstream` nor an entry `origin` is rejected.
- **Kill switch.** An entry with `enabled: false`, which may be all it says,
  turns the service off. Its prefix and legacy hosts return `503` for every
  request: nothing is proxied, extra routes included, and its operations
  leave the combined OpenAPI. Its contract is still validated, reported and
  kept as last good, and it keeps its prefix and legacy hosts, so no other
  contract can claim them while it is off. A rewrite from another service
  into it is denied, with a warning on the owner, and never rejects the
  owner's contract. Remove the field, or set it to `true`, to turn the
  service back on.
- **Local mode.** A `-manifest` entry may set `upstream` and `prefix`, and
  merges with bindings the same way.

The bindings file is parsed strictly. An unknown key at any depth, or any
data after the JSON object, fails startup. A changed file is reloaded in place (see
[Bindings reload](#bindings-reload)). A minimal file for a gateway
whose contracts all set `spec.upstream` is:

```json
{"hostname": "api.example.net", "contractAPIGroup": "darban.zyno.io"}
```

An entry that adds settings to a discovered service:

```json
"services": {
  "auth": {"backendAuth": true, "forwardRequestHeaders": ["X-Tenant"],
    "legacyHosts": ["auth.example.net"], "backendCORS": true},
  "suite": {"extraRoutes": [{"method": "GET", "path": "/assets/*", "auth": "none"}],
    "longResponsePaths": ["/exports/*"], "longResponseHeaderTimeout": "10m"}
}
```

### Service settings

Every field is optional.

| Field | Default | Meaning |
| --- | --- | --- |
| `prefix` | `spec.prefix`, else `/<name>` | The public path segment. |
| `origin` | from `spec.upstream` | The upstream's scheme, host and port: a private Service. |
| `mount` | path of `spec.upstream` | The upstream path that `prefix` stands for. |
| `enabled` | `true` | `false` serves nothing, with `503`, and keeps the prefix. |
| `publish` | `true` | `false` keeps the service out of the combined OpenAPI. |
| `operations` | every operation | Serve only the listed contract operations (see [Operation paths](#operation-paths)). |
| `extraRoutes` | none | Paths the contract cannot declare (see [Extra routes](#extra-routes)). |
| `debugOrigin` | none | An alternate backend (see [Debug routing](#authorization-and-debug-routing)). |
| `upstreamHost` | the origin's host | The `Host` header sent upstream. |
| `legacyHosts` | none | Hostnames that reach the service without the prefix. |
| `backendAuth` | `false` | Leave every request's authorization to the backend. |
| `forwardRequestHeaders` | none | Identity headers a `backendAuth` backend gets as the caller sent them. |
| `backendCORS` | `false` | Leave CORS, including preflights, to the backend. |
| `longResponsePaths` | none | Upstream paths with their own response-header timeout. |
| `longResponseHeaderTimeout` | none | That timeout, a Go duration; set with `longResponsePaths`. |

Startup fails on:

- an invalid value;
- two services with the same effective prefix (a `prefix`, or `/<name>`
  without one);
- a prefix that is the first segment of `openapi.yamlPath`,
  `openapi.jsonPath` or `authorization.path`;
- a legacy host used twice, or equal to `hostname`, or on a service with a
  `mount` (a legacy host serves the backend's own paths; a contract whose
  upstream has a path is rejected the same way);
- `forwardRequestHeaders` without `backendAuth`, or naming `Authorization`,
  `Host`, `Forwarded`, a client-address header, `X-Forwarded-*`,
  `X-Original-*`, or a hop-by-hop or framing header such as `Connection`,
  `Upgrade`, `Te`, `Keep-Alive` or `Proxy-Authorization`;
- `longResponsePaths` without `longResponseHeaderTimeout`, or the reverse;
- a `debugOrigin` without the `debug` settings;
- an extra route with `auth: gateway` on a `backendAuth` service, or without
  `authz`.

A contract with operations the gateway must authorize is rejected when
`authz` is unset and the service is not `backendAuth`. `-print-spec` and
`-report` skip that check, since they need no authorizer.

## The verified flow

Darban is a route-aware reverse proxy that authorizes before it routes. Every
request on every service and legacy host takes the same steps:

1. **Match.** The method and path must match one of the service's contract
   operations (see [Operation paths](#operation-paths)) or one of its
   [`extraRoutes`](#extra-routes).
2. **Deny.** Anything else returns `404`: an undeclared method or path, an
   `internal` operation, an operation the service's `operations` leave out,
   a non-canonical path and a path whose first segment is encoded. Nothing
   falls through to a prefix proxy. A bound service without an accepted
   contract returns `503` instead.
3. **Authorize.** An operation with `x-darban-policy: anonymous`, an extra
   route with `auth: none`, and every request to a `backendAuth` service go to
   the backend with the caller's `Authorization` unchanged. Anything else
   goes to the [authorizer](#authorization-and-debug-routing) first, with the
   caller's credentials as sent, whatever their scheme. A `2xx` answer
   proceeds, and `401`, `403` and `429` pass back to the caller. The
   contract's `security` and `securitySchemes` are documentation only: they
   must say what the operation needs, but Darban decides nothing from them.
4. **Proxy.** The request goes to the service's upstream through its
   [transport](#transport). The upstream gets the identity headers the
   authorizer returned, trusted as returned, instead of the credentials.
   Caller copies of those headers and of `stripHeaderPrefixes` are always
   removed. Darban does not validate bodies, queries or schemas.

### Extra routes

`extraRoutes` lists paths a service serves that its contract cannot declare,
such as probes, static assets and event streams:

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
  `none` (the backend does). A `backendAuth` service takes only `none`.

They use the same matcher and guards as operations. An operation of the same
shape keeps its own policy. Unknown keys, two routes of one method and path
shape, and an invalid method, path or `auth` fail startup. They count as
`routes` in `/status`, and never appear in the document. An extra route is
served only while its service has an accepted contract.

### Transport

Each service has one proxy, used for its own operations, its extra routes,
the rewrites that target it and its debug origin. A rewrite goes to its
target's upstream path through the target's proxy, with the target's
settings, whichever service owns it.

- The path sent is the operation's upstream path with the decoded
  parameters, re-encoded by Go's `url.URL` path escaping: the path that was
  matched, not the caller's spelling of it. So `/sdk/m%65` reaches the
  backend as `/sdk/me`, and `/a(1)` as `/a%281%29`. A trailing `/` on the
  request is kept. The query is sent as received.
- `Host` is `upstreamHost` when set, the legacy hostname on a legacy host,
  and otherwise the origin's host.
- The response-header timeout is 60 seconds, or `longResponseHeaderTimeout`
  for an upstream path in `longResponsePaths`, where a trailing `/*` matches a
  subtree. The timeout covers the wait for the upstream's response headers
  after the request body is sent. Debug requests use the same timeouts and
  no keep-alive, so an `Idempotency-Key` is never retried implicitly.
- On the canonical hostname, a `Location` header that points at the upstream
  (or at `https://<upstreamHost>`), and a cookie `Path`, are mapped from the
  mount to the prefix. A cookie path outside the mount becomes the prefix, and
  the cookie's `Domain` is removed. A legacy host keeps the upstream's paths.
- `X-Original-Method`, `X-Original-URI` and `X-Original-URL` describe the
  public request on a `backendAuth` service.
- `Forwarded`, every `X-Forwarded-*` header, and the client-address headers
  `X-Real-IP`, `Client-IP`, `True-Client-IP`, `X-Client-IP`,
  `X-Cluster-Client-IP`, `X-Original-Forwarded-For`, `CF-Connecting-IP`,
  `Fastly-Client-IP` and `X-Envoy-External-Address` are removed, whoever sent
  them. The client
  address travels in `X-Real-IP` only (see [Client IP](#client-ip)).

`browserOrigins` lists the exact origins for gateway CORS, and
`upstreamRequestHeaders` allows safe request metadata to every upstream.
Requests the gateway authorizes carry the identity returned by the
authorizer. Others carry the original credentials, and those on `backendAuth`
services also the `authorization.requestHeaders` that name no identity. A
caller's copy of an identity header, one of `authorization.responseHeaders`
or with a stripped prefix, is removed even there, unless the service lists it
in `forwardRequestHeaders`, for example tenant selectors an authenticating
backend reads.

Gateway CORS applies to the requests the gateway authorizes. Anonymous
operations and `backendAuth` services leave CORS to the backend, so a
preflight from an origin outside `browserOrigins` reaches the backend. With
`backendCORS` the backend handles all of its CORS responses. A real
preflight, an `OPTIONS` request whose `Access-Control-Request-Method` names
another method, then reaches the backend without authorization, since it
carries no credentials, whether or not `browserOrigins` is set. It must be for
a path and method the service serves, and a contract `OPTIONS` operation on
the path is served as itself, with its own policy. For a rewrite, the service
that serves the path decides: a preflight reaches the backend only when the
rewrite's target is `backendCORS`.

During a hostname migration, set a service's `legacyHosts` to the exact DNS
names it previously served. A request on a legacy host is matched as the
same path under the prefix, with the same verified flow and authorization.
Darban uses the original URL for authorization and preserves the legacy
hostname, cookie scope, paths and redirects. The combined OpenAPI stays on the
canonical hostname.

### Client IP

Every upstream request carries the caller's address in `X-Real-IP`. Darban
removes every caller copy first, so a caller cannot choose the value:

```json
"clientIP": {"header": "X-Real-IP", "trustedProxies": ["10.200.0.0/16"]}
```

1. The connection's peer is trusted only when it is in `trustedProxies`, a
   list of CIDRs or addresses. The list is empty by default, so no peer is
   trusted and every upstream sees the peer address. **A deployment behind an
   ingress must list the ingress's addresses**, such as the cluster's pod
   CIDR when a NetworkPolicy already limits the gateway's traffic port to the
   ingress pods (the chart's `ingress.enabled`).
2. From a trusted peer, `header` (default `X-Real-IP`) gives the address when
   it holds exactly one valid IP address, without a zone. An IPv4-mapped
   IPv6 address is sent as IPv4.
3. Otherwise, the peer's own address is sent.

The ingress must overwrite `header` with the address it saw. `header` is one
of `X-Real-IP`, `CF-Connecting-IP`, `True-Client-IP`, `X-Client-IP`,
`X-Cluster-Client-IP`, `Fastly-Client-IP` or `X-Envoy-External-Address`, and
is never forwarded under its own name. `X-Real-IP` is set
after every other header, so neither a copied request header nor an identity
header the authorizer returns can change it.

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
`/items/{id}/reviews`. A parameter matches one non-empty segment, and one
trailing `/` is allowed. `HEAD` matches a `GET` operation unless the contract
declares `HEAD` for the path, and is then sent upstream as `GET`, so a backend
need not route `HEAD`. The caller gets the response headers without the body.

When a service's bindings select `operations`, the unselected ones still
take part in matching, as written like `internal` ones, so a selected template
cannot capture their paths, and they return `404`. A template inside an
unselected operation's segment may claim more than the backend's literal
does, so a match through one is provisional. If the path, matched again
without such templates, reaches an `internal` or a selected operation at any
depth, it returns `404`, since routing it there could capture the unselected
one. With an unselected `/v1/items{batch}` and an internal `/{ver}/{id}`, or a
selected `/v1/{c}`, `/v1/itemsZ` and `/v1/items:batch` both return `404`.

Only a canonical path matches. Darban returns `404` for a path with an empty,
`.` or `..` segment (also when encoded), an encoded `/` or `\` (`%2F`,
`%5C`), a `\`, or anything else `path.Clean` changes beyond one trailing `/`,
and for a request whose first path segment is encoded. A parameter that
decodes to `.`, `..`, or a value with `/` or `\` returns `404`.

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
  non-empty `Authorization` header returns `401` without a call. They
  cannot name a hop-by-hop header: `Connection`, `Keep-Alive`,
  `Proxy-Connection`, `Te`, `Trailer`, `Transfer-Encoding` or `Upgrade`.
- `responseHeaders` are the identity the authorizer returns. Darban sends
  each single, non-empty one upstream, and removes caller copies of them
  from every request. They cannot name a header Darban manages, such as
  `Authorization`, `X-Forwarded-*` or a client-address header.
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
uses the primary Service. The debug origin gets the request with the same
settings as the primary: path, headers, client IP and timeouts. A failure
after dispatch is returned to the caller.

### Combined OpenAPI endpoints

Each configured endpoint serves bytes generated when the gateway accepts a
contract snapshot. `GET` returns the document and `HEAD` returns its headers.
Omit `openapi` to disable publication or configure either path independently.
Configure `omitOperationExtensionPrefixes` to remove selected source vendor
extensions from published operations.

The YAML document is written from the JSON one, with the same content.
Characters YAML cannot hold as they are, such as DEL, C1 controls and U+FFFE,
are escaped, and U+0085 is written as `\N`. Keys of any length are allowed;
a long or multi-line one is a YAML complex key (`? key`).

```json
{
  "defaultVisibility": "public",
  "openapi": {
    "yamlPath": "/openapi.yaml",
    "jsonPath": "/openapi.json"
  }
}
```

## Kubernetes discovery and status

The gateway reads bindings JSON from `/config/bindings.json` and its TLS
certificate and key from `/tls/` by default. The local manifest points to
OpenAPI YAML and rewrite YAML. Kubernetes registers the same information in
namespaced `GatewayContract` resources under `contractAPIGroup`.

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
- A path is the upstream mount. It must be literal, and must not end with
  `/`. Query, fragment and userinfo are rejected.
- `spec.prefix` defaults to `/<serviceName>` and is one public segment.
  `https` upstreams use the `upstreamTLS` settings below.
- A bindings entry overrides any of these (see [Services](#services)).
- In a local manifest, a contract entry may set `upstream` and `prefix` and
  may use loopback hosts. There is no namespace check.

Each contract is admitted or rejected on its own, with the reason in
`/status` and the logs. A contract is rejected, and keeps its last good
version if it had one, when:

- its upstream URL is invalid or in another namespace, or it has no upstream
  at all;
- its prefix collides with another contract: the older `creationTimestamp`
  keeps serving, then the lower service name;
- its prefix is reserved by a `bindings.services` entry of another service
  (its `prefix`, or `/<name>` when it has none), whether or not that service
  has a contract yet;
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

The chart requests 64Mi of memory and limits it to 256Mi. Composing the
contracts needs more than serving them: eight full-size contracts peak near
120Mi while they compose. Raise `resources.limits.memory` for a larger set.

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

Service origins (`spec.upstream`, `services[*].origin`, `debugOrigin`)
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

### Bindings reload

Darban reloads the `-bindings` file while it runs. It reads the file every
two seconds and compares the SHA-256 of its content, so the atomic `..data`
symlink swap of a ConfigMap volume is picked up whatever the file times say.
On a change it:

1. parses and validates the file as strictly as at startup;
2. checks that nothing changed that cannot change at runtime;
3. compiles the current contracts with it, including the last good contract
   of a service whose current one is rejected; and
4. swaps the snapshot, which carries the new bindings, in one atomic store.

A request is served entirely by one bindings revision, and readiness never
changes during a reload. On any error, the active bindings keep serving, and
the error is logged once and shown in `/status` as `lastBindingsError`, with
the `revision` of the rejected content (none when the file could not be
read). A
file that does not parse, validate or hot-swap is not tried again until its
content changes. A failure that does not depend on the content, such as
contracts that cannot be read, is retried on the next read. A reload does not
read `upstreamTLS.caFile`: the verifier re-reads it on its own. A reload that
costs a service its last good contract, because that contract no longer
compiles with the new bindings, still applies. The service fails closed like
any bound service without an accepted contract, its `/status` reason says
why, and the reload's `bindingsWarnings` and log list it. `contractAPIGroup`, `upstreamTLS` and, in cluster mode,
the set of Services named outside the watched namespace (whose
EndpointSlices are watched by name) cannot change at runtime: such a change
is rejected with an error that says to restart the gateway. Everything else
in the bindings applies in place.

The chart rolls the pods only when one of those changes: `contractAPIGroup`,
`upstreamTLS`, or the Services that `authz`, `origin` and `debugOrigin` name
outside the release namespace. Set `rolloutOnBindingsChange: true` to roll them on every bindings
change, as before reloads existed. The chart reads those keys by their exact
names, so spell every bindings key exactly as documented, although Darban
itself accepts any letter case.

### Contract isolation

Darban compiles each service's contract on its own, so one service cannot
block the others once the gateway is running.

- A contract for a service that is not in `bindings.services` is admitted
  when it sets `spec.upstream`. Without an upstream or a bindings origin it is
  rejected, logged, and reported in `/status`.
- If a service's contract fails to compile (invalid OpenAPI or visibility,
  missing credential policy, bad rewrites, unreadable `GatewayContract`), Darban
  keeps that service's last good compiled contract. The other services update
  normally. Only a bad **update** keeps the last good unit in memory; deleting
  the contract removes it.
- A service with no accepted contract, after a bad first contract, with no
  contract or after its `GatewayContract` was deleted, is not served:
  - with a `bindings.services` entry, its prefix and legacy hosts fail closed
    with `503` until a good contract arrives, exactly as on a fresh pod;
  - without one, nothing reserves its prefix, which returns `404` like any
    unknown path.

  Rewrites into a service that is not served, or not known at all, are
  denied, with a warning on their owner. A rewrite target must be a valid
  service name.
- Checks across services still apply: duplicate `operationId` values, routes
  that hide the OpenAPI endpoints, and prefix collisions. Darban first keeps
  every service's last good contract, then tries each changed contract and
  keeps the last good one when the change conflicts. After each rejection the
  selection restarts from the last good contracts, so a service with a last
  good contract is only ever current or last-good.
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
contract is bad is not served on the new pods (`503` with a bindings entry,
`404` without) while old pods still serve their last good unit. Darban writes
nothing to Kubernetes.

Darban has no Prometheus registry, so the rejections appear in `/status` only.

### Status

`GET /status` on the private admin port (8081) reports the active revision,
the bindings (`bindingsRevision`, the SHA-256 of the active file,
`bindingsLoadedAt`, and `lastBindingsError` with its message and time, which
stays after a later reload succeeds), route count, and EndpointSlice state
for the authorizer and each backend,
including the upstreams that contracts add at runtime. Darban watches every
EndpointSlice in its own namespace, and the Services named in `bindings` in
other namespaces.

`contracts` lists each service with a contract, a rejected contract, or a
bindings entry without a contract:

- `serving` is `current`, `last-good` (the current contract was rejected), or
  `none`.
- `rejected` is true while the current contract is being rejected.
  `lastRejection` holds the latest message and its RFC3339 time and remains
  after the contract is fixed.
- `missing` marks a bindings entry with no contract.
- `enabled` is false for a service turned off with `enabled: false`.
- `state` is the outcome, with a `reason`: `serving`, `serving_last_good`
  (the current contract was rejected), `closed` (a bindings entry without an
  accepted contract, whose prefix returns `503`), `disabled` (turned off with
  `enabled: false`; its prefix returns `503`, whatever its contract), or
  `not_installed` (a discovered contract that was never accepted; its prefix
  returns `404`).
- `publish` is the service's binding setting.
- `routes`, `documented` and `denied` count the public operation keys under
  the service's prefix, including the rewrites it owns and its extra routes,
  that the active snapshot routes, documents and denies.
- `warnings` lists the service's rewrites that are denied although their
  target is served.

The endpoint returns `503` during startup or drain. The chart's Role covers its own namespace. Allow the gateway's
ServiceAccount to list and watch EndpointSlices in every other namespace named
in its bindings.

## License

Darban is available under the [MIT License](LICENSE).
