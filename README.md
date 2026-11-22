# Darban

Darban is an OpenAPI-driven HTTP reverse proxy by Zyno Consulting. It routes
HTTP APIs through one hostname. It watches service
contracts, compiles routes and combined OpenAPI into one immutable snapshot,
and keeps the last accepted snapshot if an update fails validation.

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
namespaced `GatewayContract` resources under `contractAPIGroup`.

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
`api-contract-<serviceName>`. Specify `spec.serviceName`, `spec.rewrites`, and
one of `spec.openapi.yaml` or `spec.openapi.gzipBase64`. Set `spec.openapi.sha256`
to the SHA-256 of the original YAML. The gateway caps the inline field at
1,400,000 bytes and decoded gzip at 16 MiB. Kubernetes and Helm storage limits
also apply. Legacy ConfigMaps can register contracts using the
`<contractAPIGroup>/contract=true` label. A `GatewayContract` takes precedence.

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

### Status

`GET /status` on the private admin port (8081) reports the active revision,
route count, and EndpointSlice state for the authorizer and each backend.
The endpoint returns `503` during startup or drain. Allow the gateway's
ServiceAccount to list and watch EndpointSlices in every namespace named in
its bindings.

## License

Darban is available under the [MIT License](LICENSE).
