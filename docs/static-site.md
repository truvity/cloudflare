# static-site

One generic Go server (`cmd/static-site`) and one chart (`charts/static-site`)
serve every static site. The site is data, an OCI artifact; the server and the
chart are the same for all of them.

```
site CI ──oras push──► registry: static/<site>@sha256:…
                                   │ pull by digest (startup, SIGHUP)
                         static-site pods (several replicas)
                                   │
                         CDN in front (caches by headers, no purge)
```

A promotion tool (Kargo, or anything that can write a Helm value) promotes the
artifact by setting `site.artifact.digest`; the chart takes the digest as a
value of its own, independent of the tag in `site.artifact.ref`.

## The artifact

Push it with `oras`, under `static/<site>` in your registry:

```sh
# a directory: one tar+gzip layer, unpacked at the root of the site
oras push registry.example.com/static/www:main ./dist
# or single files, each named by its title annotation
oras push registry.example.com/static/www:main index.html css/site.css
```

Accepted layers: a tar (gzip or not; a layer with the media type
`application/vnd.oci.image.layer.v1.tar[+gzip]` or the `oras` unpack
annotation), and any other layer with an
`org.opencontainers.image.title` annotation, written as that file. The
manifest must be an image manifest, not an index. Layers are verified against
their digests while they are read. Only regular files and directories are
accepted: a link, device, absolute path or `..` in an archive fails the load.
Size and file count are capped (`site.maxBytes`, `site.maxFiles`).

Credentials come from a `kubernetes.io/dockerconfigjson` Secret named by
`site.pullSecretName`, mounted as the Docker config file.

## Serving

| | |
|---|---|
| Content-Type | from a built-in table, then the host's types, else `application/octet-stream`. Never sniffed; `X-Content-Type-Options: nosniff` is sent |
| ETag | strong, a hash of the bytes served (after substitution). `If-None-Match` answers 304. No `Last-Modified`, so replicas agree |
| hashed names | `Cache-Control: public, max-age=31536000, immutable` when the base name matches `cache.hashedPattern` (default: a `.`, `-` or `_` then 8 or more hex digits then the extension, such as `app.3f9a1c2b.js`). HTML is never immutable |
| everything else | `public, max-age=<cache.htmlMaxAge>` (default 60s) `, stale-while-revalidate=<cache.staleWhileRevalidate>` (default 300s) |
| directories | `/dir/` serves `/dir/index.html`; `/dir` redirects to `/dir/`; a directory with no index is a 404, never a listing |
| 404 | `site.notFoundPage` (default `404.html`) with status 404 and `no-store`, else a plain 404 |
| SPA | with `site.spaFallback`, an extensionless path that matches no file serves `/index.html` with 200; a missing asset is still a 404 |
| methods | GET and HEAD; anything else is 405 |
| paths | a `..` segment, NUL or backslash is a 400. Only files indexed from the unpacked tree can be served, and symlinks are not indexed |
| headers | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`; `headers` adds or overrides, an empty value removes one (add a `Content-Security-Policy` here) |

There is no cache purge: a new site version has new hashed assets, and its HTML
is stale for at most `htmlMaxAge` plus `staleWhileRevalidate`. The server does
not compress; let the CDN do it.

## Placeholders

`{{ name }}` (spaces optional) in `.html`, `.htm`, `.js`, `.mjs`, `.css`,
`.json` and `.webmanifest` files is replaced at load time by the value of the
allowlisted name; the chart value `placeholders` is that allowlist.

- A name that is not in the allowlist is left exactly as written.
- Other file types are never touched.
- A value may use only `A-Za-z0-9 ._:/@#+=,~-` (at most 512 characters); the
  server refuses to start on anything else, and the chart's schema refuses it
  at render. These values land in public pages: do not put secrets in them.
- Values are also escaped for the file type (HTML entities; JS `\xNN`; CSS
  `\hex `; JSON string escapes). In JS and JSON the token has to sit inside a
  string literal: `var id = '{{ gtmId }}'`.
- The ETag is computed after substitution, so changing a value changes the
  ETag and the pods roll (the chart checksums the placeholder file).

## Operations

- Site port 8080, ops port 8081: `/healthz` (process up), `/readyz` (content
  loaded and not shutting down), `/metrics` (Prometheus: requests, duration,
  loads, `static_site_content_info{digest}`, load time, file count).
- JSON logs on stdout; requests are logged at info only when they end in 4xx or
  5xx (`STATIC_SITE_LOG_LEVEL=debug` for all).
- `SIGHUP` reloads (a moved tag is re-resolved); a failed reload keeps serving
  the previous content. The previous copy is deleted after 30 seconds. The
  content volume holds both during a reload, which is why it is sized (and
  memory-limited) for two.
- On SIGTERM the server turns not-ready, waits `STATIC_SITE_SHUTDOWN_DELAY`
  (5s), then drains. The image is `gcr.io/distroless/static:nonroot`; the chart
  runs as 65532 with a read-only root file system and no capabilities.

All server settings are `STATIC_SITE_*` environment variables, listed in
`internal/staticsite/config.go`; the chart sets them from its values.
`STATIC_SITE_DIR` serves a local directory instead of pulling, for development.

## The chart

`site.artifact.ref` is `registry/repository[:tag]` (no digest), `site.artifact.digest`
is `sha256:…`; the digest wins over a tag. Replicas default to 2 with a
PodDisruptionBudget of `minAvailable: 1`. `serviceMonitor.enabled` renders a
ServiceMonitor for the ops port; `networkPolicy.enabled` allows ingress to the
site and ops ports (restricted by `ingressFrom` and `metricsFrom` when set) and
egress to DNS and HTTPS. `values.schema.json` is strict at the top level, and
every refusal has a fixture under `tests/invalid/static-site/`.

## Release

The image is built by this repository's goreleaser configuration (the `kos`
section, `gcr.io/distroless/static:nonroot`, linux/amd64 and arm64) and pushed
by the shared release workflow's `ko-docker-repo` input to
`ghcr.io/truvity/edge/static-site:<version>`, in the same job and at the same
tag as the charts and the Go module. The chart's `appVersion` is stamped with
that version and is the default `image.tag`, so a chart release always runs the
server release it was published with.
