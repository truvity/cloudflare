// Package cloudflare is the module root of github.com/truvity/cloudflare/v2.
//
// The module ships Cloudflare mechanism for Kubernetes estates, as Pulumi
// Go components, a temporary-credentials broker, and the in-cluster Helm
// charts each needs:
//
//   - pkg/account — one API token bound to one account, as a provider a
//     caller passes to everything it creates there. A token is
//     account-scoped and a tunnel cannot cross accounts, so an estate with
//     zones in several accounts writes the account as data, not as code.
//     NewChildToken mints a least-privilege, account-owned token scoped to
//     one zone, one R2 bucket or the whole account, under the root token
//     the estate's Pulumi program runs as; NewChildTokenSet mints a whole
//     map of them in one call, in sorted order — see docs/layout.md for
//     the recommended root/edge/r2 split this makes reusable.
//   - pkg/zone — the handful of zone-level settings an estate decides:
//     how Cloudflare reaches the origin, the floor it negotiates with a
//     browser, and Total TLS, which issues a certificate per proxied
//     hostname so adding one needs no certificate resource.
//   - pkg/tunnel — a tunnel, its ingress rules, the DNS records that point
//     hostnames at it and (opt-in) Advanced Certificate packs, from one
//     config struct; the tunnel token comes back as an Output for the
//     caller to store.
//   - pkg/r2 — one R2 bucket, an opt-in expiry lifecycle, and an
//     account-owned API token scoped to exactly that bucket, plus the
//     S3-compatible credential pair Cloudflare derives from it.
//   - pkg/cfnames — pure Cloudflare naming and validity rules (the R2
//     jurisdiction list, the R2 bucket-name syntax check) with no SDK
//     import of any kind, not even this module's own pkg/account or
//     pkg/r2, for a caller that only needs to validate a value.
//   - cmd/r2broker — the R2 temporary-credentials broker: `r2broker serve`
//     (the HTTP service) and `r2broker credentials` (a client of it, or an
//     in-process standalone mode) — one binary, group-only OIDC in, scoped
//     temporary R2 credentials out, its own audit catalogue for every mint
//     and refusal.
//   - charts/cloudflared — the in-cluster tunnel daemon, one install per
//     account.
//   - charts/r2-broker — the broker's Deployment, Service and
//     ServiceAccount; `grants: []` renders a broker that verifies tokens
//     and refuses every request, not a load error.
//
// Nothing in this module names an account, a zone, a hostname, an OIDC
// issuer or a secret store; those are the caller's inputs.
package cloudflare
