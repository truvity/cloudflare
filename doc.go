// Package cloudflare is the module root of github.com/truvity/edge/v4.
//
// The module ships Cloudflare mechanism for Kubernetes estates, as Pulumi
// Go components and the in-cluster Helm chart a tunnel needs:
//
//   - cloudflare/account — one API token bound to one account, as a provider a
//     caller passes to everything it creates there. A token is
//     account-scoped and a tunnel cannot cross accounts, so an estate with
//     zones in several accounts writes the account as data, not as code.
//     NewChildToken mints a least-privilege, account-owned token scoped to
//     one zone, one R2 bucket or the whole account, under the root token
//     the estate's Pulumi program runs as; NewChildTokenSet mints a whole
//     map of them in one call, in sorted order — see docs/cloudflare/layout.md for
//     the recommended root/edge/r2 split this makes reusable.
//   - cloudflare/zone — the handful of zone-level settings an estate decides:
//     how Cloudflare reaches the origin, the floor it negotiates with a
//     browser, and Total TLS, which issues a certificate per proxied
//     hostname so adding one needs no certificate resource.
//   - cloudflare/tunnel — a tunnel, its ingress rules, the DNS records that point
//     hostnames at it and (opt-in) Advanced Certificate packs, from one
//     config struct; the tunnel token comes back as an Output for the
//     caller to store.
//   - cloudflare/r2 — one R2 bucket, an opt-in expiry lifecycle, and an
//     account-owned API token scoped to exactly that bucket, plus the
//     S3-compatible credential pair Cloudflare derives from it.
//   - cloudflare/cfnames — pure Cloudflare naming and validity rules (the R2
//     jurisdiction list, the R2 bucket-name syntax check) with no SDK
//     import of any kind, not even this module's own cloudflare/account or
//     cloudflare/r2, for a caller that only needs to validate a value.
//   - cloudflare/presettoken — the client of a sluis Cloudflare preset: a short-lived
//     credential from sluisctl (or, in break-glass, minted from the account
//     root), verified before it is handed out; every estate fact is a
//     parameter.
//   - cloudflare/prototypes — the disabled prototype tokens a sluis preset is cloned
//     from, declared on the default provider so the root never enters the
//     state.
//   - charts/cloudflared — the in-cluster tunnel daemon, one install per
//     account.
//
// Nothing in this module names an account, a zone, a hostname or a
// secret store; those are the caller's inputs.
package cloudflare
