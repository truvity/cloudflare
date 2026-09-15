// Package cloudflare is the module root of github.com/truvity/cloudflare.
//
// The module ships Cloudflare mechanism for Kubernetes estates:
//
//   - pkg/account — one API token bound to one account, as a provider a
//     caller passes to everything it creates there. A token is
//     account-scoped and a tunnel cannot cross accounts, so an estate with
//     zones in several accounts writes the account as data, not as code.
//   - pkg/zone — the handful of zone-level settings an estate decides:
//     how Cloudflare reaches the origin, the floor it negotiates with a
//     browser, and Total TLS, which issues a certificate per proxied
//     hostname so adding one needs no certificate resource.
//   - pkg/tunnel — a tunnel, its ingress rules, the DNS records that point
//     hostnames at it and (opt-in) Advanced Certificate packs, from one
//     config struct; the tunnel token comes back as an Output for the
//     caller to store.
//   - charts/cloudflared — the in-cluster daemon, one install per account.
//
// Nothing in this module names an account, a zone, a hostname or a secret
// store; those are the caller's inputs.
package cloudflare
