// Package cloudflare is the module root of github.com/truvity/cloudflare.
//
// The module ships Cloudflare mechanism for Kubernetes estates: the
// cloudflared Helm chart under charts/, and (planned) pkg/tunnel — a
// Pulumi Go component that creates a tunnel, its DNS records and ingress
// rules from a config struct, returning the tunnel token as an Output for
// the caller to store. Nothing in this module names an account, a zone or
// a secret store; those are the caller's inputs.
package cloudflare
