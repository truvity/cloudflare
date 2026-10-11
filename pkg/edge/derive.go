package edge

import "github.com/truvity/cloudflare/v2/pkg/edgespec"

// The derivation and routing rules live in pkg/edgespec, which links no
// Pulumi or Cloudflare SDK; they are re-exported here so existing callers
// keep compiling. A caller that only derives and validates tunnels should
// import pkg/edgespec directly.

// ReleaseBase is the name stem of a cloudflared Helm release and of its
// tunnel-token Secret.
const ReleaseBase = edgespec.ReleaseBase

type (
	// Group is one named set of hostnames a cluster serves on one exposure.
	Group = edgespec.Group
	// Exposure is one way names arrive through Cloudflare tunnels.
	Exposure = edgespec.Exposure
	// DeriveInput is everything Derive reads.
	DeriveInput = edgespec.DeriveInput
	// Derived is what Derive returns.
	Derived = edgespec.Derived
)

// TunnelName is the tunnel's name in Cloudflare. See edgespec.TunnelName.
func TunnelName(cluster, account string, legacy bool) string {
	return edgespec.TunnelName(cluster, account, legacy)
}

// ReleaseName is the cloudflared Helm release of one tunnel. See
// edgespec.ReleaseName.
func ReleaseName(account string, legacy bool) string {
	return edgespec.ReleaseName(account, legacy)
}

// SecretName is the Kubernetes Secret holding the tunnel's token. See
// edgespec.SecretName.
func SecretName(account string, legacy bool) string {
	return edgespec.SecretName(account, legacy)
}

// ZoneOf returns the zone a hostname lies in. See edgespec.ZoneOf.
func ZoneOf(zones []string, host string) string { return edgespec.ZoneOf(zones, host) }

// Derive resolves every host of every exposure to its zone and account and
// groups the hosts into one tunnel per (cluster, account). See
// edgespec.Derive.
func Derive(in DeriveInput) (Derived, error) { return edgespec.Derive(in) }

// ValidateRouting refuses a hostname declared twice across tunnels and a
// rule shadowed by an earlier one. See edgespec.ValidateRouting.
func ValidateRouting(tunnels []Tunnel) error { return edgespec.ValidateRouting(tunnels) }
