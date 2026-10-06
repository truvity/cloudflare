package edge

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/truvity/cloudflare/v2/pkg/tunnel"
)

// ReleaseBase is the name stem of a cloudflared Helm release and of its
// tunnel-token Secret.
const ReleaseBase = "cloudflared"

// TunnelName is the tunnel's name in Cloudflare, and the name its Pulumi
// resources are registered under: the cluster alone for an account with
// legacy names (the tunnel that predates a second account), and
// <cluster>-<account> for any other.
func TunnelName(cluster, account string, legacy bool) string {
	return suffixed(cluster, account, legacy)
}

// ReleaseName is the cloudflared Helm release of one tunnel, and the suffix of
// its Application's name: ReleaseBase, or ReleaseBase-<account>.
func ReleaseName(account string, legacy bool) string {
	return suffixed(ReleaseBase, account, legacy)
}

// SecretName is the Kubernetes Secret holding the tunnel's token.
func SecretName(account string, legacy bool) string {
	return suffixed(ReleaseBase, account, legacy) + "-tunnel-token"
}

func suffixed(base, account string, legacy bool) string {
	if legacy {
		return base
	}

	return base + "-" + account
}

// ZoneOf returns the zone a hostname lies in: the longest of zones that is
// the name itself or one of its parents (a wildcard's `*.` is not a label of
// the zone), or "" when none holds it.
func ZoneOf(zones []string, host string) string {
	name := strings.ToLower(strings.TrimPrefix(host, "*."))
	best := ""

	for _, zone := range zones {
		if (name == zone || strings.HasSuffix(name, "."+zone)) && len(zone) > len(best) {
			best = zone
		}
	}

	return best
}

type (
	// Group is one named set of hostnames a cluster serves on one exposure.
	Group struct {
		Name    string
		Cluster string
		// Hosts are the group's hostnames, exact or a leading wildcard.
		Hosts []string
		// RouteNamespaces are the namespaces the group admits routes from.
		RouteNamespaces []string
	}

	// Exposure is one way names arrive through Cloudflare tunnels: the
	// accounts its tunnels may use and the groups it serves.
	Exposure struct {
		Name string
		// Accounts the exposure's tunnels may use. Required.
		Accounts []string
		Groups   []Group
	}

	// DeriveInput is everything Derive reads.
	DeriveInput struct {
		// Exposures are the exposures that arrive by a Cloudflare tunnel.
		Exposures []Exposure
		// Zones maps each zone name to the account that owns it.
		Zones map[string]string
		// LegacyNames maps each account to its legacy-names flag. Its keys
		// are the known accounts.
		LegacyNames map[string]bool
		// Business names the projects whose groups are cached at the edge.
		Business map[string]struct{}
		// CacheZones are the zones that declare a cache policy; only they get
		// CacheHosts.
		CacheZones []string
	}

	// Derived is what Derive returns.
	Derived struct {
		// Tunnels are one per (cluster, account), sorted by cluster then
		// account, hosts in ingress order. DNSDomain is left empty.
		Tunnels []Tunnel
		// CacheHosts maps each cache zone to its sorted, de-duplicated hosts.
		CacheHosts map[string][]string
	}
)

// Derive resolves every host of every exposure to its zone and account,
// groups the hosts into one tunnel per (cluster, account) in ingress order
// (tunnel.OrderHosts), and derives each cache zone's hosts. A host outside
// every zone, or in a zone of an account its exposure does not list, is
// refused here, where the exposure is still known. Callers pass exposures,
// clusters and groups in a stable order so the first refusal is stable.
func Derive(in DeriveInput) (Derived, error) {
	zones := sortedKeys(in.Zones)

	type key struct{ cluster, account string }

	hosts := map[key][]string{}

	for _, e := range in.Exposures {
		if len(e.Accounts) == 0 {
			return Derived{}, fmt.Errorf("exposures[%s] arrives by a Cloudflare tunnel and lists no accounts: name the accounts its tunnels may use", e.Name)
		}

		for _, account := range e.Accounts {
			if _, ok := in.LegacyNames[account]; !ok {
				return Derived{}, fmt.Errorf("exposures[%s].accounts: no account %q (known: %s)", e.Name, account, strings.Join(sortedKeys(in.LegacyNames), ", "))
			}
		}

		for _, g := range e.Groups {
			for _, host := range g.Hosts {
				zone := ZoneOf(zones, host)
				if zone == "" {
					return Derived{}, fmt.Errorf("exposures[%s].clusters[%s].groups[%s]: %q lies in no zone (%s)",
						e.Name, g.Cluster, g.Name, host, strings.Join(zones, ", "))
				}

				account := in.Zones[zone]
				if !slices.Contains(e.Accounts, account) {
					return Derived{}, fmt.Errorf(
						"exposures[%s].clusters[%s].groups[%s]: %q is in zone %s of account %q, and the exposure arrives through %v: "+
							"list the account on the exposure, or serve the name elsewhere",
						e.Name, g.Cluster, g.Name, host, zone, account, e.Accounts)
				}

				k := key{g.Cluster, account}
				hosts[k] = append(hosts[k], host)
			}
		}
	}

	out := Derived{CacheHosts: deriveCache(in, zones)}

	for k, list := range hosts {
		ordered := tunnel.OrderHosts(list)

		inZone := map[string]bool{}
		for _, host := range ordered {
			inZone[ZoneOf(zones, host)] = true
		}

		// pkg/tunnel creates a tunnel's CNAMEs in ONE zone. Two zones in one
		// account on one cluster need the library to take a zone per name
		// first; until then this is refused rather than half-served.
		if len(inZone) > 1 {
			return Derived{}, fmt.Errorf(
				"the %s tunnel of account %q would carry names in zones %s; a tunnel's records live in one zone (pkg/tunnel DNS) until it takes one per name",
				k.cluster, k.account, strings.Join(sortedKeys(inZone), ", "))
		}

		out.Tunnels = append(out.Tunnels, Tunnel{
			Name:    TunnelName(k.cluster, k.account, in.LegacyNames[k.account]),
			Cluster: k.cluster,
			Account: k.account,
			Zone:    ZoneOf(zones, ordered[0]),
			Hosts:   ordered,
		})
	}

	sortTunnels(out.Tunnels)

	return out, nil
}

func sortTunnels(tunnels []Tunnel) {
	slices.SortFunc(tunnels, func(a, b Tunnel) int {
		if d := strings.Compare(a.Cluster, b.Cluster); d != 0 {
			return d
		}

		return strings.Compare(a.Account, b.Account)
	})
}

// deriveCache is each cache zone's hosts: every exact name a BUSINESS
// project is served on, from an exposure that arrives from the internet.
//
// WHY DERIVED, AND WHY THESE. A zone caches by file extension unless it is
// told otherwise: a response under a name ending in .js or .css is stored at
// the edge whether or not its origin asked, and where the origin sent no
// Cache-Control the zone claims four hours of the browser's. That is how a
// single-page console, which answers its own unknown paths with its shell,
// ends up with one page cached under another page's name.
//
// The answer is not "cache less" but "cache what an origin asked for", and
// only where an origin is in a position to ask. A business project's chart is
// the estate's own, ships content-addressed assets and sets the headers to say
// so. A platform console is somebody else's chart on somebody else's release
// cycle. Those are left out, and left out is safe: the rules this list feeds
// bypass everything they do not name.
//
// A group is a business project's when EVERY namespace it admits routes from
// is a project. Mixed or unknown reads as platform, which caches nothing: the
// failure this direction is a request that reached a pod the long way, and the
// other is a response held at the edge that nobody meant to publish.
//
// A WILDCARD IS NOT A PROJECT'S CLAIM ON EVERY NAME UNDER IT. `*.<tier>.<zone>`
// matches every name of that tier, including the consoles other groups serve,
// whose bundles are the reason this list exists. A suffix test cannot say
// "except those", so a wildcard is left out and the exact names beside it carry
// the policy.
func deriveCache(in DeriveInput, zones []string) map[string][]string {
	if len(in.CacheZones) == 0 {
		return nil
	}

	byZone := map[string][]string{}

	for _, e := range in.Exposures {
		for _, g := range e.Groups {
			if !businessGroup(g, in.Business) {
				continue
			}

			for _, host := range g.Hosts {
				if strings.HasPrefix(host, "*.") {
					continue
				}

				if zone := ZoneOf(zones, host); zone != "" {
					byZone[zone] = append(byZone[zone], host)
				}
			}
		}
	}

	out := make(map[string][]string, len(in.CacheZones))

	for _, zone := range in.CacheZones {
		hosts := byZone[zone]
		slices.Sort(hosts)

		out[zone] = slices.Compact(hosts)
	}

	return out
}

// businessGroup reports whether every namespace a group admits routes from is
// a business project.
func businessGroup(g Group, business map[string]struct{}) bool {
	if len(g.RouteNamespaces) == 0 {
		return false
	}

	for _, ns := range g.RouteNamespaces {
		if _, ok := business[ns]; !ok {
			return false
		}
	}

	return true
}

// ValidateRouting enforces the tunnel ingress invariants cloudflared cannot
// check itself:
//   - every hostname is unique across every tunnel, and so across every zone
//     and account: a duplicate makes two ingress rules (or two tunnels) claim
//     one DNS name, and only the first ever receives traffic;
//   - within a tunnel, no rule is caught by an EARLIER rule, with
//     cloudflared's own matching: an exact host after a wildcard that covers
//     it, or a deeper wildcard after a broader one (`*` spans dots). A
//     shadowed rule is unreachable, and its traffic arrives under the
//     shadowing rule's SNI (see tunnel.OrderHosts).
func ValidateRouting(tunnels []Tunnel) error {
	sorted := slices.Clone(tunnels)
	sortTunnels(sorted)

	seen := map[string]string{} // lowercased host to "tunnel cluster/account: hosts[i]"

	for _, t := range sorted {
		for i, host := range t.Hosts {
			key := strings.ToLower(host)
			at := fmt.Sprintf("tunnel %s/%s: hosts[%d]", t.Cluster, t.Account, i)

			if prev, ok := seen[key]; ok {
				return fmt.Errorf("%s: hostname %q already declared at %s", at, host, prev)
			}

			seen[key] = at

			for _, earlier := range t.Hosts[:i] {
				if tunnel.Covers(strings.ToLower(earlier), key) {
					return fmt.Errorf(
						"%s: %q is shadowed by earlier rule %q: exact hosts first, "+
							"deeper wildcards before broader ones (first match wins; origin SNI = matched rule)",
						at, host, earlier)
				}
			}
		}
	}

	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}

	sort.Strings(out)

	return out
}
