// Package zonespec holds the pure side of a zone's settings: the declaration
// types (Args and its blocks), their validation, and the Cloudflare filter
// expressions rendered from them. No Cloudflare API call, no Pulumi
// resource, no SDK import of any kind: an estate's config layer that only
// validates a zone's declaration links this package and not the Pulumi and
// Cloudflare SDKs that pkg/zone imports to apply it. pkg/zone re-exports
// every type here as an alias, so existing callers keep compiling.
//
// TestNoNonStdlibImports fails the moment this package imports anything
// outside the standard library.
package zonespec

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Shortest prefixes a trusted range may have: anything broader is close to
// "the internet" and defeats the rule's purpose.
const (
	minTrustedBitsV4 = 8
	minTrustedBitsV6 = 16
)

// DefaultTrustedDescription describes the trusted-clients rule when
// TrustedClients.Description is empty.
const DefaultTrustedDescription = "Trusted clients: skip security features"

var (
	validSSL           = []string{"off", "flexible", "full", "strict"}
	validMinTLSVersion = []string{"1.0", "1.1", "1.2", "1.3"}
	validCA            = []string{"google", "lets_encrypt", "ssl_com"}
)

type (
	// TotalTLS asks the zone to issue a certificate for every proxied A,
	// AAAA or CNAME record, so a new hostname needs no certificate
	// resource of its own. Requires Advanced Certificate Manager.
	TotalTLS struct {
		// Enabled turns per-hostname issuance on. Required.
		Enabled bool `json:"enabled" yaml:"enabled"`
		// CertificateAuthority to issue through: google, lets_encrypt or
		// ssl_com. Empty leaves Cloudflare's default.
		CertificateAuthority string `json:"certificateAuthority,omitempty" yaml:"certificateAuthority,omitempty"`
	}

	// Cache decides WHICH of a zone's hostnames may be cached at all, and
	// leaves HOW LONG to the origin that serves them.
	//
	// The default it replaces is the reason it exists. A zone caches by
	// file extension: a response under a name ending in .js or .css is
	// stored at the edge whether or not its origin asked for that, and
	// where the origin sent no Cache-Control the zone tells the browser
	// to keep it for four hours. An application that answers its own
	// unknown paths — a single-page console serving its shell under every
	// name — then has one page cached under another page's name, and
	// nobody wrote that down anywhere.
	//
	// So a zone with this block caches the hostnames it lists and nothing
	// else, and each of those only as far as its own Cache-Control goes.
	// A response with no Cache-Control is not cached. Which means the
	// decision belongs where it can be read: in the application that
	// serves the bytes and knows whether they are content-addressed.
	Cache struct {
		// Hosts whose responses may be cached: an exact name
		// ("app.example") or one leading wildcard label
		// ("*.app.example").
		//
		// An EMPTY list is a policy and not an omission — the zone
		// caches nothing at all, which is what a zone serving only
		// applications that authenticate every request wants. To leave
		// caching unmanaged, omit the block.
		Hosts []string `json:"hosts" yaml:"hosts"`
		// RespectOriginBrowserTTL sets the zone setting Browser Cache
		// TTL to "Respect Existing Headers".
		//
		// The rules above decide what the EDGE stores. This is the
		// `Cache-Control` Cloudflare writes on the way out when the
		// origin sent none, and left alone it claims four hours for
		// every response of the zone — including the ones no rule here
		// caches, which is a browser holding what the edge would not.
		// False leaves the zone's setting as it is.
		RespectOriginBrowserTTL bool `json:"respectOriginBrowserTtl,omitempty" yaml:"respectOriginBrowserTtl,omitempty"`
	}

	// TrustedClients exempts client address ranges from the zone's
	// Cloudflare security features on named hosts: ONE zone custom-firewall
	// rule with action `skip`. A request to one of Hosts from an address in
	// Ranges skips the remaining custom rules, managed rules, rate
	// limiting, Super Bot Fight Mode and the legacy security products.
	//
	// For a known machine-to-machine caller whose egress is published (a
	// connector platform's address range): it keeps that caller from ever
	// meeting a challenge a later rule might introduce. It is not a
	// workaround for a rule that blocks it today.
	//
	// Both lists empty manages no ruleset at all. One empty and the other
	// not is refused: the rule would match nothing.
	TrustedClients struct {
		// Zone is the zone's domain ("example.com"). Required when Hosts
		// is not empty: every host must be the zone itself or a name
		// inside it.
		Zone string `json:"zone,omitempty" yaml:"zone,omitempty"`
		// Hosts are exact lower-case hostnames inside Zone. No wildcards.
		Hosts []string `json:"hosts" yaml:"hosts"`
		// Ranges are CIDR blocks, IPv4 or IPv6, with no host bits set.
		// Shorter than /8 (IPv4) or /16 (IPv6) is refused as too broad.
		Ranges []string `json:"ranges" yaml:"ranges"`
		// Description of the rule, shown in the dashboard and in security
		// events. Empty uses "Trusted clients: skip security features".
		Description string `json:"description,omitempty" yaml:"description,omitempty"`
	}

	// Args is one zone's settings. Every field is optional: an unset
	// field is a setting this estate does not manage.
	Args struct {
		// ZoneID the settings apply to. Required.
		ZoneID string `json:"zoneId" yaml:"zoneId"`
		// SSL is how Cloudflare connects to the origin: off, flexible,
		// full or strict. "full" encrypts to the origin and accepts any
		// certificate; "strict" also verifies it, which needs a
		// certificate the public CAs or Cloudflare's own origin CA
		// signed.
		SSL string `json:"ssl,omitempty" yaml:"ssl,omitempty"`
		// MinTLSVersion a browser must offer: 1.0, 1.1, 1.2 or 1.3.
		MinTLSVersion string `json:"minTlsVersion,omitempty" yaml:"minTlsVersion,omitempty"`
		// TotalTLS issues a certificate per proxied hostname. Nil leaves
		// the zone alone.
		TotalTLS *TotalTLS `json:"totalTls,omitempty" yaml:"totalTls,omitempty"`
		// Cache is which hostnames may be cached at all. Nil leaves the
		// zone's caching as it is, extensions and all.
		Cache *Cache `json:"cache,omitempty" yaml:"cache,omitempty"`
		// TrustedClients is the zone's one skip rule for known client
		// ranges. Nil, or both lists empty, manages no firewall ruleset.
		TrustedClients *TrustedClients `json:"trustedClients,omitempty" yaml:"trustedClients,omitempty"`
		// RateLimits is the zone's whole http_ratelimit ruleset. Nil
		// leaves the phase alone; non-nil owns it, replacing any rule
		// created elsewhere.
		RateLimits *RateLimits `json:"rateLimits,omitempty" yaml:"rateLimits,omitempty"`
	}
)

func oneOf(value string, allowed []string) bool {
	for _, a := range allowed {
		if value == a {
			return true
		}
	}

	return false
}

// Validate reports the first problem with args.
func (a *Args) Validate() error {
	if a.ZoneID == "" {
		return fmt.Errorf("zone: zoneId is required")
	}

	if a.SSL != "" && !oneOf(a.SSL, validSSL) {
		return fmt.Errorf("zone %q: ssl %q must be one of %v", a.ZoneID, a.SSL, validSSL)
	}

	if a.MinTLSVersion != "" && !oneOf(a.MinTLSVersion, validMinTLSVersion) {
		return fmt.Errorf("zone %q: minTlsVersion %q must be one of %v", a.ZoneID, a.MinTLSVersion, validMinTLSVersion)
	}

	if a.TotalTLS != nil {
		ca := a.TotalTLS.CertificateAuthority
		if ca != "" && !oneOf(ca, validCA) {
			return fmt.Errorf("zone %q: totalTls.certificateAuthority %q must be one of %v", a.ZoneID, ca, validCA)
		}
	}

	if a.Cache != nil {
		if err := a.Cache.validate(a.ZoneID); err != nil {
			return err
		}
	}

	if a.TrustedClients != nil {
		if err := a.TrustedClients.validate(a.ZoneID); err != nil {
			return err
		}
	}

	if a.RateLimits != nil {
		if err := a.RateLimits.validate(a.ZoneID); err != nil {
			return err
		}
	}

	if a.SSL == "" && a.MinTLSVersion == "" && a.TotalTLS == nil && a.Cache == nil && !a.TrustedClients.Managed() && !a.RateLimits.Managed() {
		return fmt.Errorf("zone %q: nothing to apply — omit the zone instead of declaring one that manages no setting", a.ZoneID)
	}

	return nil
}

// validate reports the first problem with a cache policy. Every rule here
// is a host that would be written into a Cloudflare filter expression and
// then match nothing, which is the failure this component exists to make
// impossible: a rule that is applied, reported healthy, and silent.
func (c *Cache) validate(zoneID string) error {
	seen := make(map[string]struct{}, len(c.Hosts))

	for i, host := range c.Hosts {
		switch {
		case host == "":
			return fmt.Errorf("zone %q: cache.hosts[%d] is empty", zoneID, i)

		case strings.ToLower(host) != host:
			return fmt.Errorf(
				"zone %q: cache.hosts[%d] %q must be lower case: Cloudflare compares a lower-cased host, so this rule would match nothing",
				zoneID, i, host)

		case strings.ContainsAny(host, `/:"\ `):
			return fmt.Errorf("zone %q: cache.hosts[%d] %q must be a hostname, not a URL", zoneID, i, host)

		case host == "*." || strings.Contains(strings.TrimPrefix(host, "*."), "*"):
			return fmt.Errorf(
				"zone %q: cache.hosts[%d] %q: a wildcard is one leading label and a name after it, as in \"*.app.example\"",
				zoneID, i, host)
		}

		if _, duplicate := seen[host]; duplicate {
			return fmt.Errorf("zone %q: cache.hosts[%d] %q is listed twice", zoneID, i, host)
		}

		seen[host] = struct{}{}
	}

	return nil
}

// Managed reports whether the block declares a rule. Nil and an empty
// block manage nothing.
func (t *TrustedClients) Managed() bool {
	return t != nil && (len(t.Hosts) > 0 || len(t.Ranges) > 0)
}

// validate reports the first problem with a trusted-clients block: a rule
// that would match nothing, or too much.
func (t *TrustedClients) validate(zoneID string) error {
	if !t.Managed() {
		return nil
	}

	if len(t.Hosts) == 0 || len(t.Ranges) == 0 {
		return fmt.Errorf("zone %q: trustedClients.hosts and ranges must both be non-empty (leave both empty to manage no rule)", zoneID)
	}

	if t.Zone == "" || t.Zone != strings.ToLower(t.Zone) {
		return fmt.Errorf("zone %q: trustedClients.zone must be the zone's lower-case domain", zoneID)
	}

	seen := map[string]struct{}{}

	for i, host := range t.Hosts {
		if host != strings.ToLower(host) || strings.ContainsAny(host, `*/:"\ `) || host == "" ||
			(host != t.Zone && !strings.HasSuffix(host, "."+t.Zone)) {
			return fmt.Errorf("zone %q: trustedClients.hosts[%d] %q must be a lower-case exact hostname inside %s", zoneID, i, host, t.Zone)
		}

		if _, dup := seen[host]; dup {
			return fmt.Errorf("zone %q: trustedClients.hosts[%d] %q is listed twice", zoneID, i, host)
		}

		seen[host] = struct{}{}
	}

	seen = map[string]struct{}{}

	for i, r := range t.Ranges {
		prefix, err := netip.ParsePrefix(r)
		if err != nil || prefix.Masked() != prefix || prefix.Addr().Is4In6() {
			return fmt.Errorf("zone %q: trustedClients.ranges[%d] %q must be a CIDR block with no host bits set", zoneID, i, r)
		}

		if (prefix.Addr().Is4() && prefix.Bits() < minTrustedBitsV4) || (prefix.Addr().Is6() && prefix.Bits() < minTrustedBitsV6) {
			return fmt.Errorf("zone %q: trustedClients.ranges[%d] %q is too broad to trust (shortest allowed: /%d IPv4, /%d IPv6)",
				zoneID, i, r, minTrustedBitsV4, minTrustedBitsV6)
		}

		if _, dup := seen[r]; dup {
			return fmt.Errorf("zone %q: trustedClients.ranges[%d] %q is listed twice", zoneID, i, r)
		}

		seen[r] = struct{}{}
	}

	return nil
}

// TrustedExpression matches a request to one of the hosts from an address
// in one of the ranges. Both sets are sorted, so the expression never
// depends on authoring order.
func TrustedExpression(t *TrustedClients) string {
	return fmt.Sprintf("(http.host in {%s}) and (ip.src in {%s})", sortedSet(t.Hosts, true), sortedSet(t.Ranges, false))
}

// sortedSet renders a Cloudflare set literal body: host sets take quoted
// strings, IP sets bare addresses.
func sortedSet(values []string, quote bool) string {
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)

	for i, v := range sorted {
		if quote {
			sorted[i] = fmt.Sprintf("%q", v)
		}
	}

	return strings.Join(sorted, " ")
}

// HostExpression is the Cloudflare filter that matches the listed hosts.
// Exact names go in one set literal; each wildcard becomes a suffix test,
// because a set literal takes no wildcards.
func HostExpression(hosts []string) string {
	var (
		exact []string
		terms []string
	)

	for _, host := range hosts {
		if suffix, isWildcard := strings.CutPrefix(host, "*."); isWildcard {
			terms = append(terms, fmt.Sprintf("ends_with(http.host, %q)", "."+suffix))

			continue
		}

		exact = append(exact, fmt.Sprintf("%q", host))
	}

	if len(exact) > 0 {
		terms = append([]string{fmt.Sprintf("http.host in {%s}", strings.Join(exact, " "))}, terms...)
	}

	return strings.Join(terms, " or ")
}
