package config_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/edge/v3/cloudflare/config"
)

const heldZone = `  held.example.net: {account: partner, zone_id: z4, manage: security_txt, ` +
	`security_txt: {contact: ["mailto:security@example.com"], expires: "2027-01-01T00:00:00Z"}}
`

func withHeld(t *testing.T) string {
	t.Helper()

	return replaceOnce(t, registry, "fleets:", heldZone+"fleets:")
}

func goodGateways() string {
	return gateways("[platform]", map[string]string{
		"kernel": "          a: {domains: [a.example.com], route_namespaces: [a]}\n",
	})
}

func TestSecurityTxtOnlyZoneLoadsAndIsInert(t *testing.T) {
	c, err := load(t, withHeld(t), goodGateways())
	require.NoError(t, err)

	z := c.Zones["held.example.net"]
	assert.True(t, z.SecurityTxtOnly())
	assert.Equal(t, "z4", z.ZoneID)
	assert.False(t, c.Zones["example.com"].SecurityTxtOnly())

	contributions, err := z.Contributions()
	require.NoError(t, err)
	assert.Empty(t, contributions)
	assert.Nil(t, z.RecordsLibrary("held.example.net"))
	assert.Empty(t, z.ActiveOrigins())
	assert.Empty(t, z.CacheHosts)

	// No name is served in it, and the tunnels are what they were.
	assert.Empty(t, c.ZoneOf("www.held.example.net"))
	assert.Equal(t, "example.com", c.ZoneOf("a.example.com"))

	base, err := load(t, registry, goodGateways())
	require.NoError(t, err)
	assert.Equal(t, base.Tunnels, c.Tunnels)

	// The account's stacks still see the zone, for its security.txt.
	partner, err := c.ForAccount("partner")
	require.NoError(t, err)
	assert.Contains(t, partner.Zones, "held.example.net")
}

func TestManageFullIsTheDefaultSpelledOut(t *testing.T) {
	y := replaceOnce(t, registry, "zone_id: z3, ssl_mode: full}", "zone_id: z3, ssl_mode: full, manage: full}")
	c, err := load(t, y, goodGateways())
	require.NoError(t, err)
	assert.False(t, c.Zones["other.test"].SecurityTxtOnly())
}

func TestSecurityTxtOnlyZoneRefusesEverythingElse(t *testing.T) {
	for field, snippet := range map[string]string{
		"ssl_mode":            "ssl_mode: full",
		"min_tls_version":     `min_tls_version: "1.2"`,
		"total_tls":           "total_tls: {enabled: true}",
		"cache":               "cache: {}",
		"trusted_clients":     "trusted_clients: {ranges: [192.0.2.0/24], hosts: [a.held.example.net]}",
		"rate_limits":         "rate_limits: {plan: pro}",
		"records":             "records: [{name: a.held.example.net, type: A, content: 192.0.2.1}]",
		"origin_cnames":       "origin_cnames: {a.held.example.net: origin.example.com}",
		"public_cache":        "public_cache: {host: a.held.example.net}",
		"ssl_mode_rules":      "ssl_mode_rules: {a.held.example.net: full}",
		"ssl_mode_rule_refs":  "ssl_mode_rule_refs: {a.held.example.net: 0123456789abcdef0123456789abcdef}",
		"always_use_https":    "always_use_https: false",
		"hsts":                "hsts: {enabled: false, max_age: 0}",
		"bot_management":      "bot_management: {ai_bots: block}",
		"managed_waf":         "managed_waf: {whole_zone: true}",
		"zone_id_pending":     "zone_id_pending: true",
		"config_rules_import": "config_rules_import_id: 0123456789abcdef0123456789abcdef",
	} {
		y := replaceOnce(t, withHeld(t), "manage: security_txt, ", "manage: security_txt, "+snippet+", ")

		_, err := load(t, y, goodGateways())
		require.Error(t, err, field)
		assert.Contains(t, err.Error(), "zones[held.example.net].", field)
		assert.Contains(t, err.Error(), "manage: security_txt", field)
	}
}

func TestSecurityTxtOnlyZoneShape(t *testing.T) {
	for name, tc := range map[string]struct{ old, new, want string }{
		"no zone_id":      {"zone_id: z4, ", "", "zones[held.example.net].zone_id is required"},
		"no security_txt": {`, security_txt: {contact: ["mailto:security@example.com"], expires: "2027-01-01T00:00:00Z"}`, "", "security_txt is required"},
		"bad contact":     {"mailto:security@example.com", "security@example.com", "security_txt.contact[0]"},
		"bad expires":     {"2027-01-01T00:00:00Z", "next year", "security_txt.expires"},
		"unknown account": {"{account: partner, zone_id: z4", "{account: nobody, zone_id: z4", `no account "nobody"`},
		"unknown manage":  {"manage: security_txt", "manage: dns", `manage: "dns" is not allowed`},
	} {
		y := replaceOnce(t, withHeld(t), tc.old, tc.new)
		if name == "no security_txt" {
			y = strings.Replace(withHeld(t), tc.old, "", 1)
		}

		_, err := load(t, y, goodGateways())
		require.ErrorContains(t, err, tc.want, name)
	}
}

func TestACatalogHostInASecurityTxtOnlyZoneIsRefused(t *testing.T) {
	// The zone is not one the registry serves a name in: the host lies in no zone.
	_, err := load(t, withHeld(t), gateways("[partner]", map[string]string{
		"kernel": "          a: {domains: [a.held.example.net], route_namespaces: [a]}\n",
	}))
	require.ErrorContains(t, err, "lies in no zone")
}

func TestSecurityTxtOnlyZoneWithAnotherZoneInside(t *testing.T) {
	// A full zone inside the held zone's name still serves its own names.
	y := replaceOnce(t, withHeld(t), "fleets:", "  sub.held.example.net: {account: partner, zone_id: z5, ssl_mode: full}\nfleets:")
	c, err := load(t, y, gateways("[partner]", map[string]string{
		"kernel": "          a: {domains: [a.sub.held.example.net], route_namespaces: [a]}\n",
	}))
	require.NoError(t, err)
	assert.Equal(t, "sub.held.example.net", c.ZoneOf("a.sub.held.example.net"))
	assert.Empty(t, c.ZoneOf("b.held.example.net"))
}

func TestContributionsOfAHandBuiltSecurityTxtOnlyZone(t *testing.T) {
	// Even a zone built by hand (not through Parse) contributes nothing.
	z := config.Zone{Name: "held.example.net", Manage: config.ManageSecurityTxt, PublicCache: &config.PublicCacheCfg{Host: "a.held.example.net"}}
	got, err := z.Contributions()
	require.NoError(t, err)
	assert.Empty(t, got)
}
