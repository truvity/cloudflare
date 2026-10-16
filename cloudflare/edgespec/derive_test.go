package edgespec

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func deriveInput() DeriveInput {
	return DeriveInput{
		Exposures: []Exposure{{
			Name:     "public",
			Accounts: []string{"main", "side"},
			Groups: []Group{
				{Name: "apps", Cluster: "prod", Hosts: []string{"app.example.com", "*.example.com", "*.env.example.com"}, RouteNamespaces: []string{"shop"}},
				{Name: "console", Cluster: "prod", Hosts: []string{"console.example.com"}, RouteNamespaces: []string{"shop", "platform"}},
				{Name: "other", Cluster: "prod", Hosts: []string{"x.example.net"}, RouteNamespaces: []string{"shop"}},
				{Name: "apps", Cluster: "dev", Hosts: []string{"dev.example.com"}, RouteNamespaces: []string{"shop"}},
			},
		}},
		Zones:       map[string]string{"example.com": "main", "example.net": "side"},
		LegacyNames: map[string]bool{"main": true, "side": false},
		Business:    map[string]struct{}{"shop": {}},
		CacheZones:  []string{"example.com"},
	}
}

func TestDerive(t *testing.T) {
	got, err := Derive(deriveInput())
	require.NoError(t, err)

	require.Len(t, got.Tunnels, 3)
	assert.Equal(t, "dev", got.Tunnels[0].Name)
	assert.Equal(t, []string{"dev.example.com"}, got.Tunnels[0].Hosts)

	// Legacy account: the bare cluster name; ingress order: exact hosts, then
	// deeper wildcards first.
	assert.Equal(t, "prod", got.Tunnels[1].Name)
	assert.Equal(t, "example.com", got.Tunnels[1].Zone)
	assert.Equal(t, []string{"app.example.com", "console.example.com", "*.env.example.com", "*.example.com"}, got.Tunnels[1].Hosts)

	assert.Equal(t, "prod-side", got.Tunnels[2].Name)
	assert.Equal(t, "example.net", got.Tunnels[2].Zone)

	// The console group admits a platform namespace, so it is not cached;
	// wildcards never are.
	assert.Equal(t, map[string][]string{"example.com": {"app.example.com", "dev.example.com"}}, got.CacheHosts)

	require.NoError(t, ValidateRouting(got.Tunnels))
}

func TestDeriveRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*DeriveInput)
		want   string
	}{
		"no accounts":        {func(in *DeriveInput) { in.Exposures[0].Accounts = nil }, "lists no accounts"},
		"unknown account":    {func(in *DeriveInput) { in.Exposures[0].Accounts = []string{"ghost"} }, `no account "ghost"`},
		"host in no zone":    {func(in *DeriveInput) { in.Exposures[0].Groups[0].Hosts = []string{"a.elsewhere.org"} }, "lies in no zone"},
		"account not listed": {func(in *DeriveInput) { in.Exposures[0].Accounts = []string{"main"} }, "list the account on the exposure"},
	} {
		in := deriveInput()
		tc.mutate(&in)

		_, err := Derive(in)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want containing %q", name, err, tc.want)
		}
	}
}

// A tunnel serves names in several zones of its account: each host keeps
// its own zone (Zones, for cloudflare/tunnel's DNS.Zones), the ingress order is
// the same OrderHosts order across zones, and Zone stays the first host's.
func TestDeriveTunnelAcrossZones(t *testing.T) {
	in := deriveInput()
	in.Zones["example.net"] = "main"
	in.Zones["deep.example.org"] = "main"
	in.Exposures[0].Accounts = []string{"main"}
	in.Exposures[0].Groups = append(in.Exposures[0].Groups,
		Group{Name: "extra", Cluster: "prod", Hosts: []string{"api.deep.example.org"}, RouteNamespaces: []string{"shop"}})

	got, err := Derive(in)
	require.NoError(t, err)

	require.Len(t, got.Tunnels, 2)
	assert.Equal(t, []string{"example.com"}, got.Tunnels[0].Zones, "a single-zone tunnel lists its one zone")

	prod := got.Tunnels[1]
	assert.Equal(t, "prod", prod.Name)
	assert.Equal(t, "main", prod.Account)
	assert.Equal(t, "example.com", prod.Zone)
	assert.Equal(t, []string{"deep.example.org", "example.com", "example.net"}, prod.Zones)
	assert.Equal(t, []string{
		// Exact hosts first in DNS canonical order (labels compared from the
		// right: com, net, org), whatever their zone; then the wildcards.
		"app.example.com", "console.example.com", "x.example.net", "api.deep.example.org",
		"*.env.example.com", "*.example.com",
	}, prod.Hosts)

	require.NoError(t, ValidateRouting(got.Tunnels))
}

// The same name served twice, here once per cluster, stays refused when the
// tunnels span several zones.
func TestValidateRoutingAcrossZones(t *testing.T) {
	err := ValidateRouting([]Tunnel{
		{Cluster: "a", Account: "x", Zones: []string{"example.com", "example.net"}, Hosts: []string{"a.example.com", "api.example.net"}},
		{Cluster: "b", Account: "x", Zones: []string{"example.net"}, Hosts: []string{"API.example.net"}},
	})
	require.ErrorContains(t, err, "already declared")
}

func TestDeriveWithoutCacheZones(t *testing.T) {
	in := deriveInput()
	in.CacheZones = nil

	got, err := Derive(in)
	require.NoError(t, err)
	assert.Nil(t, got.CacheHosts)
}

func TestValidateRouting(t *testing.T) {
	tun := func(cluster, account string, hosts ...string) Tunnel {
		return Tunnel{Cluster: cluster, Account: account, Hosts: hosts}
	}

	require.NoError(t, ValidateRouting([]Tunnel{tun("a", "x", "app.example.com", "*.example.com")}))

	err := ValidateRouting([]Tunnel{tun("a", "x", "*.example.com", "app.example.com")})
	require.ErrorContains(t, err, "is shadowed by earlier rule")

	err = ValidateRouting([]Tunnel{tun("a", "x", "app.example.com"), tun("b", "y", "APP.example.com")})
	require.ErrorContains(t, err, "already declared")
}

func TestNames(t *testing.T) {
	assert.Equal(t, "prod", TunnelName("prod", "main", true))
	assert.Equal(t, "prod-side", TunnelName("prod", "side", false))
	assert.Equal(t, "cloudflared", ReleaseName("main", true))
	assert.Equal(t, "cloudflared-side", ReleaseName("side", false))
	assert.Equal(t, "cloudflared-side-tunnel-token", SecretName("side", false))
	assert.Equal(t, "cloudflared-tunnel-token", SecretName("main", true))
}

func TestZoneOf(t *testing.T) {
	zones := []string{"example.com", "env.example.com"}
	assert.Equal(t, "env.example.com", ZoneOf(zones, "*.env.example.com"))
	assert.Equal(t, "example.com", ZoneOf(zones, "a.EXAMPLE.com"))
	assert.Equal(t, "", ZoneOf(zones, "example.org"))
}

// TestNoNonStdlibImports guards this package's reason to exist: a caller
// must be able to import edgespec alone, with no Pulumi or Cloudflare SDK
// riding along. See cloudflare/cfnames' test of the same name.
func TestNoNonStdlibImports(t *testing.T) {
	const pkg = "github.com/truvity/edge/v4/cloudflare/edgespec"

	out, err := exec.Command("go", "list", "-deps", pkg).Output()
	require.NoError(t, err, "go list -deps")

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" || line == pkg {
			continue
		}

		root, _, _ := strings.Cut(line, "/")
		assert.NotContains(t, root, ".", "cloudflare/edgespec must depend on the standard library only, found %q", line)
	}
}

func TestOrderHosts(t *testing.T) {
	got := OrderHosts([]string{
		"*.env.example.com",
		"app.env.example.com",
		"*.example.com",
		"other.example.com",
		"*.team.env.example.com",
		"example.com",
		"*.a.example.com",
	})

	assert.Equal(t, []string{
		"example.com",
		"app.env.example.com",
		"other.example.com",
		"*.team.env.example.com",
		"*.a.example.com",
		"*.env.example.com",
		"*.example.com",
	}, got)
}

func TestCovers(t *testing.T) {
	assert.True(t, Covers("a.example.com", "a.example.com"))
	assert.True(t, Covers("*.example.com", "a.b.example.com"))
	assert.True(t, Covers("*.example.com", "*.a.example.com"))
	assert.True(t, Covers("*", "anything.example.com"))
	assert.False(t, Covers("a.example.com", "b.example.com"))
	assert.False(t, Covers("*.a.example.com", "*.example.com"))
}

func TestDeriveDNSElsewhereKeepsTheRuleAndDropsTheRecord(t *testing.T) {
	in := deriveInput()
	in.Exposures[0].Groups[0].DNSElsewhere = []string{"app.example.com", "*.example.com"}

	got, err := Derive(in)
	require.NoError(t, err)

	prod := got.Tunnels[1]
	assert.Equal(t, []string{"app.example.com", "console.example.com", "*.env.example.com", "*.example.com"}, prod.Hosts,
		"every host keeps its ingress rule")
	assert.Equal(t, []string{"app.example.com", "*.example.com"}, prod.DNSElsewhere, "in ingress order")
	assert.Equal(t, []string{"console.example.com", "*.env.example.com"}, prod.DNSNames())
	assert.Empty(t, got.Tunnels[0].DNSElsewhere)
	assert.Equal(t, got.Tunnels[0].Hosts, got.Tunnels[0].DNSNames())

	require.NoError(t, ValidateRouting(got.Tunnels))
}
