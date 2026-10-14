package instancetunnel_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/pulumi/pulumi-random/sdk/v4/go/random"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/edge/v3/cloudflare/account"
	"github.com/truvity/edge/v3/cloudflare/instancetunnel"
	"github.com/truvity/edge/v3/cloudflare/internal/stacktest"
	"github.com/truvity/edge/v3/cloudflare/tunnel"
)

// The box's tunnel, as an estate's status stack registers it today
// (legacyStatus below, which reproduces that stack's code), and as
// instancetunnel registers it: the same resources, parents, providers and
// inputs. Account ids, zone ids, names and tokens are placeholders.

const accountID = "aaaa1111bbbb2222cccc3333dddd4444"

var zones = []tunnel.DNSZone{
	{ZoneID: "1111aaaa2222bbbb3333cccc4444dddd", Name: "example.com"},
	{ZoneID: "2222aaaa3333bbbb4444cccc5555dddd", Name: "example.org"},
}

func routes() []instancetunnel.Route {
	return []instancetunnel.Route{
		{Host: "status.example.com", Service: "http://127.0.0.1:8081", Zone: "example.com"},
		{Host: "pages.example.org", Service: "http://127.0.0.1:8082", Zone: "example.org"},
		{Host: "kept.example.org", Service: "http://127.0.0.1:8083"}, // its record answers already
		{Host: "more.example.com", Service: "http://127.0.0.1:8084", Zone: "example.com"},
	}
}

func args() instancetunnel.Args {
	return instancetunnel.Args{
		Name: "status", TunnelName: "status-box", AccountID: accountID, Routes: routes(), Zones: zones, Token: "token-status",
	}
}

func TestMatchesTheStatusStack(t *testing.T) {
	var sunk []pulumi.StringOutput

	before, err := stacktest.Run(legacyStatus)
	require.NoError(t, err)

	after, err := stacktest.Run(func(ctx *pulumi.Context) error {
		a := args()
		a.Sink = func(_ *pulumi.Context, token pulumi.StringOutput) error {
			sunk = append(sunk, token)

			return nil
		}

		_, err := instancetunnel.Deploy(ctx, a)

		return err
	})
	require.NoError(t, err)

	want, got := before.ByKey(), after.ByKey()
	assert.Equal(t, want, got)
	assert.Len(t, sunk, 1, "the token reaches the sink")

	for _, key := range []string{
		"pulumi:providers:cloudflare::provider-status",
		"random:index/randomBytes:RandomBytes::status-tunnel-secret",
		"truvity:cloudflare:Tunnel::status",
		"cloudflare:index/zeroTrustTunnelCloudflared:ZeroTrustTunnelCloudflared::tunnel-status",
		"cloudflare:index/zeroTrustTunnelCloudflaredConfig:ZeroTrustTunnelCloudflaredConfig::ingress-status",
		"cloudflare:index/dnsRecord:DnsRecord::cname-status-status-example-com",
		"cloudflare:index/dnsRecord:DnsRecord::cname-status-pages-example-org",
		"cloudflare:index/dnsRecord:DnsRecord::cname-status-more-example-com",
	} {
		assert.Contains(t, got, key)
	}

	assert.NotContains(t, got, "cloudflare:index/dnsRecord:DnsRecord::cname-status-kept-example-org",
		"a route without a zone has an ingress rule and no record")

	assert.Equal(t, "status-box", got["cloudflare:index/zeroTrustTunnelCloudflared:ZeroTrustTunnelCloudflared::tunnel-status"].Inputs["name"])

	b, err := after.Render()
	require.NoError(t, err)
	assertGolden(t, "status.json", b)
}

func TestRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*instancetunnel.Args)
		want   string
	}{
		"no name":         {func(a *instancetunnel.Args) { a.Name = "" }, "Name and AccountID are required"},
		"no routes":       {func(a *instancetunnel.Args) { a.Routes = nil }, "at least one route"},
		"no credentials":  {func(a *instancetunnel.Args) { a.Token = "" }, "no resolved API token"},
		"an unknown zone": {func(a *instancetunnel.Args) { a.Routes[0].Zone = "missing.test" }, `zone "missing.test", which is not among Zones`},
	} {
		a := args()
		tc.mutate(&a)

		_, err := stacktest.Run(func(ctx *pulumi.Context) error {
			_, err := instancetunnel.Deploy(ctx, a)

			return err
		})
		require.ErrorContains(t, err, tc.want, name)
	}
}

func TestNoRecordsNoDNSBlock(t *testing.T) {
	a := args()
	for i := range a.Routes {
		a.Routes[i].Zone = ""
	}

	r, err := stacktest.Run(func(ctx *pulumi.Context) error {
		_, err := instancetunnel.Deploy(ctx, a)

		return err
	})
	require.NoError(t, err)

	for _, res := range r.Resources() {
		assert.NotEqual(t, "cloudflare:index/dnsRecord:DnsRecord", res.Type)
	}
}

func TestAGivenAccountProviderIsUsed(t *testing.T) {
	r, err := stacktest.Run(func(ctx *pulumi.Context) error {
		acct, err := account.New(ctx, "shared", account.Args{AccountID: accountID}, pulumi.String("token"))
		if err != nil {
			return err
		}

		a := args()
		a.Token, a.Account = "", acct
		_, err = instancetunnel.Deploy(ctx, a)

		return err
	})
	require.NoError(t, err)

	got := r.ByKey()
	assert.Contains(t, got, "pulumi:providers:cloudflare::provider-shared")
	assert.NotContains(t, got, "pulumi:providers:cloudflare::provider-status")
	assert.Equal(t, "provider-shared", got["cloudflare:index/zeroTrustTunnelCloudflared:ZeroTrustTunnelCloudflared::tunnel-status"].Provider)
}

// legacyStatus is the status stack's tunnel code, in the shape it has today:
// a provider named for the box, a secret, and the tunnel with ingress to the
// box's loopback and DNS in the zones its routes use.
func legacyStatus(ctx *pulumi.Context) error {
	var (
		ingress []tunnel.Ingress
		names   []string
		inZones []tunnel.DNSZone
		seen    = map[string]bool{}
	)

	for _, r := range routes() {
		ingress = append(ingress, tunnel.Ingress{Hostname: r.Host, Service: r.Service})

		if r.Zone == "" {
			continue
		}

		names = append(names, r.Host)

		if !seen[r.Zone] {
			seen[r.Zone] = true

			for _, z := range zones {
				if z.Name == r.Zone {
					inZones = append(inZones, z)
				}
			}
		}
	}

	acct, err := account.New(ctx, "status", account.Args{AccountID: accountID}, pulumi.String("token-status"))
	if err != nil {
		return err
	}

	secret, err := random.NewRandomBytes(ctx, "status-tunnel-secret", &random.RandomBytesArgs{Length: pulumi.Int(32)})
	if err != nil {
		return err
	}

	_, err = tunnel.New(ctx, "status", tunnel.Args{
		AccountID: accountID, Name: "status-box", Ingress: ingress, DNS: &tunnel.DNS{Names: names, Zones: inZones},
	}, secret.Base64, acct.Use())

	return err
}

func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()

	path := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") != "" {
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(path, got, 0o600))
	}

	want, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(want), string(got), fmt.Sprintf("golden %s", name))
}
