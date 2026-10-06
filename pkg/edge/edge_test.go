package edge

import (
	"log/slog"
	"slices"
	"sync"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/cloudflare/v2/pkg/zone"
)

func baseArgs(sink TokenSink) Args {
	return Args{
		Accounts: []Account{
			{Name: "platform", AccountID: "a1", Token: "token-platform"},
			{Name: "partner", AccountID: "a2", Token: "token-partner"},
		},
		Zones: []Zone{
			{Name: "example.test", Account: "platform", Args: zone.Args{ZoneID: "z1", SSL: "full"}},
			{Name: "partner.test", Account: "partner", Args: zone.Args{ZoneID: "z2", SSL: "full"}},
		},
		Tunnels: []Tunnel{
			{Name: "alpha", Cluster: "alpha", Account: "platform", Zone: "example.test", Hosts: []string{"a.example.test"}, DNSDomain: "cluster.example"},
			{Name: "alpha-partner", Cluster: "alpha", Account: "partner", Zone: "partner.test", Hosts: []string{"a.partner.test"}},
		},
		Origin: Origin{Service: "gateway-internal", Namespace: "gateways"},
		Sink:   sink,
	}
}

type sunk struct {
	mu    sync.Mutex
	names []string
}

func (s *sunk) sink(_ *pulumi.Context, t Tunnel, _ pulumi.StringOutput) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.names = append(s.names, t.Name)

	return nil
}

func run(t *testing.T, args Args) (*mocks, error) {
	t.Helper()

	args.Logger = slog.New(slog.DiscardHandler)
	m := &mocks{}
	err := pulumi.RunErr(func(ctx *pulumi.Context) error { return Deploy(ctx, args) },
		pulumi.WithMocks("example", "edge", m))

	return m, err
}

func TestDeployRegistersOneProviderPerAccountAndOneTunnelPerEntry(t *testing.T) {
	s := &sunk{}
	m, err := run(t, baseArgs(s.sink))
	require.NoError(t, err)

	assert.Equal(t, []string{"provider-partner", "provider-platform"}, m.names("pulumi:providers:cloudflare"))
	assert.Equal(t, []string{"alpha", "alpha-partner"}, m.names("truvity:cloudflare:Tunnel"))
	assert.Equal(t, []string{"tunnel-secret-alpha", "tunnel-secret-alpha-partner"}, m.names("random:index/randomBytes:RandomBytes"))
	assert.Equal(t, []string{"alpha", "alpha-partner"}, s.names, "every tunnel token reaches the sink")

	tun := "cloudflare:index/zeroTrustTunnelCloudflared:ZeroTrustTunnelCloudflared"
	assert.Equal(t, "a2", m.input(tun, "tunnel-alpha-partner", "accountId"))

	record := "cloudflare:index/dnsRecord:DnsRecord"
	assert.Equal(t, "z2", m.input(record, "cname-alpha-partner-a-partner-test", "zoneId"))
	assert.Equal(t, "z1", m.input(record, "cname-alpha-a-example-test", "zoneId"))
}

func TestTunnelArgsOriginAndCAPool(t *testing.T) {
	args := baseArgs(nil)

	got := TunnelArgs(args, "a1", "z1", args.Tunnels[0])
	require.Len(t, got.Ingress, 1)
	assert.Equal(t, "https://gateway-internal.gateways.svc.cluster.example:443", got.Ingress[0].Service)
	assert.Equal(t, DefaultCAPoolPath, got.Ingress[0].CAPool)
	assert.Equal(t, "a.example.test", got.Ingress[0].OriginServerName)

	// No DNS domain: the convention.
	got = TunnelArgs(args, "a2", "z2", args.Tunnels[1])
	assert.Equal(t, "https://gateway-internal.gateways.svc.cluster.alpha:443", got.Ingress[0].Service)
}

func TestDeployAppliesTheOptionHooks(t *testing.T) {
	args := baseArgs((&sunk{}).sink)

	var zones, tunnels, accounts []string

	args.AccountOptions = func(a Account) []pulumi.ResourceOption { accounts = append(accounts, a.Name); return nil }
	args.ZoneOptions = func(z Zone) []pulumi.ResourceOption { zones = append(zones, z.Name); return nil }
	args.TunnelOptions = func(t Tunnel) []pulumi.ResourceOption { tunnels = append(tunnels, t.Name); return nil }

	_, err := run(t, args)
	require.NoError(t, err)

	assert.Equal(t, []string{"partner", "platform"}, accounts)
	assert.Equal(t, []string{"example.test", "partner.test"}, zones)
	assert.Equal(t, []string{"alpha", "alpha-partner"}, tunnels)
}

func TestDeployRefusals(t *testing.T) {
	_, err := run(t, baseArgs(nil))
	require.ErrorContains(t, err, "TokenSink is required")

	args := baseArgs((&sunk{}).sink)
	args.Accounts[0].Token = ""
	_, err = run(t, args)
	require.ErrorContains(t, err, "no resolved API token")

	args = baseArgs((&sunk{}).sink)
	args.Tunnels[0].Zone = "missing.test"
	_, err = run(t, args)
	require.ErrorContains(t, err, `zone "missing.test" is not declared`)

	args = baseArgs((&sunk{}).sink)
	args.Zones[0].Account = "missing"
	_, err = run(t, args)
	require.ErrorContains(t, err, `account "missing" is not declared`)
}

type (
	recorded struct {
		typ, name string
		inputs    resource.PropertyMap
	}

	mocks struct {
		mu        sync.Mutex
		resources []recorded
	}
)

func (m *mocks) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.resources = append(m.resources, recorded{args.TypeToken, args.Name, args.Inputs})

	return args.Name + "-id", args.Inputs.Copy(), nil
}

func (m *mocks) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	if args.Token == "cloudflare:index/getZeroTrustTunnelCloudflaredToken:getZeroTrustTunnelCloudflaredToken" {
		return resource.PropertyMap{"token": resource.NewStringProperty("tunnel-token")}, nil
	}

	return resource.PropertyMap{}, nil
}

func (m *mocks) names(typ string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []string

	for _, r := range m.resources {
		if r.typ == typ {
			out = append(out, r.name)
		}
	}

	slices.Sort(out)

	return out
}

func (m *mocks) input(typ, name, key string) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, r := range m.resources {
		if r.typ == typ && r.name == name {
			return r.inputs[resource.PropertyKey(key)].StringValue()
		}
	}

	return ""
}
