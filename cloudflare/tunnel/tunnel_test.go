package tunnel

import (
	"errors"
	"sync"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/edge/v3/cloudflare/account"
)

const tunnelTokenType = "cloudflare:index/getZeroTrustTunnelCloudflaredToken:getZeroTrustTunnelCloudflaredToken"

// mocks records every registered resource so tests can assert on the
// exact child names, types and inputs — the names are a documented
// contract (consumers alias existing resources onto them).
type mocks struct {
	mu  sync.Mutex
	res map[string]resource.PropertyMap // "type/name" → inputs

	// lastTokenProvider records the provider ref the mock most recently
	// saw on the tunnel-token invoke — "" if none.
	lastTokenProvider string
}

func (m *mocks) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.res[args.TypeToken+"/"+args.Name] = args.Inputs

	out := args.Inputs.Copy()
	if args.TypeToken == "cloudflare:index/zeroTrustTunnelCloudflared:ZeroTrustTunnelCloudflared" {
		return "tunnel-id-123", out, nil
	}

	return args.Name + "-id", out, nil
}

func (m *mocks) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	if args.Token == tunnelTokenType {
		m.mu.Lock()
		m.lastTokenProvider = args.Provider
		m.mu.Unlock()

		// The token invoke MUST carry an explicit provider — the same
		// class of bug cloudflare/r2 shipped in gitops#1700: a plain invoke
		// does not inherit one from its parent component the way a
		// resource does, so a missing provider ref here must fail the
		// test, not just log it.
		if args.Provider == "" {
			return resource.PropertyMap{}, assertionError("getZeroTrustTunnelCloudflaredToken invoked with no explicit provider")
		}

		return resource.PropertyMap{"token": resource.NewStringProperty("token-abc")}, nil
	}

	return resource.PropertyMap{}, nil
}

func assertionError(msg string) error { return errors.New(msg) }

// withAccountProvider builds a real (mocked) Cloudflare provider and
// returns the option that binds it — the same pulumi.Provider(...)
// account.Use() returns — so tests exercise the actual path a real
// caller takes.
func withAccountProvider(t *testing.T, ctx *pulumi.Context, accountID string) pulumi.ResourceOption {
	t.Helper()

	acct, err := account.New(ctx, "acct", account.Args{AccountID: accountID}, pulumi.String("token-"+accountID))
	require.NoError(t, err)

	return acct.Use()
}

func run(t *testing.T, args Args) *mocks {
	t.Helper()
	m := &mocks{res: map[string]resource.PropertyMap{}}
	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		tun, err := New(ctx, "cluster-a", args, pulumi.String("c2VjcmV0"), withAccountProvider(t, ctx, args.AccountID))
		if err != nil {
			return err
		}

		// Outputs resolve.
		ch := make(chan string, 1)
		tun.CNAMETarget.ApplyT(func(v string) string { ch <- v; return v })
		assert.Equal(t, "tunnel-id-123.cfargotunnel.com", <-ch)

		return nil
	}, pulumi.WithMocks("proj", "stack", m))
	require.NoError(t, err)

	return m
}

func baseArgs() Args {
	return Args{
		AccountID: "acct",
		Name:      "cluster-a",
		Ingress: []Ingress{
			{Hostname: "console.apps.example.com", Service: "https://gateway.svc:443", CAPool: "/etc/cloudflared/certs/ca.pem"},
			{Hostname: "*.apps.example.com", Service: "https://gateway.svc:443", OriginServerName: "*.apps.example.com"},
		},
		DNS: &DNS{ZoneID: "zone", Names: []string{"console.apps.example.com", "*.apps.example.com"}},
	}
}

func TestChildNamesAreTheDocumentedContract(t *testing.T) {
	m := run(t, baseArgs())

	for _, want := range []string{
		"cloudflare:index/zeroTrustTunnelCloudflared:ZeroTrustTunnelCloudflared/tunnel-cluster-a",
		"cloudflare:index/zeroTrustTunnelCloudflaredConfig:ZeroTrustTunnelCloudflaredConfig/ingress-cluster-a",
		"cloudflare:index/dnsRecord:DnsRecord/cname-cluster-a-console-apps-example-com",
		"cloudflare:index/dnsRecord:DnsRecord/cname-cluster-a-star-apps-example-com",
	} {
		assert.Contains(t, m.res, want)
	}

	// No certificate packs unless opted in.
	for k := range m.res {
		assert.NotContains(t, k, "certificatePack")
	}
}

func TestIngressGetsCatchAllAppended(t *testing.T) {
	m := run(t, baseArgs())

	cfg := m.res["cloudflare:index/zeroTrustTunnelCloudflaredConfig:ZeroTrustTunnelCloudflaredConfig/ingress-cluster-a"]
	rules := cfg["config"].ObjectValue()["ingresses"].ArrayValue()
	require.Len(t, rules, 3)
	assert.Equal(t, "http_status:404", rules[2].ObjectValue()["service"].StringValue())
	assert.Equal(t, "console.apps.example.com", rules[0].ObjectValue()["hostname"].StringValue())
}

func TestDNSRecordShape(t *testing.T) {
	m := run(t, baseArgs())

	rec := m.res["cloudflare:index/dnsRecord:DnsRecord/cname-cluster-a-console-apps-example-com"]
	assert.Equal(t, "CNAME", rec["type"].StringValue())
	assert.True(t, rec["proxied"].BoolValue())
	assert.Equal(t, float64(1), rec["ttl"].NumberValue())
}

func TestCertificatesOptInSkipsTopWildcard(t *testing.T) {
	args := baseArgs()
	args.Certificates = &Certificates{ZoneID: "zone", Zone: "example.com"}
	m := run(t, args)

	assert.Contains(t, m.res, "cloudflare:index/certificatePack:CertificatePack/acm-cluster-a-console-apps-example-com")
	assert.Contains(t, m.res, "cloudflare:index/certificatePack:CertificatePack/acm-cluster-a-star-apps-example-com")

	pack := m.res["cloudflare:index/certificatePack:CertificatePack/acm-cluster-a-console-apps-example-com"]
	assert.Equal(t, "advanced", pack["type"].StringValue())
	assert.Equal(t, float64(90), pack["validityDays"].NumberValue())
	assert.Equal(t, "lets_encrypt", pack["certificateAuthority"].StringValue())
}

func TestCertificatesTopWildcardOnlyIsSkippedEntirely(t *testing.T) {
	args := baseArgs()
	args.DNS.Names = []string{"*.example.com"}
	args.Ingress = args.Ingress[:1]
	args.Certificates = &Certificates{ZoneID: "zone", Zone: "example.com"}
	m := run(t, args)

	for k := range m.res {
		assert.NotContains(t, k, "certificatePack")
	}
}

func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*Args)
		want string
	}{
		{"no account", func(a *Args) { a.AccountID = "" }, "accountId is required"},
		{"no name", func(a *Args) { a.Name = "" }, "name is required"},
		{"no ingress", func(a *Args) { a.Ingress = nil }, "at least one ingress rule"},
		{"catch-all supplied by hand", func(a *Args) { a.Ingress = []Ingress{{Service: "http_status:404"}} }, "needs hostname and service"},
		{"dns without zone", func(a *Args) { a.DNS.ZoneID = "" }, "dns.zoneId is required"},
		{"empty dns names", func(a *Args) { a.DNS.Names = nil }, "omit the dns block"},
		{"certs without zone", func(a *Args) { a.Certificates = &Certificates{ZoneID: "z"} }, "certificates.zoneId and certificates.zone"},
		{
			"a wildcard listed before the exact host it swallows",
			func(a *Args) {
				a.Ingress = []Ingress{
					{Hostname: "*.apps.example.com", Service: "https://fleet:443"},
					{Hostname: "console.apps.example.com", Service: "https://console:443"},
				}
			},
			"already caught by ingress[0]",
		},
		{
			"a broad wildcard listed before a deeper one",
			func(a *Args) {
				a.Ingress = []Ingress{
					{Hostname: "*.apps.example.com", Service: "https://fleet:443"},
					{Hostname: "*.team-a.apps.example.com", Service: "https://team-a:443"},
				}
			},
			"put the more specific rule first",
		},
		{
			"the same hostname twice",
			func(a *Args) {
				a.Ingress = []Ingress{
					{Hostname: "a.example.com", Service: "https://one:443"},
					{Hostname: "a.example.com", Service: "https://two:443"},
				}
			},
			"the second is dead",
		},
		{
			"a hand-written catch-all before everything else",
			func(a *Args) {
				a.Ingress = []Ingress{
					{Hostname: "*", Service: "http_status:404"},
					{Hostname: "a.example.com", Service: "https://one:443"},
				}
			},
			"already caught by ingress[0]",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := baseArgs()
			tc.mut(&a)
			err := a.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestTokenLookupCarriesTheExplicitProvider is the regression test for
// the same class of bug cloudflare/r2 shipped in gitops#1700: New with an
// explicit provider in opts (the account.Use() every real caller passes)
// must thread that SAME provider into the token invoke, not rely solely
// on Parent-based inheritance.
func TestTokenLookupCarriesTheExplicitProvider(t *testing.T) {
	m := run(t, baseArgs())

	assert.NotEmpty(t, m.lastTokenProvider, "the token invoke must carry the account's explicit provider")
}

// TestTokenLookupWithNoExplicitProviderFails is the mirror case: with no
// provider anywhere in opts, the token invoke has no explicit provider
// and no inherited one either — the mock refuses that, and the refusal
// must surface as New's own error rather than silently resolving against
// a default provider.
func TestTokenLookupWithNoExplicitProviderFails(t *testing.T) {
	m := &mocks{res: map[string]resource.PropertyMap{}}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		_, err := New(ctx, "cluster-a", baseArgs(), pulumi.String("c2VjcmV0"))

		return err
	}, pulumi.WithMocks("proj", "stack", m))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no explicit provider")
}

func TestSecretIsRequired(t *testing.T) {
	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		_, err := New(ctx, "x", baseArgs(), nil)
		return err
	}, pulumi.WithMocks("p", "s", &mocks{res: map[string]resource.PropertyMap{}}))
	require.ErrorContains(t, err, "secret is required")
}

// A correctly ordered list has to pass, or the check is a blocker
// rather than a guard: exact hosts first, then the deeper wildcard, then
// the broader one.
func TestCorrectlyOrderedIngressIsAccepted(t *testing.T) {
	a := baseArgs()
	a.Ingress = []Ingress{
		{Hostname: "console.apps.example.com", Service: "https://console:443"},
		{Hostname: "dashboard.apps.example.com", Service: "https://dashboard:443"},
		{Hostname: "*.team-a.apps.example.com", Service: "https://fleet:443"},
		{Hostname: "*.apps.example.com", Service: "https://fleet:443"},
	}

	require.NoError(t, a.Validate())
}

// An exact hostname never covers a wildcard: the wildcard matches names
// the exact rule does not, so it is still reachable.
func TestAnExactRuleDoesNotShadowAWildcard(t *testing.T) {
	a := baseArgs()
	a.Ingress = []Ingress{
		{Hostname: "a.example.com", Service: "https://one:443"},
		{Hostname: "*.example.com", Service: "https://fleet:443"},
	}

	require.NoError(t, a.Validate())
}

// Sibling wildcards catch disjoint sets of names; neither shadows the
// other however they are ordered.
func TestSiblingWildcardsDoNotShadowEachOther(t *testing.T) {
	a := baseArgs()
	a.Ingress = []Ingress{
		{Hostname: "*.team-a.example.com", Service: "https://team-a:443"},
		{Hostname: "*.team-b.example.com", Service: "https://team-b:443"},
	}

	require.NoError(t, a.Validate())
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

	want := []string{
		"example.com",
		"app.env.example.com",
		"other.example.com",
		"*.team.env.example.com",
		"*.a.example.com",
		"*.env.example.com",
		"*.example.com",
	}
	assert.Equal(t, want, got)

	// The derived order never trips the shadow check.
	a := Args{Name: "t", Ingress: nil}
	for _, h := range got {
		a.Ingress = append(a.Ingress, Ingress{Hostname: h, Service: "https://origin:443"})
	}

	require.NoError(t, a.validateIngressOrder())
}

// multiZoneArgs is a tunnel serving names in three zones of its account,
// one of them a zone delegated under another (deep.example.com).
func multiZoneArgs() Args {
	return Args{
		AccountID: "acct",
		Name:      "cluster-a",
		Ingress: []Ingress{
			{Hostname: "console.apps.example.com", Service: "https://gateway.svc:443"},
			{Hostname: "api.example.net", Service: "https://gateway.svc:443"},
			{Hostname: "api.deep.example.com", Service: "https://gateway.svc:443"},
			{Hostname: "*.apps.example.com", Service: "https://gateway.svc:443"},
		},
		DNS: &DNS{
			Names: []string{"console.apps.example.com", "api.example.net", "api.deep.example.com", "*.apps.example.com"},
			Zones: []DNSZone{
				{ZoneID: "zone-com", Name: "example.com"},
				{ZoneID: "zone-net", Name: "example.net"},
				{ZoneID: "zone-deep", Name: "deep.example.com"},
			},
		},
	}
}

func TestMultiZoneRecordsLandInTheirOwnZones(t *testing.T) {
	m := run(t, multiZoneArgs())

	const record = "cloudflare:index/dnsRecord:DnsRecord/"

	for name, zone := range map[string]string{
		"cname-cluster-a-console-apps-example-com": "zone-com",
		"cname-cluster-a-star-apps-example-com":    "zone-com",
		"cname-cluster-a-api-example-net":          "zone-net",
		// The longest suffix wins: deep.example.com, not example.com.
		"cname-cluster-a-api-deep-example-com": "zone-deep",
	} {
		rec, ok := m.res[record+name]
		require.True(t, ok, "record %s", name)
		assert.Equal(t, zone, rec["zoneId"].StringValue(), name)
		assert.Equal(t, "tunnel-id-123.cfargotunnel.com", rec["content"].StringValue(), name)
		assert.True(t, rec["proxied"].BoolValue(), name)
	}

	// One tunnel, one config: every name's rule, in the order given, then
	// the catch-all.
	cfg := m.res["cloudflare:index/zeroTrustTunnelCloudflaredConfig:ZeroTrustTunnelCloudflaredConfig/ingress-cluster-a"]
	rules := cfg["config"].ObjectValue()["ingresses"].ArrayValue()

	var hosts []string
	for _, r := range rules[:len(rules)-1] {
		hosts = append(hosts, r.ObjectValue()["hostname"].StringValue())
	}

	assert.Equal(t, []string{"console.apps.example.com", "api.example.net", "api.deep.example.com", "*.apps.example.com"}, hosts)
	assert.Equal(t, "http_status:404", rules[len(rules)-1].ObjectValue()["service"].StringValue())
}

// A single zone given as Zones renders exactly as the same zone given as
// ZoneID.
func TestOneZoneInZonesRendersAsZoneID(t *testing.T) {
	args := baseArgs()
	args.DNS = &DNS{Names: args.DNS.Names, Zones: []DNSZone{{ZoneID: "zone", Name: "example.com"}}}

	assert.Equal(t, string(render(t, run(t, baseArgs()))), string(render(t, run(t, args))))
}

func TestZoneIDOf(t *testing.T) {
	d := multiZoneArgs().DNS

	id, err := d.ZoneIDOf("A.Deep.Example.com")
	require.NoError(t, err)
	assert.Equal(t, "zone-deep", id)

	id, err = d.ZoneIDOf("*.example.net")
	require.NoError(t, err)
	assert.Equal(t, "zone-net", id)

	_, err = d.ZoneIDOf("a.example.org")
	require.ErrorContains(t, err, "lies in no zone of dns.zones")

	// One zone by id: taken as given, unchecked, as before.
	id, err = (&DNS{ZoneID: "zone"}).ZoneIDOf("a.example.org")
	require.NoError(t, err)
	assert.Equal(t, "zone", id)
}

func TestValidateMultiZone(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*Args)
		want string
	}{
		{"zoneId and zones both set", func(a *Args) { a.DNS.ZoneID = "zone" }, "dns.zoneId and dns.zones are both set"},
		{"a zone with no id", func(a *Args) { a.DNS.Zones[1].ZoneID = "" }, "dns.zones[1] needs zoneId and name"},
		{"a zone with no name", func(a *Args) { a.DNS.Zones[0].Name = "" }, "dns.zones[0] needs zoneId and name"},
		{"a zone twice", func(a *Args) { a.DNS.Zones[1].Name = "EXAMPLE.com" }, `dns.zones[1] "EXAMPLE.com" is already dns.zones[0]`},
		{"a zone id twice", func(a *Args) { a.DNS.Zones[1].ZoneID = "zone-com" }, "has the zoneId of dns.zones[0]"},
		{
			"a name outside every zone",
			func(a *Args) { a.DNS.Names = append(a.DNS.Names, "api.example.org") },
			`dns.names[4]: "api.example.org" lies in no zone of dns.zones`,
		},
		{
			"the same name twice",
			func(a *Args) { a.DNS.Names = append(a.DNS.Names, "API.example.net") },
			`dns.names[4] "API.example.net" is already dns.names[1]`,
		},
		{
			"certificates defaulting to names across zones",
			func(a *Args) { a.Certificates = &Certificates{ZoneID: "zone-com", Zone: "example.com"} },
			"dns.names span dns.zones",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := multiZoneArgs()
			require.NoError(t, a.Validate())

			tc.mut(&a)
			err := a.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}
