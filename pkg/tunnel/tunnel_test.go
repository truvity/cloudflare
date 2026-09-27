package tunnel

import (
	"errors"
	"sync"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/cloudflare/v2/pkg/account"
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
		// class of bug pkg/r2 shipped in gitops#1700: a plain invoke
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
// the same class of bug pkg/r2 shipped in gitops#1700: New with an
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
