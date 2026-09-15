package zone

import (
	"sync"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mocks records every registered resource so tests can assert on the exact
// child names, types and inputs — the names are a documented contract
// (consumers alias existing resources onto them).
type mocks struct {
	mu  sync.Mutex
	res map[string]resource.PropertyMap // "type/name" → inputs
}

func (m *mocks) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.res[args.TypeToken+"/"+args.Name] = args.Inputs

	return args.Name + "-id", args.Inputs.Copy(), nil
}

func (m *mocks) Call(pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return resource.PropertyMap{}, nil
}

func run(t *testing.T, args Args) *mocks {
	t.Helper()
	m := &mocks{res: map[string]resource.PropertyMap{}}
	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		_, err := New(ctx, "example", args)

		return err
	}, pulumi.WithMocks("proj", "stack", m))
	require.NoError(t, err)

	return m
}

const (
	settingType  = "cloudflare:index/zoneSetting:ZoneSetting"
	totalTLSType = "cloudflare:index/totalTls:TotalTls"
)

func TestChildNames(t *testing.T) {
	m := run(t, Args{
		ZoneID:        "zone-1",
		SSL:           "full",
		MinTLSVersion: "1.2",
		TotalTLS:      &TotalTLS{Enabled: true, CertificateAuthority: "google"},
	})

	for _, want := range []string{
		settingType + "/setting-example-ssl",
		settingType + "/setting-example-min-tls-version",
		totalTLSType + "/total-tls-example",
	} {
		assert.Contains(t, m.res, want, "child name is a contract consumers alias onto")
	}
}

func TestOnlyDeclaredSettingsAreManaged(t *testing.T) {
	m := run(t, Args{ZoneID: "zone-1", SSL: "strict"})

	assert.Contains(t, m.res, settingType+"/setting-example-ssl")
	assert.NotContains(t, m.res, settingType+"/setting-example-min-tls-version",
		"an unset field is a setting this estate does not manage")
	assert.NotContains(t, m.res, totalTLSType+"/total-tls-example")
}

func TestSettingInputs(t *testing.T) {
	m := run(t, Args{ZoneID: "zone-1", SSL: "full", MinTLSVersion: "1.3"})

	ssl := m.res[settingType+"/setting-example-ssl"]
	assert.Equal(t, "zone-1", ssl["zoneId"].StringValue())
	assert.Equal(t, "ssl", ssl["settingId"].StringValue())
	assert.Equal(t, "full", ssl["value"].StringValue())

	minTLS := m.res[settingType+"/setting-example-min-tls-version"]
	assert.Equal(t, "min_tls_version", minTLS["settingId"].StringValue())
	assert.Equal(t, "1.3", minTLS["value"].StringValue())
}

func TestTotalTLSInputs(t *testing.T) {
	m := run(t, Args{ZoneID: "zone-1", TotalTLS: &TotalTLS{Enabled: true, CertificateAuthority: "lets_encrypt"}})

	tls := m.res[totalTLSType+"/total-tls-example"]
	assert.Equal(t, "zone-1", tls["zoneId"].StringValue())
	assert.True(t, tls["enabled"].BoolValue())
	assert.Equal(t, "lets_encrypt", tls["certificateAuthority"].StringValue())
}

func TestTotalTLSDefaultsToCloudflaresAuthority(t *testing.T) {
	m := run(t, Args{ZoneID: "zone-1", TotalTLS: &TotalTLS{Enabled: true}})

	tls := m.res[totalTLSType+"/total-tls-example"]
	assert.False(t, tls.HasValue("certificateAuthority"),
		"an unset authority leaves Cloudflare's default rather than picking one")
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name string
		args Args
		want string
	}{
		{"no zone", Args{SSL: "full"}, "zoneId is required"},
		{"nothing to apply", Args{ZoneID: "z"}, "nothing to apply"},
		{"bad ssl", Args{ZoneID: "z", SSL: "sometimes"}, `ssl "sometimes" must be one of`},
		{"bad min tls", Args{ZoneID: "z", MinTLSVersion: "1.4"}, `minTlsVersion "1.4" must be one of`},
		{
			"bad authority",
			Args{ZoneID: "z", TotalTLS: &TotalTLS{Enabled: true, CertificateAuthority: "someone"}},
			`totalTls.certificateAuthority "someone" must be one of`,
		},
		{"ok", Args{ZoneID: "z", SSL: "strict"}, ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.args.Validate()
			if c.want == "" {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), c.want)
		})
	}
}
