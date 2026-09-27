package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validYAML = `
issuer: https://access.example.com
audience: r2-broker
groupsClaim: groups
account:
  id: example-account-id
  parentTokenEnv: R2_BROKER_PARENT_TOKEN
grants:
  - group: ci:cache:reader
    bucket: example-bucket
    prefixes: ["go-build/"]
    permission: object-read-only
    ttlSeconds: 900
  - group: ci:cache:writer
    bucket: example-bucket
    prefixes: ["go-build/"]
    permission: object-read-write
    ttlSeconds: 900
`

func TestLoadValid(t *testing.T) {
	cfg, err := Load(strings.NewReader(validYAML))
	require.NoError(t, err)

	assert.Equal(t, "https://access.example.com", cfg.Issuer)
	assert.Equal(t, MintModeLocal, cfg.Minting.Mode, "empty minting.mode defaults to local")
	require.Len(t, cfg.Grants, 2)
	assert.Equal(t, PermissionReadOnly, cfg.Grants[0].Permission)
}

func TestLoadRefusesUnknownField(t *testing.T) {
	_, err := Load(strings.NewReader(validYAML + "\nbogusTopLevelField: true\n"))
	require.Error(t, err)
}

func TestLoadRefusesUnknownFieldInGrantRow(t *testing.T) {
	const bad = `
issuer: https://access.example.com
audience: r2-broker
groupsClaim: groups
account:
  id: example-account-id
  parentTokenEnv: TOKEN
grants:
  - group: ci:cache:reader
    bucket: example-bucket
    permission: object-read-only
    ttlSeconds: 900
    repository: example/repo
`
	_, err := Load(strings.NewReader(bad))
	require.Error(t, err, "a claim-matching field like repository must never load silently")
}

func TestLoadEmptyGrantsIsValid(t *testing.T) {
	const noGrants = `
issuer: https://access.example.com
audience: r2-broker
groupsClaim: groups
account:
  id: example-account-id
  parentTokenEnv: TOKEN
`
	cfg, err := Load(strings.NewReader(noGrants))
	require.NoError(t, err, "no grants renders a broker that refuses everything, not a load error")
	assert.Empty(t, cfg.Grants)
}

func TestValidate(t *testing.T) {
	base := func() Config {
		return Config{
			Issuer:      "https://access.example.com",
			Audience:    "r2-broker",
			GroupsClaim: "groups",
			Account:     Account{ID: "acct", ParentTokenEnv: "TOKEN"},
			Minting:     Minting{Mode: MintModeLocal},
		}
	}

	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"ok, no grants", func(*Config) {}, ""},
		{"missing issuer", func(c *Config) { c.Issuer = "" }, "issuer is required"},
		{"missing audience", func(c *Config) { c.Audience = "" }, "audience is required"},
		{"missing groupsClaim", func(c *Config) { c.GroupsClaim = "" }, "groupsClaim is required"},
		{"missing account id", func(c *Config) { c.Account.ID = "" }, "account.id is required"},
		{"neither token source", func(c *Config) { c.Account.ParentTokenEnv = "" }, "exactly one of parentTokenFile or parentTokenEnv"},
		{"both token sources", func(c *Config) { c.Account.ParentTokenFile = "/var/run/token" }, "exactly one of parentTokenFile or parentTokenEnv"},
		{"unknown minting mode", func(c *Config) { c.Minting.Mode = "sometimes" }, `minting.mode "sometimes" is neither`},
		{
			"empty group", func(c *Config) {
				c.Grants = []Grant{{Bucket: "b", Permission: PermissionReadOnly, TTLSeconds: 1}}
			}, "group is required",
		},
		{
			"empty bucket", func(c *Config) {
				c.Grants = []Grant{{Group: "g", Permission: PermissionReadOnly, TTLSeconds: 1}}
			}, "bucket is required",
		},
		{
			"unknown permission", func(c *Config) {
				c.Grants = []Grant{{Group: "g", Bucket: "b", Permission: "admin-read-write", TTLSeconds: 1}}
			}, "neither",
		},
		{
			"zero ttl", func(c *Config) {
				c.Grants = []Grant{{Group: "g", Bucket: "b", Permission: PermissionReadOnly, TTLSeconds: 0}}
			}, "ttlSeconds must be > 0",
		},
		{
			"negative ttl", func(c *Config) {
				c.Grants = []Grant{{Group: "g", Bucket: "b", Permission: PermissionReadOnly, TTLSeconds: -1}}
			}, "ttlSeconds must be > 0",
		},
		{
			// Same group+bucket+prefixes, different ttlSeconds: nothing
			// in a request can choose between them — a real conflict.
			"conflicting ttl on otherwise-identical rows", func(c *Config) {
				c.Grants = []Grant{
					{Group: "g", Bucket: "b", Permission: PermissionReadOnly, TTLSeconds: 900},
					{Group: "g", Bucket: "b", Permission: PermissionReadOnly, TTLSeconds: 60},
				}
			}, "more than one grant row",
		},
		{
			// The estate's one-prefix-per-row convention: several rows,
			// same group+bucket, differing ONLY by prefix. This is
			// normal, not a conflict — internal/decide resolves it from
			// the request's own prefixes.
			"several rows, same group+bucket, differing only by prefix is fine", func(c *Config) {
				c.Grants = []Grant{
					{Group: "g", Bucket: "b", Prefixes: []string{"a/"}, Permission: PermissionReadOnly, TTLSeconds: 900},
					{Group: "g", Bucket: "b", Prefixes: []string{"b/"}, Permission: PermissionReadOnly, TTLSeconds: 900},
				}
			}, "",
		},
		{
			// Same group+bucket+prefixes, differing ONLY by permission
			// (a reader row and a writer row for the same scope): also
			// fine — a request disambiguates with an explicit
			// permission (internal/decide).
			"same group+bucket+prefixes, differing only by permission is fine", func(c *Config) {
				c.Grants = []Grant{
					{Group: "g", Bucket: "b", Prefixes: []string{"a/"}, Permission: PermissionReadOnly, TTLSeconds: 900},
					{Group: "g", Bucket: "b", Prefixes: []string{"a/"}, Permission: PermissionReadWrite, TTLSeconds: 900},
				}
			}, "",
		},
		{
			"exact duplicate row is redundant, not a conflict", func(c *Config) {
				c.Grants = []Grant{
					{Group: "g", Bucket: "b", Prefixes: []string{"a/"}, Permission: PermissionReadOnly, TTLSeconds: 900},
					{Group: "g", Bucket: "b", Prefixes: []string{"a/"}, Permission: PermissionReadOnly, TTLSeconds: 900},
				}
			}, "",
		},
		{
			// Same prefix SET, written in a different order: still the
			// same identity, so a ttl disagreement here must also be
			// caught (grantIdentity sorts before comparing).
			"conflicting ttl survives a differently-ordered prefix list", func(c *Config) {
				c.Grants = []Grant{
					{Group: "g", Bucket: "b", Prefixes: []string{"a/", "b/"}, Permission: PermissionReadOnly, TTLSeconds: 900},
					{Group: "g", Bucket: "b", Prefixes: []string{"b/", "a/"}, Permission: PermissionReadOnly, TTLSeconds: 60},
				}
			}, "more than one grant row",
		},
		{
			"same group, different bucket is fine", func(c *Config) {
				c.Grants = []Grant{
					{Group: "g", Bucket: "b1", Permission: PermissionReadOnly, TTLSeconds: 900},
					{Group: "g", Bucket: "b2", Permission: PermissionReadWrite, TTLSeconds: 900},
				}
			}, "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.mutate(&cfg)

			err := cfg.Validate()
			if tc.wantErr == "" {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestPermissionValid(t *testing.T) {
	assert.True(t, PermissionReadOnly.Valid())
	assert.True(t, PermissionReadWrite.Valid())
	assert.False(t, Permission("admin-read-write").Valid())
	assert.False(t, Permission("").Valid())
}
