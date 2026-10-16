package prototypes

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/edge/v4/cloudflare/presets"
	"github.com/truvity/edge/v4/cloudflare/presettoken"
)

// registry and rows: the same synthetic testdata as the presets package's
// golden test.
func testdataTable(t *testing.T) []presets.Preset {
	t.Helper()

	var (
		reg struct {
			Accounts []presets.Account `json:"accounts"`
			Zones    []presets.Zone    `json:"zones"`
		}
		rows []struct {
			Name     string   `json:"name"`
			Kind     string   `json:"kind"`
			Account  string   `json:"account"`
			WAFZones []string `json:"waf_zones"`
			Grants   []string `json:"grants"`
		}
	)

	for name, into := range map[string]any{"registry.json": &reg, "rows.json": &rows} {
		data, err := os.ReadFile("../presets/testdata/" + name)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(data, into))
	}

	var rs []presets.Row
	for _, r := range rows {
		rs = append(rs, presets.Row{Name: r.Name, Kind: r.Kind, Account: r.Account, WAFZones: r.WAFZones, Grants: r.Grants})
	}

	table, err := presets.Build(presets.Registry{Accounts: reg.Accounts, Zones: reg.Zones}, rs)
	require.NoError(t, err)

	return table
}

func testTable(t *testing.T, account string) Table {
	t.Helper()

	return Table{
		Account: account,
		Presets: testdataTable(t),
		Estate: presettoken.Estate{
			SluisctlMin: "1.0.0", BinaryPrefixes: []string{"/nix/store"},
			BreakGlass: presettoken.EstateBreakGlass{
				Env: testEnv, ItemEnv: testEnv + "_ITEM", Account: "example.1password.com", Vault: "breakglass", Field: "api-token",
				ChildPrefix: "example-breakglass", ItemHint: "accounts.%s.root_item",
			},
		},
		Item:       "cloudflare-root-" + account,
		Getenv:     os.Getenv,
		NamePrefix: "sluis-prototype-",
	}
}

// An estate's prototypes, declared from the table: the Pulumi names, token
// names and policy documents of Deploy, one
// protected disabled token per preset of the account and nothing of the other.
func TestDeployTableNamesAndPolicies(t *testing.T) {
	for account, want := range map[string]struct {
		id      string
		presets []string
	}{
		"acme":   {"0a1b2c3d4e5f60718293a4b5c6d7e8f9", []string{"acme-r2-admin", "acme-services", "acme-status", "acme-zone"}},
		"globex": {"1f2e3d4c5b6a79880716253443526170", []string{"globex-r2-admin", "globex-services", "globex-status", "globex-zone"}},
	} {
		t.Run(account, func(t *testing.T) {
			rootEnv(t)

			m := newMocks()
			err := pulumi.RunErr(func(ctx *pulumi.Context) error {
				toks, err := DeployTable(ctx, testTable(t, account))
				if err != nil {
					return err
				}

				var names []string
				for n := range toks {
					names = append(names, n)
				}

				sort.Strings(names)
				assert.Equal(t, want.presets, names)

				return nil
			}, pulumi.WithMocks("proj", "stack", m))
			require.NoError(t, err)

			golden := map[string][]presets.PolicyDocument{}

			for _, p := range testdataTable(t) {
				if p.Account == account {
					docs, err := p.Documents()
					require.NoError(t, err)

					golden[p.Name] = docs
				}
			}

			require.Len(t, golden, 4)

			for _, name := range want.presets {
				key := tokenType + "/prototype-" + name
				in := m.res[key]
				require.NotNil(t, in, key)

				assert.True(t, m.protect[key], name)
				assert.Equal(t, "sluis-prototype-"+name, in["name"].StringValue())
				assert.Equal(t, "disabled", in["status"].StringValue())
				assert.Equal(t, want.id, in["accountId"].StringValue())

				pols := in["policies"].ArrayValue()
				require.Len(t, pols, len(golden[name]), name)

				for i, pol := range pols {
					o := pol.ObjectValue()

					var groups []string
					for _, g := range o["permissionGroups"].ArrayValue() {
						groups = append(groups, strings.TrimPrefix(g.ObjectValue()["id"].StringValue(), "pg:"))
					}

					assert.Equal(t, golden[name][i].Groups, groups, "%s policy %d", name, i)

					var res map[string]string
					require.NoError(t, json.Unmarshal([]byte(o["resources"].StringValue()), &res))
					assert.Equal(t, golden[name][i].Resources, res, "%s policy %d", name, i)
				}
			}
		})
	}
}

func TestDeployTableRefusals(t *testing.T) {
	rootEnv(t)

	for name, tc := range map[string]struct {
		mutate func(*Table)
		want   string
	}{
		"no item":                  {func(tb *Table) { tb.Item = "" }, testEnv + "_ITEM=<item> for this command, or accounts.globex.root_item"},
		"no preset of the account": {func(tb *Table) { tb.Account = "nobody"; tb.Item = "x" }, "the table has no preset of account nobody"},
		"no getenv":                {func(tb *Table) { tb.Getenv = nil }, "Getenv is required"},
	} {
		t.Run(name, func(t *testing.T) {
			tb := testTable(t, "globex")
			tc.mutate(&tb)

			m := newMocks()
			err := pulumi.RunErr(func(ctx *pulumi.Context) error {
				_, err := DeployTable(ctx, tb)

				return err
			}, pulumi.WithMocks("proj", "stack", m))
			require.ErrorContains(t, err, tc.want)
			assert.Empty(t, m.res)
		})
	}
}

func TestOptionsHook(t *testing.T) {
	rootEnv(t)

	called := map[string]bool{}
	tb := testTable(t, "globex")
	tb.Options = func(preset string) []pulumi.ResourceOption {
		called[preset] = true

		return []pulumi.ResourceOption{pulumi.Aliases([]pulumi.Alias{{Name: pulumi.String("old-" + preset)}})}
	}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		_, err := DeployTable(ctx, tb)

		return err
	}, pulumi.WithMocks("proj", "stack", newMocks()))
	require.NoError(t, err)
	assert.Len(t, called, 4)
}
