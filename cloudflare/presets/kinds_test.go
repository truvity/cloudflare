package presets

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/edge/v4/cloudflare/tokensplit"
)

const zoneT = "dddddddddddddddddddddddddddddddd"

// splitFixture has a security.txt-only zone beside three managed ones.
func splitFixture() Registry {
	reg := fixture()
	reg.Zones = append(reg.Zones, Zone{Name: "t.example", ID: zoneT, Account: "umbrella", SecurityTxtOnly: true})

	return reg
}

func groups(t *testing.T, reg Registry, row Row) []string {
	t.Helper()

	table, err := Build(reg, []Row{row})
	require.NoError(t, err)

	return flat(t, table[0])
}

// zone holds no account-wide grant; services holds the account's tunnel write
// and DNS Write on the managed zones, nothing else.
func TestZoneAndServicesSplitTheRights(t *testing.T) {
	reg := splitFixture()
	common := Row{
		Account: "umbrella", WAFZones: []string{"a.example"}, BotManagementZones: []string{"b.example"},
		CloudConnectorZones: []string{"a.example", "t.example"}[:1], DNSOnlyZones: nil,
	}

	cases := map[string]Row{
		"all zones": common,
		"listed zones": {
			Account: "umbrella", Zones: []string{"a.example", "b.example", "t.example"}, WAFZones: []string{"a.example"},
			BotManagementZones: []string{"b.example"}, CloudConnectorZones: []string{"a.example", "c.example"},
		},
		"dns-only zone":      {Account: "umbrella", Zones: []string{"a.example"}, DNSOnlyZones: []string{"c.example"}},
		"txt-only zone only": {Account: "umbrella", Zones: []string{"t.example"}},
	}

	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			zoneRow, svc := in, in
			zoneRow.Name, zoneRow.Kind = "umbrella-zone", KindZone
			svc.Name, svc.Kind = "umbrella-services", KindServices
			// services never lists a security.txt-only zone (it writes DNS).
			svc.Zones = without(svc.Zones, "t.example")
			svc.WAFZones, svc.BotManagementZones, svc.CloudConnectorZones, svc.DNSOnlyZones = nil, nil, nil, nil

			z := groups(t, reg, zoneRow)
			tunnel := "Cloudflare Tunnel Write@" + acct1

			// zone holds no account-wide grant: no tunnel write.
			assert.NotContains(t, z, tunnel)

			// A services row needs a managed zone: with only a security.txt-only
			// zone there is no services row.
			if name == "txt-only zone only" {
				return
			}

			// services holds the tunnel write and DNS Write on managed zones,
			// nothing else.
			s := groups(t, reg, svc)
			assert.Contains(t, s, tunnel)

			for _, g := range s {
				if g != tunnel {
					assert.Regexp(t, `^DNS Write@zone\.`, g)
				}
			}
		})
	}
}

func without[S ~[]string](in S, drop string) S {
	var out S

	for _, g := range in {
		if g != drop {
			out = append(out, g)
		}
	}

	return out
}

// The exact groups of the two new kinds.
func TestZoneAndServicesGroups(t *testing.T) {
	reg := splitFixture()

	zoneGroups := groups(t, reg, Row{
		Name: "umbrella-zone", Kind: KindZone, Account: "umbrella", Zones: []string{"a.example", "t.example"},
		WAFZones: []string{"a.example"}, BotManagementZones: []string{"a.example"}, CloudConnectorZones: []string{"a.example"}, DNSOnlyZones: []string{"c.example"},
	})
	assert.Equal(t, []string{
		"DNS Write,SSL and Certificates Write,Zone Settings Write,Cache Settings Write,Config Settings Write@zone." + zoneA,
		"Zone WAF Write@zone." + zoneA,
		"Bot Management Write@zone." + zoneA,
		"Cloud Connector Write@zone." + zoneA,
		"DNS Write@zone." + zoneC,
		"Zone Settings Write@zone." + zoneT,
	}, zoneGroups)

	svc := groups(t, reg, Row{Name: "umbrella-services", Kind: KindServices, Account: "umbrella"})
	assert.Equal(t, []string{
		"Cloudflare Tunnel Write@" + acct1,
		"DNS Write@zone." + zoneA,
		"DNS Write@zone." + zoneB,
		"DNS Write@zone." + zoneC,
	}, svc)
}

// services is status under another name: same policies, in the same order.
func TestServicesEqualsStatus(t *testing.T) {
	for _, reg := range []Registry{fixture(), splitFixture()} {
		for _, zones := range [][]string{nil, {"a.example", "c.example"}} {
			table, err := Build(reg, []Row{
				{Name: "umbrella-services", Kind: KindServices, Account: "umbrella", Zones: zones},
				{Name: "umbrella-status", Kind: KindStatus, Account: "umbrella", Zones: zones},
			})
			require.NoError(t, err)

			assert.Equal(t, table[1].Policies, table[0].Policies)

			docs0, _ := table[0].Documents()
			docs1, _ := table[1].Documents()
			assert.Equal(t, docs1, docs0)

			var ids []string
			for _, z := range reg.zonesOf("umbrella") {
				if !z.SecurityTxtOnly && (zones == nil || slices.Contains(zones, z.Name)) {
					ids = append(ids, z.ID)
				}
			}

			assert.Equal(t, tokensplit.StatusPolicies(ids), table[0].Policies)
			assert.NotEqual(t, table[1].Description, table[0].Description)
		}
	}
}

func TestServicesRefusesSecurityTxtOnlyZone(t *testing.T) {
	_, err := Build(splitFixture(), []Row{{Name: "umbrella-services", Kind: KindServices, Account: "umbrella", Zones: []string{"t.example"}}})
	require.ErrorContains(t, err, "security.txt only")
}

func TestServicesRefusesEdgeOnlyLists(t *testing.T) {
	_, err := Build(fixture(), []Row{{Name: "umbrella-services", Kind: KindServices, Account: "umbrella", WAFZones: []string{"a.example"}}})
	require.ErrorContains(t, err, "for the zone kind")
}

// StandardRows are an account's four rows: status, r2-admin, zone and services.
func TestStandardRows(t *testing.T) {
	rows := StandardRows("umbrella", []string{"example:deploy"}, []string{"a.example"}, []string{"b.example"})
	require.Len(t, rows, 4)

	assert.Equal(t, []string{"umbrella-status", "umbrella-r2-admin", "umbrella-zone", "umbrella-services"},
		[]string{rows[0].Name, rows[1].Name, rows[2].Name, rows[3].Name})
	assert.Equal(t, []string{KindStatus, KindR2Admin, KindZone, KindServices},
		[]string{rows[0].Kind, rows[1].Kind, rows[2].Kind, rows[3].Kind})
	assert.Equal(t, []string{"b.example"}, rows[2].BotManagementZones)
	assert.Equal(t, []string{"a.example"}, rows[2].WAFZones)

	_, err := Build(fixture(), rows)
	require.NoError(t, err)
}
