package presets

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/edge/v3/cloudflare/tokensplit"
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

// zone and services together hold exactly the groups edge holds for the same
// inputs: nothing lost, nothing gained. The one difference is stated: edge's
// tunnel write appears in services (as status holds it), once.
func TestZonePlusServicesCoverEdge(t *testing.T) {
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
			edge, zoneRow, svc := in, in, in
			edge.Name, edge.Kind = "umbrella-edge", KindEdge
			zoneRow.Name, zoneRow.Kind = "umbrella-zone", KindZone
			svc.Name, svc.Kind = "umbrella-services", KindServices
			// services never lists a security.txt-only zone (it writes DNS).
			svc.Zones = without(svc.Zones, "t.example")
			svc.WAFZones, svc.BotManagementZones, svc.CloudConnectorZones, svc.DNSOnlyZones = nil, nil, nil, nil

			e := groups(t, reg, edge)
			z := groups(t, reg, zoneRow)
			tunnel := "Cloudflare Tunnel Write@" + acct1

			// A services row needs a managed zone: with only a security.txt-only
			// zone there is no services row, and edge's tunnel write is the
			// stated difference.
			var s []string
			if name != "txt-only zone only" {
				s = groups(t, reg, svc)
				assert.Contains(t, s, tunnel)
			}

			// zone holds no account-wide grant: no tunnel write.
			assert.NotContains(t, z, tunnel)
			assert.Contains(t, e, tunnel)

			// Every edge group other than the tunnel write is in zone, in the
			// same order, and zone has nothing else.
			assert.Equal(t, without(e, tunnel), z)

			// The union, compared as (permission group, resource) pairs, is
			// edge's: DNS Write on a managed zone is held by both zone and
			// services (a repeat is the same right), nothing else is added.
			if name != "txt-only zone only" {
				assert.Equal(t, atoms(e), atoms(append(slices.Clone(z), s...)))
			}

			// services adds, beyond edge, nothing but the tunnel write and DNS
			// Write on managed zones, which edge already holds in its zone policy.
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

// atoms are the distinct "group@resource" pairs of flattened policies, sorted.
func atoms(in []string) []string {
	var out []string

	for _, g := range in {
		names, res, _ := strings.Cut(g, "@")
		for _, n := range strings.Split(names, ",") {
			out = append(out, n+"@"+res)
		}
	}

	slices.Sort(out)

	return slices.Compact(out)
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
	require.ErrorContains(t, err, "for the edge kind")
}

// StandardRows is unchanged; SplitRows is StandardRows plus the two new rows.
func TestSplitRows(t *testing.T) {
	std := StandardRows("umbrella", []string{"example:deploy"}, []string{"a.example"})
	require.Len(t, std, 3)

	split := SplitRows("umbrella", []string{"example:deploy"}, []string{"a.example"}, []string{"b.example"})
	require.Len(t, split, 5)

	assert.Equal(t, []string{"umbrella-edge", "umbrella-status", "umbrella-r2-admin", "umbrella-zone", "umbrella-services"},
		[]string{split[0].Name, split[1].Name, split[2].Name, split[3].Name, split[4].Name})
	assert.Equal(t, []string{KindEdge, KindStatus, KindR2Admin, KindZone, KindServices},
		[]string{split[0].Kind, split[1].Kind, split[2].Kind, split[3].Kind, split[4].Kind})
	assert.Equal(t, []string{"b.example"}, split[3].BotManagementZones)
	assert.Equal(t, []string{"a.example"}, split[3].WAFZones)

	_, err := Build(fixture(), split)
	require.NoError(t, err)
}
