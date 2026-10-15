package tokensplit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const heldZoneID = "cccccccccccccccccccccccccccccccc"

func heldInputs() Inputs {
	in := inputs(&recordingWriter{})
	in.Zones = append(in.Zones, Zone{Name: "held.test", ID: heldZoneID, AccountID: testAccountID, SecurityTxtOnly: true})

	return in
}

func TestMatchingZoneIDsLeavesASecurityTxtOnlyZoneOut(t *testing.T) {
	in := heldInputs()

	assert.Equal(t, []string{testZoneID}, MatchingZoneIDs(in.Zones, testAccountID))
	assert.Equal(t, []string{heldZoneID}, SecurityTxtZoneIDs(in.Zones, testAccountID))
	assert.Empty(t, SecurityTxtZoneIDs(in.Zones, "acct-2"))
}

func TestDeployGivesASecurityTxtOnlyZoneZoneSettingsWriteOnEdgeOnly(t *testing.T) {
	m, _ := deploy(t, heldInputs())

	edge := m.policies("edge")
	require.Len(t, edge, 4)
	assertPolicy(t, edge[2], []string{"Zone WAF Write"}, "com.cloudflare.api.account.zone."+testZoneID)
	assertPolicy(t, edge[3], []string{PermZoneSettingsWrite}, "com.cloudflare.api.account.zone."+heldZoneID)

	status := m.policies("status")
	require.Len(t, status, 2, "status never touches the zone")
}

func TestDeployWithoutASecurityTxtOnlyZoneIsUnchanged(t *testing.T) {
	m, _ := deploy(t, inputs(&recordingWriter{}))
	require.Len(t, m.policies("edge"), 3)
}
