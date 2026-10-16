package zonestack_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/edge/v4/cloudflare/config"
	"github.com/truvity/edge/v4/cloudflare/zonestack"
)

// holdSecurityTxt adds a zone managed for its security.txt only to the
// account of the company's registry.
func holdSecurityTxt(cfg *config.Config, account string) {
	cfg.Zones["held.example.net"] = config.Zone{
		Name: "held.example.net", Account: account, ZoneID: "5555aaaa6666bbbb7777cccc8888dddd", Manage: config.ManageSecurityTxt,
		SecurityTxt: &config.SecurityTxtCfg{Contact: []string{"mailto:security@example.com"}, Expires: "2027-01-01T00:00:00Z"},
	}
}

func resourceKeys(t *testing.T, a zonestack.Args) []string {
	t.Helper()

	r, err := run(t, a)
	require.NoError(t, err)

	var out []string
	for k := range r.ByKey() {
		out = append(out, k)
	}

	sort.Strings(out)

	return out
}

func TestASecurityTxtOnlyZoneRegistersNothing(t *testing.T) {
	for _, company := range []string{"example", "partner-co"} {
		before := resourceKeys(t, args(t, company))

		a := args(t, company)
		holdSecurityTxt(a.Config, a.Config.AccountsOf(company)[0])

		assert.Equal(t, before, resourceKeys(t, a), company)
	}
}

func TestZoneArgsRefusesASecurityTxtOnlyZone(t *testing.T) {
	cfg := fixture(t)
	holdSecurityTxt(cfg, "main")

	_, err := zonestack.ZoneArgs("held.example.net", cfg.Zones["held.example.net"])
	require.ErrorIs(t, err, zonestack.ErrSecurityTxtOnly)
}
