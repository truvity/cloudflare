package services_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/edge/v3/cloudflare/config"
)

func TestASecurityTxtOnlyZoneRegistersNothing(t *testing.T) {
	for _, company := range []string{"example", "partner-co"} {
		list := func(hold bool) []string {
			s := &sunk{}
			a := args(t, company, s)

			if hold {
				for _, acct := range a.Config.AccountsOf(company) {
					a.Config.Zones["held.example.net"] = config.Zone{
						Name: "held.example.net", Account: acct, ZoneID: "5555aaaa6666bbbb7777cccc8888dddd", Manage: config.ManageSecurityTxt,
						SecurityTxt: &config.SecurityTxtCfg{Contact: []string{"mailto:security@example.com"}, Expires: "2027-01-01T00:00:00Z"},
					}
				}
			}

			r, err := run(t, a)
			require.NoError(t, err)

			var out []string
			for k := range r.ByKey() {
				out = append(out, k)
			}

			sort.Strings(out)

			return out
		}

		assert.Equal(t, list(false), list(true), company)
	}
}
