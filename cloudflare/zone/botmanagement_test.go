package zone

import (
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const botManagementType = "cloudflare:index/botManagement:BotManagement"

func TestBotManagementGolden(t *testing.T) {
	m := run(t, Args{
		ZoneID:        "023e105f4ecef8ad9ca31a8372d0c353",
		BotManagement: &BotManagement{AIBots: "block", ManagedRobotsTxt: ptr(true)},
	})

	got := m.res[botManagementType+"/bot-management-example"]
	require.NotNil(t, got, "child name is a contract consumers alias onto")

	assertGolden(t, "botmanagement.json", render(t, m))
}

func TestBotManagementSendsOnlyManagedFields(t *testing.T) {
	m := run(t, Args{ZoneID: "zone-1", BotManagement: &BotManagement{AIBots: "disabled"}})

	got := m.res[botManagementType+"/bot-management-example"]
	require.NotNil(t, got)
	assert.Equal(t, "disabled", got["aiBotsProtection"].StringValue())
	assert.False(t, got.HasValue("isRobotsTxtManaged"), "an unset field is not sent")

	for _, k := range []string{
		"fightMode", "sbfmDefinitelyAutomated", "sbfmLikelyAutomated", "sbfmVerifiedBots",
		"sbfmStaticResourceProtection", "enableJs", "crawlerProtection", "contentBotsProtection",
		"optimizeWordpress", "suppressSessionScore", "autoUpdateModel", "bmCookieEnabled", "cfRobotsVariant",
	} {
		assert.False(t, got.HasValue(resource.PropertyKey(k)), "%s is left to Cloudflare", k)
	}

	m = run(t, Args{ZoneID: "zone-1", BotManagement: &BotManagement{ManagedRobotsTxt: ptr(false)}})
	got = m.res[botManagementType+"/bot-management-example"]
	require.NotNil(t, got)
	assert.False(t, got.HasValue("aiBotsProtection"))
	assert.True(t, got.HasValue("isRobotsTxtManaged"), "false is a value, not an absence")
	assert.False(t, got["isRobotsTxtManaged"].BoolValue())
}

func TestAbsentBotManagementIsNoResource(t *testing.T) {
	m := run(t, Args{ZoneID: "zone-1", SSL: "strict"})

	assert.NotContains(t, m.res, botManagementType+"/bot-management-example")
}

func TestBotManagementValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		b    *BotManagement
		want string
	}{
		"unknown value": {&BotManagement{AIBots: "challenge"}, "botManagement.aiBots"},
		"wrong case":    {&BotManagement{AIBots: "Block"}, "botManagement.aiBots"},
		"empty block":   {&BotManagement{}, "sets nothing"},
	} {
		t.Run(name, func(t *testing.T) {
			err := (&Args{ZoneID: "z", BotManagement: tc.b}).Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}

	for _, v := range []string{"block", "disabled", "only_on_ad_pages"} {
		require.NoError(t, (&Args{ZoneID: "z", BotManagement: &BotManagement{AIBots: v}}).Validate())
	}

	require.NoError(t, (&Args{ZoneID: "z", BotManagement: &BotManagement{ManagedRobotsTxt: ptr(true)}}).Validate(),
		"the block alone is a zone that manages something")
}
