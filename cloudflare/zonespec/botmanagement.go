package zonespec

import "fmt"

// AI bots protection values, as the Cloudflare API spells them.
const (
	// AIBotsBlock blocks AI scrapers and crawlers.
	AIBotsBlock = "block"
	// AIBotsDisabled turns the rule off. It is how a zone that set block
	// goes back: the resource is a singleton and destroying it changes
	// nothing in Cloudflare.
	AIBotsDisabled = "disabled"
	// AIBotsOnlyOnAdPages blocks them only on pages that show ads.
	AIBotsOnlyOnAdPages = "only_on_ad_pages"
)

// BotManagement is the part of the zone's bot management setting
// (/zones/{id}/bot_management) this library manages: the AI scrapers and
// crawlers rule and Cloudflare's managed robots.txt. Nothing else of that
// object is sent: Bot Fight Mode, Super Bot Fight Mode (fight_mode,
// sbfm_*), JavaScript detections and crawler protection stay as they are.
//
// At least one field must be set. A field left unset is not managed.
//
// The setting is a singleton of the zone: it cannot be deleted, so removing
// the block from the configuration leaves the last applied values in place.
// To undo, set AIBots to "disabled" and ManagedRobotsTxt to false, apply, and
// only then remove the block.
type BotManagement struct {
	// AIBots is the AI scrapers and crawlers rule: "block", "disabled" or
	// "only_on_ad_pages". Empty leaves it alone.
	AIBots string `json:"aiBots,omitempty" yaml:"aiBots,omitempty"`
	// ManagedRobotsTxt serves Cloudflare's managed robots.txt, prepended to
	// the zone's own if it has one. Nil leaves it alone; false turns it off.
	ManagedRobotsTxt *bool `json:"managedRobotsTxt,omitempty" yaml:"managedRobotsTxt,omitempty"`
}

// validate reports the first problem with a bot management block.
func (b *BotManagement) validate(zoneID string) error {
	switch b.AIBots {
	case "", AIBotsBlock, AIBotsDisabled, AIBotsOnlyOnAdPages:
	default:
		return fmt.Errorf("zone %q: botManagement.aiBots %q must be %q, %q or %q",
			zoneID, b.AIBots, AIBotsBlock, AIBotsDisabled, AIBotsOnlyOnAdPages)
	}

	if b.AIBots == "" && b.ManagedRobotsTxt == nil {
		return fmt.Errorf("zone %q: botManagement sets nothing; set aiBots or managedRobotsTxt, or omit the block", zoneID)
	}

	return nil
}
