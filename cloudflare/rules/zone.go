package rules

import (
	"fmt"

	"github.com/truvity/edge/v3/cloudflare/zonespec"
)

// validationZone stands in for the zone id in zonespec's messages: the rules
// package knows no zone.
const validationZone = "rules"

// What a trusted client is exempted from, besides the rest of the custom
// rules: rate limiting, managed rules, Super Bot Fight Mode, and the legacy
// security products.
var (
	skipPhases   = []string{"http_ratelimit", "http_request_firewall_managed", "http_request_sbfm"}
	skipProducts = []string{"bic", "hot", "rateLimit", "securityLevel", "uaBlock", "waf", "zoneLockdown"}
)

// RateLimits is the zone's whole http_ratelimit ruleset, one rule per row in
// the order given, checked against the plan by zonespec's validation (rule
// count, periods, mitigation timeouts, characteristics, actions). An error
// is zonespec's, unchanged.
func RateLimits(plan string, rows []zonespec.RateLimitRule) (Contribution, error) {
	limits := &zonespec.RateLimits{Plan: plan, Rules: rows}
	if err := (&zonespec.Args{ZoneID: validationZone, RateLimits: limits}).Validate(); err != nil {
		return Contribution{}, err
	}

	c := Contribution{Source: "rate-limits", Phase: PhaseRateLimit, Order: OrderHostsCache}

	for i := range rows {
		r := &rows[i]
		c.Rules = append(c.Rules, Rule{
			Ref:         "ratelimit-" + r.Name,
			Description: r.Name,
			Action:      r.Action,
			Expression:  r.MatchExpression(),
			RateLimit: &RateLimit{
				Characteristics:    r.CharacteristicList(),
				Period:             r.Period,
				Requests:           r.Requests,
				MitigationTimeout:  r.MitigationTimeout,
				CountingExpression: r.CountingExpression,
			},
		})
	}

	return c, nil
}

// TrustedClients is the zone's one skip rule for known client address ranges
// on named hosts. An unmanaged block (nil, or no hosts and no ranges) is a
// contribution with no rules.
func TrustedClients(t *zonespec.TrustedClients) (Contribution, error) {
	c := Contribution{Source: "trusted-clients", Phase: PhaseFirewallCustom, Order: OrderHostsCache}
	if !t.Managed() {
		return c, nil
	}

	if err := (&zonespec.Args{ZoneID: validationZone, TrustedClients: t}).Validate(); err != nil {
		return Contribution{}, err
	}

	description := t.Description
	if description == "" {
		description = zonespec.DefaultTrustedDescription
	}

	c.Rules = []Rule{{
		Ref:         "trusted-clients",
		Description: description,
		Action:      ActionSkip,
		Expression:  zonespec.TrustedExpression(t),
		Params: Params{Skip: &SkipParams{
			Ruleset:  "current",
			Phases:   append([]string(nil), skipPhases...),
			Products: append([]string(nil), skipProducts...),
		}},
		Logging: true,
	}}

	return c, nil
}

// ManagedWAF is the one rule that executes the Cloudflare Managed Ruleset,
// with its default actions, on the declared hosts. Nil is a contribution with
// no rules.
func ManagedWAF(m *zonespec.ManagedWAF) (Contribution, error) {
	c := Contribution{Source: "managed-waf", Phase: PhaseFirewallManaged, Order: OrderHostsCache}
	if !m.Managed() {
		return c, nil
	}

	if err := (&zonespec.Args{ZoneID: validationZone, ManagedWAF: m}).Validate(); err != nil {
		return Contribution{}, err
	}

	description := m.Description
	if description == "" {
		description = zonespec.DefaultManagedWAFDescription
	}

	c.Rules = []Rule{{
		Ref:         "managed-waf",
		Description: description,
		Action:      ActionExecute,
		Expression:  zonespec.ManagedWAFExpression(m),
		Params:      Params{Execute: &ExecuteParams{ID: zonespec.CloudflareManagedRulesetID}},
	}}

	return c, nil
}

// SSLMode sets the SSL mode (off, flexible, full or strict) for one host with
// a set_config rule, for a host whose origin differs from the zone's setting.
// ref names the rule and must be unique in the phase.
//
// Authenticated Origin Pulls has no counterpart here: it is a zone or
// hostname certificate setting, not a ruleset rule.
func SSLMode(host, mode, ref string) (Contribution, error) {
	if !hostPattern.MatchString(host) {
		return Contribution{}, fmt.Errorf("rules: ssl mode: host %q is not a domain name", host)
	}

	if ref == "" {
		return Contribution{}, fmt.Errorf("rules: ssl mode: ref is required")
	}

	if err := (&zonespec.Args{ZoneID: validationZone, SSL: mode}).Validate(); err != nil || mode == "" {
		return Contribution{}, fmt.Errorf("rules: ssl mode %q must be one of off, flexible, full, strict", mode)
	}

	return Contribution{
		Source: "ssl-mode:" + ref, Phase: PhaseConfigSettings, Order: OrderHostsCache,
		Rules: []Rule{{
			Ref:         ref,
			Description: fmt.Sprintf("%s: SSL mode %s", host, mode),
			Action:      ActionSetConfig,
			Expression:  fmt.Sprintf(`http.host eq "%s"`, host),
			Params:      Params{Config: &ConfigParams{SSL: mode}},
		}},
	}, nil
}
