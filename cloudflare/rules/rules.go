package rules

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Phase is a Cloudflare ruleset phase: a zone holds one entry point ruleset
// per phase.
type Phase string

// The phases this package assembles.
const (
	PhaseCacheSettings   Phase = "http_request_cache_settings"
	PhaseConfigSettings  Phase = "http_config_settings"
	PhaseFirewallCustom  Phase = "http_request_firewall_custom"
	PhaseFirewallManaged Phase = "http_request_firewall_managed"
	PhaseRateLimit       Phase = "http_ratelimit"
)

// Phases lists every phase, in a fixed order.
func Phases() []Phase {
	return []Phase{PhaseCacheSettings, PhaseConfigSettings, PhaseFirewallCustom, PhaseFirewallManaged, PhaseRateLimit}
}

// Conventional Orders in the cache phase.
const (
	// OrderHostsCache places the zone's cacheable-hosts rule.
	OrderHostsCache = 100
	// OrderBypass is where Assemble puts the catch-all bypass rule.
	OrderBypass = 500
	// OrderPathCaches places rules that cache part of a host that
	// the hosts rule does not.
	OrderPathCaches = 900
)

// BypassRef and BypassSource identify the rule Assemble synthesizes in the
// cache phase. No contribution may use that Ref.
const (
	BypassRef         = "cache-bypass"
	BypassSource      = "assembler"
	BypassDescription = "Not a cacheable hostname"
)

// Rule actions the builders use.
const (
	ActionSetCacheSettings = "set_cache_settings"
	ActionSetConfig        = "set_config"
	ActionSkip             = "skip"
	ActionExecute          = "execute"
)

// TTL modes of Cloudflare cache settings.
const (
	TTLOverrideOrigin  = "override_origin"
	TTLRespectOrigin   = "respect_origin"
	TTLBypassByDefault = "bypass_by_default"
)

// TTL is a cache TTL: a mode and, for the overriding modes, the seconds.
type TTL struct {
	Mode string
	// Default is the TTL in seconds (the API's "default"); 0 where the
	// mode takes none.
	Default int
}

// CacheParams are the action parameters of set_cache_settings.
type CacheParams struct {
	// Cache is whether matching responses are cached at all.
	Cache bool
	// EdgeTTL and BrowserTTL are unset when nil.
	EdgeTTL    *TTL
	BrowserTTL *TTL
	// RespectStrongETags honours the origin's strong ETag when set.
	RespectStrongETags bool
}

// ConfigParams are the action parameters of set_config.
type ConfigParams struct {
	// SSL is the SSL mode: off, flexible, full or strict.
	SSL string
}

// SkipParams are the action parameters of skip.
type SkipParams struct {
	// Ruleset is "current" to skip the rest of the rule's own ruleset.
	Ruleset  string
	Phases   []string
	Products []string
}

// ExecuteParams are the action parameters of execute.
type ExecuteParams struct {
	// ID of the ruleset executed.
	ID string
}

// Params are the action parameters of a rule. At most one member is set,
// the one its Action takes.
type Params struct {
	Cache   *CacheParams
	Config  *ConfigParams
	Skip    *SkipParams
	Execute *ExecuteParams
}

// RateLimit is the rate limiting block of a rule in the http_ratelimit phase.
type RateLimit struct {
	Characteristics    []string
	Period             int
	Requests           int
	MitigationTimeout  int
	CountingExpression string
}

// Rule is one Cloudflare ruleset rule in provider-neutral terms.
type Rule struct {
	// Ref identifies the rule within its phase; unique per phase.
	Ref         string
	Description string
	Action      string
	Expression  string
	// Disabled turns the rule off; the zero value is an enabled rule.
	Disabled  bool
	Params    Params
	RateLimit *RateLimit
	// Logging is whether a match is logged (skip rules).
	Logging bool
}

// Contribution is the rules one source wants in one phase.
type Contribution struct {
	// Source names the contributor; with Order it fixes the sort order.
	Source string
	Phase  Phase
	// Order is ascending; ties are broken by Source.
	Order int
	Rules []Rule
	// Claim is the parenthesised expression this contribution serves. Only
	// the cache phase takes one; the bypass rule excludes it.
	Claim string
}

// Assemble merges contributions into one ordered rule list per phase. It
// sorts by (Order, Source), rejects conflicting writers, and in the cache
// phase synthesizes the catch-all bypass rule at OrderBypass. A phase with no
// contribution is absent from the result; an absent phase is one the caller
// does not manage. The input is not modified.
func Assemble(c []Contribution) (map[Phase][]Rule, error) {
	sorted := append([]Contribution(nil), c...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Order != sorted[j].Order {
			return sorted[i].Order < sorted[j].Order
		}

		return sorted[i].Source < sorted[j].Source
	})

	var errs []error

	refs := map[Phase]map[string]string{}
	claims := []string{}
	cacheSeen := false
	byPhase := map[Phase][]Contribution{}

	for i := range sorted {
		con := &sorted[i]
		at := fmt.Sprintf("rules: contribution %q", con.Source)

		if !knownPhase(con.Phase) {
			errs = append(errs, fmt.Errorf("%s: unknown phase %q", at, con.Phase))

			continue
		}

		if con.Source == "" {
			errs = append(errs, fmt.Errorf("rules: a %s contribution has no source", con.Phase))
		}

		if con.Claim != "" && con.Phase != PhaseCacheSettings {
			errs = append(errs, fmt.Errorf("%s: a claim belongs to the %s phase, not %s", at, PhaseCacheSettings, con.Phase))
		}

		if con.Phase == PhaseCacheSettings {
			cacheSeen = true

			if con.Claim != "" {
				if !strings.HasPrefix(con.Claim, "(") || !strings.HasSuffix(con.Claim, ")") {
					errs = append(errs, fmt.Errorf("%s: claim %q must be a parenthesised expression", at, con.Claim))
				}

				claims = append(claims, con.Claim)
			}
		}

		if refs[con.Phase] == nil {
			refs[con.Phase] = map[string]string{}
		}

		for _, r := range con.Rules {
			if err := checkRule(&r); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", at, err))

				continue
			}

			if prev, dup := refs[con.Phase][r.Ref]; dup {
				errs = append(errs, fmt.Errorf("%s: rule ref %q in %s is already written by %q", at, r.Ref, con.Phase, prev))

				continue
			}

			refs[con.Phase][r.Ref] = con.Source
		}

		byPhase[con.Phase] = append(byPhase[con.Phase], *con)
	}

	if cacheSeen {
		bypass := Contribution{
			Source: BypassSource, Phase: PhaseCacheSettings, Order: OrderBypass,
			Rules: []Rule{BypassRule(claims)},
		}
		if prev, dup := refs[PhaseCacheSettings][BypassRef]; dup {
			errs = append(errs, fmt.Errorf("rules: rule ref %q in %s is reserved for the assembler's bypass, written by %q", BypassRef, PhaseCacheSettings, prev))
		}

		list := append(slices.Clone(byPhase[PhaseCacheSettings]), bypass)
		sort.SliceStable(list, func(i, j int) bool {
			if list[i].Order != list[j].Order {
				return list[i].Order < list[j].Order
			}

			return list[i].Source < list[j].Source
		})
		byPhase[PhaseCacheSettings] = list
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	out := map[Phase][]Rule{}

	for phase, list := range byPhase {
		rules := []Rule{}
		for i := range list {
			rules = append(rules, list[i].Rules...)
		}

		out[phase] = rules
	}

	return out, nil
}

// BypassRule is the cache phase's catch-all: it bypasses the cache for every
// request no claim covers. See the package documentation for the fold.
func BypassRule(claims []string) Rule {
	return Rule{
		Ref:         BypassRef,
		Description: BypassDescription,
		Action:      ActionSetCacheSettings,
		Expression:  BypassExpression(claims),
		Params:      Params{Cache: &CacheParams{Cache: false}},
	}
}

// BypassExpression folds claims, in the order given, into the expression of
// the requests none of them serves: "true" for no claims, "not a" for one,
// then "(<previous>) and not <claim>" for each further claim.
func BypassExpression(claims []string) string {
	if len(claims) == 0 {
		return "true"
	}

	expr := "not " + claims[0]
	for _, claim := range claims[1:] {
		expr = "(" + expr + ") and not " + claim
	}

	return expr
}

func knownPhase(p Phase) bool {
	for _, k := range Phases() {
		if p == k {
			return true
		}
	}

	return false
}

func checkRule(r *Rule) error {
	switch {
	case r.Ref == "":
		return errors.New("a rule has no ref")
	case r.Action == "":
		return fmt.Errorf("rule %q has no action", r.Ref)
	case r.Expression == "":
		return fmt.Errorf("rule %q has no expression", r.Ref)
	}

	return nil
}
