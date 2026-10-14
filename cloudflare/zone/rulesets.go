package zone

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	cfrules "github.com/truvity/edge/v3/cloudflare/rules"
	"github.com/truvity/edge/v3/cloudflare/zonespec"
)

// builtinKey identifies a rule the zone's own blocks (Cache, TrustedClients,
// ManagedWAF, RateLimits) contribute, as opposed to one in Args.Contributions.
type builtinKey struct {
	phase cfrules.Phase
	ref   string
}

// builtins are the rules the declaration blocks contribute, mapped to
// whether the rule is registered with enabled=true. Those registered before
// rules were assembled keep their inputs exactly: the cache and skip rules
// never set enabled, the managed and rate limit rules always did, and none
// carried a ref. A contributed rule is registered with its ref and enabled
// unless Disabled.
type builtins map[builtinKey]bool

// contributions is every contribution the zone assembles: the declaration
// blocks first, then Args.Contributions.
func contributions(args *Args) ([]cfrules.Contribution, builtins, error) {
	var out []cfrules.Contribution

	known := builtins{{cfrules.PhaseCacheSettings, cfrules.BypassRef}: false}

	add := func(c cfrules.Contribution, enabled bool) {
		for i := range c.Rules {
			known[builtinKey{c.Phase, c.Rules[i].Ref}] = enabled
		}

		out = append(out, c)
	}

	if args.Cache != nil {
		add(cfrules.CacheHosts(args.Cache.Hosts), false)
	}

	if args.TrustedClients.Managed() {
		c, err := cfrules.TrustedClients(args.TrustedClients)
		if err != nil {
			return nil, nil, fmt.Errorf("trusted clients: %w", err)
		}

		add(c, false)
	}

	if args.ManagedWAF.Managed() {
		c, err := cfrules.ManagedWAF(args.ManagedWAF)
		if err != nil {
			return nil, nil, fmt.Errorf("managed waf: %w", err)
		}

		add(c, true)
	}

	if args.RateLimits.Managed() {
		c, err := cfrules.RateLimits(args.RateLimits.Plan, args.RateLimits.Rules)
		if err != nil {
			return nil, nil, fmt.Errorf("rate limits: %w", err)
		}

		add(c, true)
	}

	out = append(out, args.Contributions...)

	// A contributed rule whose ref stays out of the inputs is registered like
	// a block's rule: enabled, no ref (providerRule).
	for _, ref := range args.Compat.OmitRefs {
		found := false

		for i := range args.Contributions {
			c := &args.Contributions[i]

			for j := range c.Rules {
				if c.Rules[j].Ref != ref {
					continue
				}

				if c.Rules[j].Disabled {
					return nil, nil, fmt.Errorf("compat.omitRefs: rule %q is disabled: a disabled rule keeps its ref", ref)
				}

				known[builtinKey{c.Phase, ref}] = true
				found = true
			}
		}

		if !found {
			return nil, nil, fmt.Errorf("compat.omitRefs: no contributed rule has ref %q", ref)
		}
	}

	return out, known, nil
}

// rulesetChild is the child name of a phase's ruleset: a documented
// contract, like the other child names.
func rulesetChild(phase cfrules.Phase, name string) string {
	switch phase {
	case cfrules.PhaseCacheSettings:
		return "cache-rules-" + name
	case cfrules.PhaseFirewallCustom:
		return "firewall-custom-" + name
	case cfrules.PhaseFirewallManaged:
		return "firewall-managed-" + name
	case cfrules.PhaseRateLimit:
		return "ratelimit-" + name
	case cfrules.PhaseConfigSettings:
		return "ssl-mode-" + name
	default:
		return "ruleset-" + string(phase) + "-" + name
	}
}

// withTopLevelAlias adds the alias of a resource that lives at the stack
// root today, when compat asks for it.
func withTopLevelAlias(opts []pulumi.ResourceOption, c zonespec.Compat) []pulumi.ResourceOption {
	if !c.TopLevelAliases {
		return opts
	}

	return append(append([]pulumi.ResourceOption(nil), opts...),
		pulumi.Aliases([]pulumi.Alias{{NoParent: pulumi.Bool(true)}}))
}

// newRulesets assembles every contribution and registers one ruleset per
// phase that has any.
func newRulesets(ctx *pulumi.Context, name string, args *Args, zoneID pulumi.String, child []pulumi.ResourceOption) error {
	contribs, known, err := contributions(args)
	if err != nil {
		return fmt.Errorf("zone %q: %w", name, err)
	}

	assembled, err := cfrules.Assemble(contribs)
	if err != nil {
		return fmt.Errorf("zone %q: %w", name, err)
	}

	for phase, id := range args.ImportRulesets {
		if _, ok := assembled[phase]; !ok {
			return fmt.Errorf("zone %q: importRulesets: the zone manages no %s ruleset to import %q into", name, phase, id)
		}
	}

	for _, phase := range cfrules.Phases() {
		list, ok := assembled[phase]
		if !ok {
			continue
		}

		opts := child

		switch phase {
		case cfrules.PhaseFirewallCustom, cfrules.PhaseConfigSettings:
			opts = withTopLevelAlias(child, args.Compat)
		}

		if id := args.ImportRulesets[phase]; id != "" {
			opts = append(append([]pulumi.ResourceOption(nil), opts...),
				pulumi.Import(pulumi.ID("zones/"+args.ZoneID+"/"+id)))
		}

		out := make(cloudflare.RulesetRuleArray, 0, len(list))
		for i := range list {
			enabled, builtin := known[builtinKey{phase, list[i].Ref}]
			out = append(out, providerRule(&list[i], builtin, enabled))
		}

		if _, err := cloudflare.NewRuleset(ctx, rulesetChild(phase, name), &cloudflare.RulesetArgs{
			ZoneId: zoneID,
			Kind:   pulumi.String(rulesetKind),
			Phase:  pulumi.String(string(phase)),
			Name:   pulumi.String("default"),
			Rules:  out,
		}, opts...); err != nil {
			return fmt.Errorf("zone %q: %s: %w", name, phase, err)
		}
	}

	return nil
}

// providerRule maps a rule onto the provider's. A built-in rule keeps the
// inputs it had before rules were assembled (no ref, enabled as recorded).
func providerRule(r *cfrules.Rule, builtin, builtinEnabled bool) cloudflare.RulesetRuleArgs {
	out := cloudflare.RulesetRuleArgs{
		Action:      pulumi.String(r.Action),
		Description: pulumi.String(r.Description),
		Expression:  pulumi.String(r.Expression),
	}

	switch {
	case !builtin:
		out.Ref = pulumi.String(r.Ref)
		out.Enabled = pulumi.Bool(!r.Disabled)
	case builtinEnabled:
		out.Enabled = pulumi.Bool(true)
	}

	out.ActionParameters = actionParameters(&r.Params)

	if r.Logging {
		out.Logging = &cloudflare.RulesetRuleLoggingArgs{Enabled: pulumi.Bool(true)}
	}

	if l := r.RateLimit; l != nil {
		limit := &cloudflare.RulesetRuleRatelimitArgs{
			Characteristics:   pulumi.ToStringArray(l.Characteristics),
			Period:            pulumi.Int(l.Period),
			RequestsPerPeriod: pulumi.Int(l.Requests),
			MitigationTimeout: pulumi.Int(l.MitigationTimeout),
		}
		if l.CountingExpression != "" {
			limit.CountingExpression = pulumi.String(l.CountingExpression)
		}

		out.Ratelimit = limit
	}

	return out
}

func actionParameters(p *cfrules.Params) *cloudflare.RulesetRuleActionParametersArgs {
	switch {
	case p.Cache != nil:
		c := p.Cache
		out := &cloudflare.RulesetRuleActionParametersArgs{Cache: pulumi.Bool(c.Cache)}

		if c.EdgeTTL != nil {
			ttl := &cloudflare.RulesetRuleActionParametersEdgeTtlArgs{Mode: pulumi.String(c.EdgeTTL.Mode)}
			if c.EdgeTTL.Default > 0 {
				ttl.Default = pulumi.Int(c.EdgeTTL.Default)
			}

			out.EdgeTtl = ttl
		}

		if c.BrowserTTL != nil {
			ttl := &cloudflare.RulesetRuleActionParametersBrowserTtlArgs{Mode: pulumi.String(c.BrowserTTL.Mode)}
			if c.BrowserTTL.Default > 0 {
				ttl.Default = pulumi.Int(c.BrowserTTL.Default)
			}

			out.BrowserTtl = ttl
		}

		if c.RespectStrongETags {
			out.RespectStrongEtags = pulumi.Bool(true)
		}

		return out
	case p.Config != nil:
		return &cloudflare.RulesetRuleActionParametersArgs{Ssl: pulumi.String(p.Config.SSL)}
	case p.Skip != nil:
		return &cloudflare.RulesetRuleActionParametersArgs{
			Ruleset:  pulumi.String(p.Skip.Ruleset),
			Phases:   pulumi.ToStringArray(p.Skip.Phases),
			Products: pulumi.ToStringArray(p.Skip.Products),
		}
	case p.Execute != nil:
		return &cloudflare.RulesetRuleActionParametersArgs{Id: pulumi.String(p.Execute.ID)}
	}

	return nil
}
