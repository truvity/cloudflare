package zone

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// The rate limiting ruleset. Same rule as the cache and trusted-clients
// rulesets: a zone has ONE entry point ruleset per phase, so a zone that
// declares RateLimits owns the whole http_ratelimit phase. Rules added
// beside these in the dashboard are replaced, not merged.
const (
	rateLimitPhase       = "http_ratelimit"
	rateLimitRulesetName = "default"

	// Cloudflare tracks every rate limit counter per data center, and the
	// API refuses a rule that does not name cf.colo.id explicitly. The
	// library adds it; the author never writes it.
	characteristicColo = "cf.colo.id"
	characteristicIP   = "ip.src"
	// A business-plan alternative to the plain address that survives NAT.
	characteristicVisitor = "cf.unique_visitor_id"

	actionBlock            = "block"
	actionManagedChallenge = "managed_challenge"
	actionJSChallenge      = "js_challenge"
	actionChallenge        = "challenge"
	// Log is listed so that asking for it gets an explanation and not a
	// generic "unknown action": Cloudflare offers it on Enterprise only.
	actionLog = "log"

	// Longest expression Cloudflare accepts in a rule.
	maxExpressionLength = 4096
)

// Plan names, as Cloudflare names the zone plans this library models.
const (
	PlanFree     = "free"
	PlanPro      = "pro"
	PlanBusiness = "business"
)

// planLimit is what one Cloudflare plan allows a rate limiting rule.
//
// Source: https://developers.cloudflare.com/waf/rate-limiting-rules/ ("Availability")
// and https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/ .
// The two pages list slightly different period sets for the lower plans
// (the availability table's footnote names more values than the API
// reference); the INTERSECTION is used here, so a value this library
// accepts is a value both pages agree is real.
type planLimit struct {
	// maxRules is how many rate limiting rules the zone may hold.
	maxRules int
	// periods are the counting windows, in seconds.
	periods []int
	// mitigationTimeouts are the block durations, in seconds, for the
	// block action.
	mitigationTimeouts []int
	// characteristics are the counting keys an author may name besides
	// the cf.colo.id the library always adds.
	characteristics []string
	// oneCharacteristic is true when at most one of characteristics may
	// be used per rule.
	oneCharacteristic bool
	// method: the request method is a field of the rule expression.
	method bool
	// countingExpression: a counting expression that differs from the
	// match expression.
	countingExpression bool
}

var planLimits = map[string]planLimit{
	PlanFree: {
		maxRules:           1,
		periods:            []int{10},
		mitigationTimeouts: []int{10},
		characteristics:    []string{characteristicIP},
	},
	PlanPro: {
		maxRules:           2,
		periods:            []int{10, 60},
		mitigationTimeouts: []int{10, 60, 120, 300, 600, 3600},
		characteristics:    []string{characteristicIP},
	},
	PlanBusiness: {
		maxRules:           5,
		periods:            []int{10, 60, 120, 300, 600},
		mitigationTimeouts: []int{10, 60, 120, 300, 600, 3600, 86400},
		characteristics:    []string{characteristicIP, characteristicVisitor},
		oneCharacteristic:  true,
		method:             true,
		countingExpression: true,
	},
}

// validRateLimitActions are the actions a rate limiting rule can take on
// the plans modelled here. The challenge actions throttle instead of
// blocking for a duration: on Free, Pro and Business the API wants a
// mitigation timeout of exactly 0 for them.
var validRateLimitActions = []string{actionBlock, actionManagedChallenge, actionJSChallenge, actionChallenge}

type (
	// RateLimits is the zone's whole http_ratelimit entry point ruleset.
	//
	// A zone has one entry point ruleset per phase, and this block owns it:
	// rules created beside these (in the dashboard, or by another program)
	// are replaced, not merged. Nil leaves the phase alone. A non-nil block
	// with no rules is a policy, not an omission: it applies an EMPTY
	// ruleset, which is how the last rule is removed.
	RateLimits struct {
		// Plan the zone is on: free, pro or business. Required, because
		// every limit below depends on it and a default would be a guess
		// that surfaces as a refusal during the apply. Raising the plan
		// raises what is accepted; nothing here checks the zone's real
		// plan.
		Plan string `json:"plan" yaml:"plan"`
		// Rules in evaluation order. A Pro zone holds two.
		Rules []RateLimitRule `json:"rules" yaml:"rules"`
	}

	// RateLimitRule is one rate limiting rule: count the requests that
	// match, per Characteristics, and when more than Requests arrive in
	// Period seconds, take Action.
	//
	// Match with Endpoints (host and path pairs, rendered into one
	// expression with every value escaped) or with Expression (a Cloudflare
	// expression written by hand), not both.
	RateLimitRule struct {
		// Name of the rule, shown in the dashboard and in security events.
		// Unique within the ruleset.
		Name string `json:"name" yaml:"name"`
		// Endpoints this rule protects. A request matching ANY of them is
		// counted, and all of them feed ONE counter per characteristics
		// value: two endpoints in one rule share a budget.
		Endpoints []Endpoint `json:"endpoints,omitempty" yaml:"endpoints,omitempty"`
		// Expression is a hand-written Cloudflare expression, instead of
		// Endpoints. It is passed through; only its length and, on plans
		// without the request method field, a mention of it are checked.
		Expression string `json:"expression,omitempty" yaml:"expression,omitempty"`
		// CountingExpression increments the counter on something other
		// than the match expression (business plan and above). It does not
		// extend the match: include the matching condition in it. Empty
		// counts what matches.
		CountingExpression string `json:"countingExpression,omitempty" yaml:"countingExpression,omitempty"`
		// Characteristics key the counter. Empty is ip.src. The data
		// center id Cloudflare requires is added for you. On Free and Pro
		// the address is the only key there is.
		Characteristics []string `json:"characteristics,omitempty" yaml:"characteristics,omitempty"`
		// Period is the counting window in seconds. Pro: 10 or 60.
		Period int `json:"period" yaml:"period"`
		// Requests allowed in one Period before Action fires. Required,
		// at least 1.
		Requests int `json:"requests" yaml:"requests"`
		// MitigationTimeout is how many seconds Action keeps applying once
		// the rate is exceeded. Required for block (Pro: 10, 60, 120, 300,
		// 600 or 3600); must be 0 or omitted for the challenge actions,
		// which throttle instead.
		MitigationTimeout int `json:"mitigationTimeout,omitempty" yaml:"mitigationTimeout,omitempty"`
		// Action: block, managed_challenge, js_challenge or challenge.
		// (log is Enterprise-only and refused.) Required.
		Action string `json:"action" yaml:"action"`
	}

	// Endpoint is one host and path a rate limit protects.
	Endpoint struct {
		// Host is an exact lower-case hostname.
		Host string `json:"host" yaml:"host"`
		// Path is an exact request path starting with "/" and without a
		// query string. Exactly one of Path and PathPrefix.
		Path string `json:"path,omitempty" yaml:"path,omitempty"`
		// PathPrefix matches every path that starts with it.
		PathPrefix string `json:"pathPrefix,omitempty" yaml:"pathPrefix,omitempty"`
		// Methods restricts the endpoint to these HTTP methods
		// (upper-case). Empty counts every method, preflights included.
		// Business plan and above only: the Pro rule expression has no
		// method field.
		Methods []string `json:"methods,omitempty" yaml:"methods,omitempty"`
	}
)

func (r *RateLimits) managed() bool { return r != nil }

func containsInt(values []int, v int) bool {
	for _, x := range values {
		if x == v {
			return true
		}
	}

	return false
}

// validate reports the first problem with the rate limits.
func (r *RateLimits) validate(zoneID string) error {
	limit, ok := planLimits[r.Plan]
	if !ok {
		return fmt.Errorf("zone %q: rateLimits.plan %q must be one of %v", zoneID, r.Plan, planNames())
	}

	if len(r.Rules) > limit.maxRules {
		return fmt.Errorf("zone %q: rateLimits has %d rules but the %s plan allows %d: fold endpoints that share a budget into one rule's endpoints",
			zoneID, len(r.Rules), r.Plan, limit.maxRules)
	}

	names := map[string]struct{}{}

	for i := range r.Rules {
		rule := &r.Rules[i]
		if err := rule.validate(zoneID, r.Plan, limit, i); err != nil {
			return err
		}

		if _, dup := names[rule.Name]; dup {
			return fmt.Errorf("zone %q: rateLimits.rules[%d] name %q is used twice", zoneID, i, rule.Name)
		}

		names[rule.Name] = struct{}{}
	}

	return nil
}

func planNames() []string {
	out := make([]string, 0, len(planLimits))
	for name := range planLimits {
		out = append(out, name)
	}

	sort.Strings(out)

	return out
}

func (r *RateLimitRule) validate(zoneID, plan string, limit planLimit, i int) error {
	at := fmt.Sprintf("zone %q: rateLimits.rules[%d]", zoneID, i)

	if err := r.validateMatch(at, plan, limit); err != nil {
		return err
	}

	if err := r.validateKeyAndRate(at, plan, limit); err != nil {
		return err
	}

	return r.validateAction(at, plan, limit)
}

func (r *RateLimitRule) validateMatch(at, plan string, limit planLimit) error {
	if r.Name == "" || strings.TrimSpace(r.Name) != r.Name || len(r.Name) > 200 {
		return fmt.Errorf("%s: name is required, without surrounding spaces, at most 200 characters", at)
	}

	switch {
	case len(r.Endpoints) > 0 && r.Expression != "":
		return fmt.Errorf("%s (%s): endpoints and expression are alternatives: use one", at, r.Name)
	case len(r.Endpoints) == 0 && r.Expression == "":
		return fmt.Errorf("%s (%s): endpoints or expression is required: a rule that matches everything is a mistake", at, r.Name)
	case len(r.Expression) > maxExpressionLength:
		return fmt.Errorf("%s (%s): expression is longer than Cloudflare's %d characters", at, r.Name, maxExpressionLength)
	case !limit.method && strings.Contains(r.Expression, "http.request.method"):
		return fmt.Errorf("%s (%s): the %s plan's rule expression has no request method field", at, r.Name, plan)
	case r.CountingExpression != "" && !limit.countingExpression:
		return fmt.Errorf("%s (%s): countingExpression needs the business plan or above; on %s the counter counts what the rule matches", at, r.Name, plan)
	}

	seen := map[string]struct{}{}

	for j := range r.Endpoints {
		e := &r.Endpoints[j]
		if err := e.validate(fmt.Sprintf("%s (%s) endpoints[%d]", at, r.Name, j), plan, limit); err != nil {
			return err
		}

		key := e.Host + "\x00" + e.Path + "\x00" + e.PathPrefix + "\x00" + strings.Join(e.Methods, ",")
		if _, dup := seen[key]; dup {
			return fmt.Errorf("%s (%s) endpoints[%d] repeats an earlier endpoint", at, r.Name, j)
		}

		seen[key] = struct{}{}
	}

	return nil
}

func (r *RateLimitRule) validateKeyAndRate(at, plan string, limit planLimit) error {
	named := 0
	seen := map[string]struct{}{}

	for _, c := range r.Characteristics {
		if c == characteristicColo {
			continue
		}

		if !oneOf(c, limit.characteristics) {
			return fmt.Errorf("%s (%s): characteristic %q is not available on the %s plan (available: %v)", at, r.Name, c, plan, limit.characteristics)
		}

		if _, dup := seen[c]; dup {
			return fmt.Errorf("%s (%s): characteristic %q is listed twice", at, r.Name, c)
		}

		seen[c] = struct{}{}
		named++
	}

	if limit.oneCharacteristic && named > 1 {
		return fmt.Errorf("%s (%s): %s and %s cannot be used together", at, r.Name, characteristicIP, characteristicVisitor)
	}

	if !containsInt(limit.periods, r.Period) {
		return fmt.Errorf("%s (%s): period %d is not available on the %s plan (available: %v seconds)", at, r.Name, r.Period, plan, limit.periods)
	}

	if r.Requests < 1 {
		return fmt.Errorf("%s (%s): requests must be at least 1", at, r.Name)
	}

	return nil
}

func (r *RateLimitRule) validateAction(at, plan string, limit planLimit) error {
	switch {
	case r.Action == actionLog:
		return fmt.Errorf("%s (%s): action %q is Enterprise-only; use one of %v", at, r.Name, r.Action, validRateLimitActions)
	case !oneOf(r.Action, validRateLimitActions):
		return fmt.Errorf("%s (%s): action %q must be one of %v", at, r.Name, r.Action, validRateLimitActions)
	case r.Action == actionBlock && !containsInt(limit.mitigationTimeouts, r.MitigationTimeout):
		return fmt.Errorf("%s (%s): mitigationTimeout %d is not available on the %s plan for block (available: %v seconds)",
			at, r.Name, r.MitigationTimeout, plan, limit.mitigationTimeouts)
	case r.Action != actionBlock && r.MitigationTimeout != 0:
		return fmt.Errorf("%s (%s): %s throttles instead of blocking for a duration on the %s plan: mitigationTimeout must be 0 or omitted",
			at, r.Name, r.Action, plan)
	}

	return nil
}

// validate reports the first problem with one endpoint. Every value is
// written into a Cloudflare expression, so each is held to a character set
// that needs no escaping: a value that did would be a quote or a backslash
// pasted by mistake, and is refused rather than escaped into a rule that
// matches something nobody meant.
func (e *Endpoint) validate(at, plan string, limit planLimit) error {
	if err := validHostname(e.Host); err != nil {
		return fmt.Errorf("%s: host %q %w", at, e.Host, err)
	}

	if (e.Path == "") == (e.PathPrefix == "") {
		return fmt.Errorf("%s: exactly one of path and pathPrefix is required", at)
	}

	for field, value := range map[string]string{"path": e.Path, "pathPrefix": e.PathPrefix} {
		if value == "" {
			continue
		}

		if !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "?#") {
			return fmt.Errorf("%s: %s %q must start with \"/\" and carry no query string or fragment", at, field, value)
		}

		if !printableASCII(value) || strings.ContainsAny(value, `"\`) {
			return fmt.Errorf("%s: %s %q must be printable ASCII without a quote or backslash", at, field, value)
		}
	}

	if len(e.Methods) > 0 && !limit.method {
		return fmt.Errorf("%s: methods needs the business plan or above: the %s rule expression has no request method field, so every method is counted", at, plan)
	}

	for _, m := range e.Methods {
		if m == "" || strings.ToUpper(m) != m || strings.Trim(m, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
			return fmt.Errorf("%s: method %q must be an upper-case HTTP method", at, m)
		}
	}

	return nil
}

func validHostname(h string) error {
	if h == "" {
		return fmt.Errorf("is empty")
	}

	if strings.Trim(h, "abcdefghijklmnopqrstuvwxyz0123456789.-") != "" || strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") || strings.Contains(h, "..") {
		return fmt.Errorf("must be an exact lower-case hostname (letters, digits, dots, hyphens): " +
			"Cloudflare compares a lower-cased host and a set literal takes no wildcards")
	}

	return nil
}

func printableASCII(s string) bool {
	for _, c := range s {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}

	return true
}

// expression renders the rule's match expression: the hand-written one as
// given, or the endpoints ORed together. Each endpoint is its host, its
// path and, where the plan has the field, its methods, ANDed.
func (r *RateLimitRule) expression() string {
	if r.Expression != "" {
		return r.Expression
	}

	terms := make([]string, 0, len(r.Endpoints))

	for _, e := range r.Endpoints {
		path := fmt.Sprintf("http.request.uri.path eq %q", e.Path)
		if e.PathPrefix != "" {
			path = fmt.Sprintf("starts_with(http.request.uri.path, %q)", e.PathPrefix)
		}

		parts := []string{fmt.Sprintf("http.host eq %q", e.Host), path}

		if len(e.Methods) > 0 {
			methods := append([]string(nil), e.Methods...)
			sort.Strings(methods)

			quoted := make([]string, len(methods))
			for i, m := range methods {
				quoted[i] = fmt.Sprintf("%q", m)
			}

			parts = append(parts, fmt.Sprintf("http.request.method in {%s}", strings.Join(quoted, " ")))
		}

		terms = append(terms, "("+strings.Join(parts, " and ")+")")
	}

	return strings.Join(terms, " or ")
}

// characteristicList is cf.colo.id first, then the author's keys sorted,
// or ip.src alone when none are named.
func (r *RateLimitRule) characteristicList() []string {
	keys := []string{}

	for _, c := range r.Characteristics {
		if c != characteristicColo {
			keys = append(keys, c)
		}
	}

	if len(keys) == 0 {
		keys = []string{characteristicIP}
	}

	sort.Strings(keys)

	return append([]string{characteristicColo}, keys...)
}

// rateLimitRules is the phase's whole ruleset, in the order declared.
func rateLimitRules(rules []RateLimitRule) cloudflare.RulesetRuleArray {
	out := cloudflare.RulesetRuleArray{}

	for i := range rules {
		r := &rules[i]

		limit := &cloudflare.RulesetRuleRatelimitArgs{
			Characteristics:   pulumi.ToStringArray(r.characteristicList()),
			Period:            pulumi.Int(r.Period),
			RequestsPerPeriod: pulumi.Int(r.Requests),
			MitigationTimeout: pulumi.Int(r.MitigationTimeout),
		}
		if r.CountingExpression != "" {
			limit.CountingExpression = pulumi.String(r.CountingExpression)
		}

		out = append(out, cloudflare.RulesetRuleArgs{
			Action:      pulumi.String(r.Action),
			Description: pulumi.String(r.Name),
			Enabled:     pulumi.Bool(true),
			Expression:  pulumi.String(r.expression()),
			Ratelimit:   limit,
		})
	}

	return out
}
