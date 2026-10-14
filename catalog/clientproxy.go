package catalog

import (
	"fmt"
	"regexp"
)

// The sign-in a gateway puts in front of one console: who is admitted, what
// is forwarded, and what the cookies and the Origin check defend. The
// estate keeps the row that declares it; the defaults and the rules are
// here, so that every estate reads the same ones.

const (
	// PostureAuthenticated lets the application authorize itself from the
	// directory it owns; PostureGroups makes the gateway the enforcement
	// point. Two copies of one decision is how the gateway's ends up being
	// the stale one, so `groups` is for applications that have no roles of
	// their own.
	PostureAuthenticated = "authenticated"
	PostureGroups        = "groups"

	// CSRF postures for a browser route. `shadow` reports what enforcing
	// would refuse without refusing it, which is the only safe way to learn
	// whether a real client of this application sends an Origin.
	CSRFOff     = "off"
	CSRFShadow  = "shadow"
	CSRFEnforce = "enforce"
)

// ClientProxy is the part of a console's sign-in that is the gateway's: the
// route it binds to, the posture, the bearer and the cookie defences.
type ClientProxy struct {
	// AttachRouteName names the HTTPRoute the SecurityPolicy binds to.
	// REQUIRED: the gateway renders no route of its own, so the route is
	// the application's or the estate's. Two charts claiming one hostname
	// collide rather than coexist.
	AttachRouteName string `yaml:"attach_route_name,omitempty"`
	// AttachRouteRule narrows the binding to ONE NAMED RULE of that route,
	// rather than the whole of it.
	//
	// It is what lets an application's content-hashed assets be public
	// while its shell and its API are not. A route rendered by the
	// `gateway-routes` library chart names its rules: `app` carries the
	// shell and the API, `static` carries the asset prefixes. Naming `app`
	// puts the sign-in on the first and leaves the second anonymous, so the
	// edge may cache an asset without ever holding a response that was
	// somebody's.
	//
	// Gating the assets too means every one of them travels the tunnel to
	// the pod on every cold browser, because a gated response is a redirect
	// carrying Set-Cookie and a CDN will not cache it -- and the moment
	// anything DOES cache one, the bundle is public anyway, by accident and
	// unwritten. This says it on purpose.
	//
	// Empty binds the whole route.
	AttachRouteRule string `yaml:"attach_route_rule,omitempty"`
	// Posture is `authenticated` or `groups`; see the constants.
	Posture string `yaml:"posture,omitempty"`
	// Allow are the groups admitted under `groups`.
	Allow []string `yaml:"allow,omitempty"`
	// ForwardBearer sends the token on to the application as
	// `Authorization`, so a backend that verifies it against the issuer's
	// keys can, instead of trusting a header. Default true, which is right
	// for an application that checks. Set false for one that does not:
	// handing a bearer to something that will not verify it is a credential
	// in a place nothing reads, and the next thing to read it may not be the
	// application.
	ForwardBearer *bool `yaml:"forward_bearer,omitempty"`
	// CSRF is `off` (default), `shadow` or `enforce`. The gateway checks the
	// Origin header of every mutating request against the destination, which
	// is protection this application's cookies would otherwise need to
	// provide themselves.
	//
	// ONLY for a route a browser calls. Envoy refuses a mutating request
	// carrying neither Origin nor Referer, which is every curl, every
	// webhook and every server-to-server client -- so turning this on for an
	// API is an outage, not a hardening.
	//
	// Go through `shadow` first. It reports what enforcing would refuse, in
	// the fleet's csrf counters, without refusing it.
	CSRF string `yaml:"csrf,omitempty"`
	// CSRFAdditionalOrigins are origins other than this client's own host
	// that may make mutating requests to it.
	CSRFAdditionalOrigins []string `yaml:"csrf_additional_origins,omitempty"`
	// SameSite sets the attribute on the sign-in cookies: `Lax`, `Strict` or
	// `None`. Unset leaves the browser's own default, which differs between
	// browsers and versions -- so state it.
	//
	// This is the FIRST line and CSRF is the second: SameSite stops the
	// cookie being sent cross-site at all, and the Origin check catches what
	// SameSite cannot (a same-site attacker, an older browser). `Lax` suits
	// a console someone reaches by link; `Strict` suits one nobody links
	// into.
	SameSite string `yaml:"same_site,omitempty"`
}

// ForwardsBearer reports whether the proxy passes the token on, which it
// does unless the row says otherwise.
func (p *ClientProxy) ForwardsBearer() bool {
	return p == nil || p.ForwardBearer == nil || *p.ForwardBearer
}

// PostureOrDefault is the proxy's posture, defaulting to the one that
// leaves authorization with the application.
func (p *ClientProxy) PostureOrDefault() string {
	if p == nil || p.Posture == "" {
		return PostureAuthenticated
	}

	return p.Posture
}

// routeRuleName is Gateway API's own pattern for HTTPRouteRule.name, copied
// from the CRD rather than approximated: a name the API server refuses is
// refused here, where the message arrives before the apply.
var routeRuleName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

// IsRouteRuleName reports whether rule is a name Gateway API accepts for a
// route rule.
func IsRouteRuleName(rule string) bool {
	return len(rule) <= 253 && routeRuleName.MatchString(rule)
}

// Validate checks the proxy row. where is the caller's path to the row, as
// the messages should name it (for example `cfg/x: clients[web].proxy`).
// checkAllow validates the group names of `allow`, which are the estate's
// vocabulary; nil accepts any.
func (p *ClientProxy) Validate(where string, checkAllow func(allow []string) error) error {
	if err := p.validateRouteBinding(where); err != nil {
		return err
	}

	if err := p.validateCookieDefences(where); err != nil {
		return err
	}

	if checkAllow != nil {
		if err := checkAllow(p.Allow); err != nil {
			return err
		}
	}

	switch p.PostureOrDefault() {
	case PostureAuthenticated:
		if len(p.Allow) > 0 {
			return fmt.Errorf(
				"%s: posture `authenticated` admits every signed-in identity, so `allow` would be read by nothing",
				where)
		}
	case PostureGroups:
		if len(p.Allow) == 0 {
			return fmt.Errorf("%s: posture `groups` with an empty `allow` admits nobody", where)
		}
	default:
		return fmt.Errorf("%s: posture %q is neither `authenticated` nor `groups`", where, p.Posture)
	}

	return nil
}

// validateRouteBinding checks what this policy is bound TO: one route,
// named one way, and at most one rule of it.
func (p *ClientProxy) validateRouteBinding(where string) error {
	switch {
	case p.AttachRouteName == "":
		return fmt.Errorf(
			"%s: name the route this binds to with attach_route_name — "+
				"the gateway renders none of its own, and a policy that protects no route protects nothing",
			where)
	case p.AttachRouteRule != "" && !IsRouteRuleName(p.AttachRouteRule):
		return fmt.Errorf(
			"%s.attach_route_rule: %q is not a Gateway API rule name "+
				"(lower-case letters, digits, - and ., starting and ending alphanumeric) — the API server would "+
				"refuse the SecurityPolicy after everything else in the wave had applied",
			where, p.AttachRouteRule)
	}

	return nil
}

// validateCookieDefences checks the two settings on the sign-in cookies the
// gateway owns.
func (p *ClientProxy) validateCookieDefences(where string) error {
	switch {
	case p.CSRF != "" && p.CSRF != CSRFOff && p.CSRF != CSRFShadow && p.CSRF != CSRFEnforce:
		return fmt.Errorf("%s.csrf: %q is not %q, %q or %q", where, p.CSRF, CSRFOff, CSRFShadow, CSRFEnforce)
	case len(p.CSRFAdditionalOrigins) > 0 && (p.CSRF == "" || p.CSRF == CSRFOff):
		return fmt.Errorf(
			"%s.csrf_additional_origins: listed without csrf — origins nothing checks are not a policy", where)
	case p.SameSite != "" && p.SameSite != "Lax" && p.SameSite != "Strict" && p.SameSite != "None":
		return fmt.Errorf("%s.same_site: %q is not Lax, Strict or None", where, p.SameSite)
	}

	return nil
}
