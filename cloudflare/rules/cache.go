package rules

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/truvity/edge/v3/cloudflare/zonespec"
)

// CacheHosts is the zone's cacheable-hosts rule: the listed hosts (exact
// names and "*." wildcards) are cached, the origin's Cache-Control decides how
// long. It claims the hosts, so the assembled bypass leaves them alone. No
// hosts is a contribution with no rules and no claim: the assembled phase is
// then the bypass alone and the zone caches nothing. Hosts are validated by
// zonespec.Args.Validate (Cache.Hosts), not here.
func CacheHosts(hosts []string) Contribution {
	c := Contribution{Source: "cache-hosts", Phase: PhaseCacheSettings, Order: OrderHostsCache}
	if len(hosts) == 0 {
		return c
	}

	expr := zonespec.HostExpression(hosts)
	c.Claim = "(" + expr + ")"
	c.Rules = []Rule{{
		Ref:         "cacheable-hosts",
		Description: "Cacheable hostname: the origin's Cache-Control decides",
		Action:      ActionSetCacheSettings,
		Expression:  expr,
		Params: Params{Cache: &CacheParams{
			Cache:      true,
			EdgeTTL:    &TTL{Mode: TTLBypassByDefault},
			BrowserTTL: &TTL{Mode: TTLRespectOrigin},
		}},
	}}

	return c
}

// DefaultPublicCachePaths are the installation's public documents that are the
// same for every caller: the key set and the two metadata documents.
var DefaultPublicCachePaths = []string{
	"/keys",
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
}

const (
	// DefaultPublicCacheTTL is how long Cloudflare keeps a copy when
	// PublicPathsArgs.TTL is unset.
	DefaultPublicCacheTTL = 5 * time.Minute
	// MaxPublicCacheTTL is the longest TTL accepted. A key that is removed from
	// the key set stays served for up to the TTL, so it is kept short.
	MaxPublicCacheTTL = time.Hour
)

// PublicPathsArgs asks Cloudflare to cache a host's public documents at the
// edge.
//
// A rule caches a request only when it carries no Origin header. The service
// answers a request with an Origin by echoing it in
// Access-Control-Allow-Origin, Cloudflare ignores Vary: Origin, and a cache key
// that includes a request header is an Enterprise feature: a cached copy would
// hand one site's CORS answer to the next. Requests without an Origin (token
// verifiers, CLIs, cloud STS services, MCP servers) are cached; browser
// requests still reach the origin.
type PublicPathsArgs struct {
	// TTL is how long Cloudflare keeps a copy (the rule's edge TTL, overriding
	// the origin, which sends no Cache-Control). Default DefaultPublicCacheTTL,
	// at least a second, at most MaxPublicCacheTTL, in whole seconds. Keep it
	// shorter than the signing keys' prepublish window, so a key is in every
	// cached key set before it signs.
	TTL time.Duration
	// Paths are the exact request paths cached. Default DefaultPublicCachePaths.
	// Each starts with "/" and holds only URL path characters; nothing that
	// differs by caller belongs here.
	Paths []string
}

// CacheRule is a Cloudflare cache rule, in the zone's own terms. It has the
// fields of the sluis edge package's CacheRule, so code that handed that type
// around compiles against this one.
type CacheRule struct {
	// Description is a one-line description for the rule.
	Description string
	// Expression is the rule's filter in Cloudflare's Rules language.
	Expression string
	// EdgeTTLSeconds is the edge TTL (edge_ttl.default, mode override_origin).
	EdgeTTLSeconds int
	// Host and Paths are what Expression matches, for an estate that builds
	// its own expression or reports on the rule.
	Host  string
	Paths []string
}

// hostPattern and pathPattern keep the values put into the expression to
// characters that need no quoting in a Rules-language string.
var (
	hostPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$`)
	pathPattern = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)
)

// PublicPathsCache is the rule that caches host's public documents at the
// edge. It is the sluis edge package's PublicCacheRule, moved here unchanged:
// the same checks, expression and defaults. It needs no Pulumi engine.
func PublicPathsCache(host string, a PublicPathsArgs) (CacheRule, error) {
	if !hostPattern.MatchString(host) {
		return CacheRule{}, fmt.Errorf("rules: public cache: host %q is not a domain name", host)
	}

	ttl := a.TTL
	if ttl == 0 {
		ttl = DefaultPublicCacheTTL
	}

	if ttl < time.Second || ttl > MaxPublicCacheTTL || ttl%time.Second != 0 {
		return CacheRule{}, fmt.Errorf("rules: public cache: TTL %s must be whole seconds between 1s and %s", ttl, MaxPublicCacheTTL)
	}

	paths := a.Paths
	if len(paths) == 0 {
		paths = DefaultPublicCachePaths
	}

	paths = slices.Clone(paths)

	for _, p := range paths {
		if !pathPattern.MatchString(p) {
			return CacheRule{}, fmt.Errorf("rules: public cache: path %q must start with / and hold only URL path characters", p)
		}
	}

	slices.Sort(paths)

	if len(slices.Compact(slices.Clone(paths))) != len(paths) {
		return CacheRule{}, errors.New("rules: public cache: a path is listed twice")
	}

	quoted := make([]string, len(paths))
	for i, p := range paths {
		quoted[i] = `"` + p + `"`
	}

	expr := fmt.Sprintf(`(http.host eq "%s" and http.request.method in {"GET" "HEAD"} and http.request.uri.path in {%s} `+
		`and not any(lower(http.request.headers.names[*])[*] eq "origin"))`, host, strings.Join(quoted, " "))

	return CacheRule{
		Description:    fmt.Sprintf("%s: public documents, %s at the edge, requests without Origin", host, ttl),
		Expression:     expr,
		EdgeTTLSeconds: int(ttl / time.Second),
		Host:           host,
		Paths:          paths,
	}, nil
}

// Contribution is the rule as a cache-phase contribution at OrderPathCaches:
// cache true, edge TTL override_origin for EdgeTTLSeconds, browser TTL
// respect_origin. Its Expression is its claim, so the assembled bypass leaves
// these requests alone.
func (r CacheRule) Contribution() Contribution {
	return Contribution{
		Source: "public-paths:" + r.Host,
		Phase:  PhaseCacheSettings,
		Order:  OrderPathCaches,
		Claim:  r.Expression,
		Rules: []Rule{{
			Ref:         "public-paths-" + r.Host,
			Description: r.Description,
			Action:      ActionSetCacheSettings,
			Expression:  r.Expression,
			Params: Params{Cache: &CacheParams{
				Cache:      true,
				EdgeTTL:    &TTL{Mode: TTLOverrideOrigin, Default: r.EdgeTTLSeconds},
				BrowserTTL: &TTL{Mode: TTLRespectOrigin},
			}},
		}},
	}
}

const (
	// DefaultStaticEdgeTTL is how long content-hashed files stay at the edge
	// when StaticSiteArgs.EdgeTTL is unset: a year, Cloudflare's longest.
	DefaultStaticEdgeTTL = 365 * 24 * time.Hour
	// MaxStaticEdgeTTL is the longest edge TTL accepted.
	MaxStaticEdgeTTL = 365 * 24 * time.Hour
)

// StaticSiteArgs caches a static site that is a whole host.
type StaticSiteArgs struct {
	// HashedPrefix is the path prefix ("/assets/") under which file names
	// carry a content hash, so a copy never goes stale. Only requests under
	// it get the long edge TTL. Empty has no such files: everything follows
	// the origin. Starts and ends with "/".
	HashedPrefix string
	// EdgeTTL is the edge TTL under HashedPrefix. Default
	// DefaultStaticEdgeTTL, whole seconds, at most MaxStaticEdgeTTL.
	EdgeTTL time.Duration
	// HTMLTTL is the edge TTL of everything else. Zero keeps the origin's
	// Cache-Control and strong ETag decisive (respect_origin).
	HTMLTTL time.Duration
}

// StaticSiteCache caches every request to host: the origin's Cache-Control
// and strong ETag decide everywhere except under HashedPrefix, which gets the
// long edge TTL. It claims the whole host.
func StaticSiteCache(host string, a StaticSiteArgs) (Contribution, error) {
	if !hostPattern.MatchString(host) {
		return Contribution{}, fmt.Errorf("rules: static site: host %q is not a domain name", host)
	}

	prefix := a.HashedPrefix
	if prefix != "" && (!pathPattern.MatchString(prefix) || !strings.HasSuffix(prefix, "/")) {
		return Contribution{}, fmt.Errorf("rules: static site: hashed prefix %q must start and end with / and hold only URL path characters", prefix)
	}

	edge := a.EdgeTTL
	if edge == 0 {
		edge = DefaultStaticEdgeTTL
	}

	for name, d := range map[string]time.Duration{"edge TTL": edge, "HTML TTL": a.HTMLTTL} {
		if d < 0 || d > MaxStaticEdgeTTL || d%time.Second != 0 {
			return Contribution{}, fmt.Errorf("rules: static site: %s %s must be whole seconds, at most %s", name, d, MaxStaticEdgeTTL)
		}
	}

	hostExpr := fmt.Sprintf(`http.host eq "%s"`, host)
	rest := &TTL{Mode: TTLRespectOrigin}

	if a.HTMLTTL > 0 {
		rest = &TTL{Mode: TTLOverrideOrigin, Default: int(a.HTMLTTL / time.Second)}
	}

	c := Contribution{
		Source: "static-site:" + host, Phase: PhaseCacheSettings, Order: OrderPathCaches,
		Claim: "(" + hostExpr + ")",
	}

	hashedMatch := fmt.Sprintf(`starts_with(http.request.uri.path, "%s")`, prefix)
	restExpr := hostExpr

	if prefix != "" {
		restExpr = hostExpr + " and not " + hashedMatch
		c.Rules = append(c.Rules, Rule{
			Ref:         "static-hashed-" + host,
			Description: fmt.Sprintf("%s: content-hashed files under %s, %s at the edge", host, prefix, edge),
			Action:      ActionSetCacheSettings,
			Expression:  hostExpr + " and " + hashedMatch,
			Params: Params{Cache: &CacheParams{
				Cache:              true,
				EdgeTTL:            &TTL{Mode: TTLOverrideOrigin, Default: int(edge / time.Second)},
				BrowserTTL:         &TTL{Mode: TTLRespectOrigin},
				RespectStrongETags: true,
			}},
		})
	}

	c.Rules = append(c.Rules, Rule{
		Ref:         "static-site-" + host,
		Description: host + ": static site, the origin's Cache-Control and ETag decide",
		Action:      ActionSetCacheSettings,
		Expression:  restExpr,
		Params: Params{Cache: &CacheParams{
			Cache:              true,
			EdgeTTL:            rest,
			BrowserTTL:         &TTL{Mode: TTLRespectOrigin},
			RespectStrongETags: true,
		}},
	})

	return c, nil
}
