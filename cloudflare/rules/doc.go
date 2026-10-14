// Package rules turns the Cloudflare rules an estate wants into the ONE
// ruleset per phase a zone can hold.
//
// A zone has a single entry point ruleset per phase, so two programs (or two
// features of one program) cannot each create "the cache ruleset": the second
// would replace the first. This package inverts that. Each feature states a
// [Contribution], the rules it wants in a phase, and [Assemble] merges all of
// them into one ordered rule list per [Phase] that a single resource owns.
// The package links the standard library and cloudflare/zonespec only: it
// models rules, it does not create them, so a caller can assemble, test and
// diff a zone's rules without a Pulumi or Cloudflare SDK. The caller maps a
// [Rule] onto its provider's ruleset rule.
//
// # Contributions and order
//
// A Contribution names its Source (who wants these rules), the Phase, an
// Order and its Rules. Assemble sorts contributions by (Order, Source) and
// concatenates their rules, so the assembled order depends on neither the
// order contributions were passed in nor on map iteration. The conventional
// Orders in the cache phase are [OrderHostsCache] (100), the assembler's
// own catch-all [OrderBypass] (500) and [OrderPathCaches] (900).
//
// Assemble refuses a conflicting writer: a Ref used twice within a phase, an
// unknown phase, a rule without a Ref, action or expression, or a Claim
// outside the cache phase.
//
// # The cache phase: Claim and the bypass fold
//
// Cloudflare merges cache settings from every matching rule, so a request
// matched by two cache rules gets a blend. The cache phase is therefore
// kept a PARTITION: every request matches exactly one rule. A contribution
// that caches something declares what it serves as its Claim, a
// parenthesised expression. Assemble then adds one catch-all rule, Ref
// [BypassRef], at Order 500 that bypasses the cache for everything no
// contribution claimed. Its expression folds over the claims in Order:
//
//	no claims:             true
//	one claim a:           not a
//	two claims a, b:       (not a) and not b
//	three claims a, b, c:  ((not a) and not b) and not c
//
// With a hosts rule claiming "(http.host in {"a.example.com"})" and a path
// rule claiming "(http.host eq "b.example.com" and ...)" the bypass reads
//
//	(not (http.host in {"a.example.com"})) and not (http.host eq "b.example.com" and ...)
//
// A cache-phase contribution with no Claim caches something the bypass
// does not exclude; that is the contributor's decision and is not checked.
//
// # What is not a rule
//
// Authenticated Origin Pulls is a zone (or hostname) certificate setting, not
// a ruleset rule, so there is no builder for it here.
package rules
