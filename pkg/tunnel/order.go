package tunnel

import (
	"slices"
	"strings"
)

// OrderHosts puts a tunnel's hostnames in ingress order. Order is
// derived, never authored, because cloudflared makes it load-bearing:
//
//   - FIRST MATCH WINS, and the origin SNI is the MATCHED rule's
//     hostname. The fleet selects listeners (and certificates) by SNI,
//     so a host caught by a broader rule is sent under that rule's name
//     and lands on the wrong listener — or on none, and answers 502. A
//     host that falls through to a broad "*.example.com" rule fails
//     exactly this way.
//   - `*` SPANS DOTS: "*.env.example.com" also catches
//     "a.team.env.example.com". Listed above "*.team.env.example.com"
//     it would send every host of that team to the listener of the
//     broader rule instead, silently.
//
// So: every exact host first, then wildcards deeper-first (more labels
// first). Within each part hosts are in DNS canonical order (RFC 4034
// §6.1: compared label by label from the root), which keeps one parent
// domain's names together. No exact host can shadow another, and no
// wildcard can shadow one with more labels, so the result never trips
// Args.Validate.
func OrderHosts(hosts []string) []string {
	out := slices.Clone(hosts)

	slices.SortStableFunc(out, func(a, b string) int {
		aWild, bWild := isWildcard(a), isWildcard(b)

		switch {
		case aWild != bWild:
			if aWild {
				return 1
			}

			return -1
		case aWild:
			if d := labelCount(b) - labelCount(a); d != 0 {
				return d
			}
		}

		return canonicalCompare(a, b)
	})

	return out
}

func isWildcard(host string) bool { return strings.HasPrefix(host, "*.") }

func labelCount(host string) int { return strings.Count(host, ".") + 1 }

// canonicalCompare orders hostnames as DNS does (RFC 4034 §6.1): label
// by label from the rightmost, a name before its own subdomains.
func canonicalCompare(a, b string) int {
	al := strings.Split(strings.ToLower(a), ".")
	bl := strings.Split(strings.ToLower(b), ".")

	for i := 1; i <= len(al) && i <= len(bl); i++ {
		if d := strings.Compare(al[len(al)-i], bl[len(bl)-i]); d != 0 {
			return d
		}
	}

	return len(al) - len(bl)
}
