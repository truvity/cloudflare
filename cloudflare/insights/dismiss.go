package insights

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// issueIDPattern is a safe insight id: letters, digits, dot, dash and
// underscore. Cloudflare's ids embed the subject, a host name for the DNS
// insights (<zone tag>-www.example.com-<n>-cname_record_not_proxied), so
// they carry dots; "." and ".." alone are refused as path segments.
// Cloudflare's ids are UUIDs; the pattern keeps anything that could change the
// path (slash, dot, query, whitespace) out of the request.
var issueIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,512}$`)

// ValidID reports whether id is a safe insight id.
func ValidID(id string) error {
	if !issueIDPattern.MatchString(id) || id == "." || id == ".." {
		return fmt.Errorf("insight id %q: want a non-empty token of letters, digits, '.', '-' and '_'", id)
	}

	return nil
}

func (s Scope) dismissPath(issueID string) (string, error) {
	if err := ValidID(issueID); err != nil {
		return "", err
	}

	base, err := s.path()
	if err != nil {
		return "", err
	}

	return base + "/" + url.PathEscape(issueID) + "/dismiss", nil
}

// Dismiss archives one insight (dismiss true) or brings it back (false).
//
// Endpoint, from Cloudflare's API reference "Archives Security Center Insight"
// (https://developers.cloudflare.com/api/resources/security_center/subresources/insights/methods/dismiss/):
//
//	PUT /accounts/{account_id}/security-center/insights/{issue_id}/dismiss
//	PUT /zones/{zone_id}/security-center/insights/{issue_id}/dismiss
//	body {"dismiss": true|false}
//
// It needs a Write permission group, the preset kind `insights-admin`; the
// read-only `insights` kind is refused by Cloudflare.
func (c *Client) Dismiss(ctx context.Context, scope Scope, issueID string, dismiss bool) error {
	path, err := scope.dismissPath(issueID)
	if err != nil {
		return err
	}

	body, err := json.Marshal(struct {
		Dismiss bool `json:"dismiss"`
	}{dismiss})
	if err != nil {
		return err
	}

	_, err = c.API.Do(ctx, "PUT", path, nil, body)

	return err
}

// DismissMatching lists the insights of scope that pass f and dismisses each
// one (or, with Client.Undo, brings each dismissed one back). It is a dry run
// unless Client.Apply is set: nothing is written and the insights that would
// change are returned. The returned slice is what was changed, or with no
// Apply what would be; on a failure part way it holds those done before it,
// with the error.
//
// f.Dismissed is overridden: Active when dismissing, OnlyDismissed when
// undoing, so an insight is never written twice.
//
// reason is a note for the caller's log; Cloudflare's endpoint takes no
// reason, so it is validated (printable, at most 200 bytes) and not sent.
func (c *Client) DismissMatching(ctx context.Context, scope Scope, f Filter, reason string) ([]Insight, error) {
	if len(reason) > 200 || strings.ContainsFunc(reason, func(r rune) bool { return r < ' ' || r == 0x7f }) {
		return nil, fmt.Errorf("reason: want printable text of at most 200 bytes")
	}

	if c.Undo {
		f.Dismissed = OnlyDismissed
	} else {
		f.Dismissed = Active
	}

	items, err := c.List(ctx, scope, f)
	if err != nil {
		return nil, err
	}

	if !c.Apply {
		return items, nil
	}

	done := []Insight{}

	for k := range items {
		if err := c.Dismiss(ctx, scope, items[k].ID, !c.Undo); err != nil {
			return done, fmt.Errorf("insight %s: %w", items[k].ID, err)
		}

		done = append(done, items[k])
	}

	return done, nil
}
