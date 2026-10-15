// Package insights is the read-only view that judges a WAF rollout and shows
// Security Center warnings clearing. It has two halves:
//
//   - Security Center insights (the warnings the dashboard lists), over
//     GET /accounts/{account_id}/security-center/insights and
//     GET /zones/{zone_id}/security-center/insights, filtered by severity,
//     type and dismissed;
//   - Security Events (firewall events) summed per host, rule and action over
//     a time window, from the GraphQL Analytics API dataset
//     firewallEventsAdaptiveGroups, so the false positives per host are
//     visible before the managed WAF widens.
//
// Nothing here writes. The preset kind `insights` is the credential: Account
// Security Center Insights Read on the account, and Zone Security Center
// Insights Read, Analytics Read, Zone WAF Read and Bot Management Read on each
// zone.
package insights

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/truvity/edge/v3/cloudflare/internal/cfapi"
)

// Insight is one Security Center insight.
type Insight struct {
	ID         string          `json:"id"`
	Severity   string          `json:"severity"`
	IssueType  string          `json:"issue_type"`
	IssueClass string          `json:"issue_class"`
	Subject    string          `json:"subject"`
	Dismissed  bool            `json:"dismissed"`
	Timestamp  string          `json:"timestamp"`
	Header     string          `json:"header,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`
}

// Dismissed selects insights by their dismissed state.
type Dismissed int

// The dismissed filters. The zero value is Active, the dashboard's default.
const (
	Active Dismissed = iota // not dismissed
	OnlyDismissed
	AnyState
)

// Filter narrows a listing. Empty slices do not filter.
type Filter struct {
	// Severity values are Low, Moderate and Critical (case is normalised).
	Severity []string
	// Type values are issue types such as compliance_violation,
	// exposed_infrastructure, insecure_configuration, weak_authentication.
	Type []string
	// Class values are issue classes such as always_use_https_not_enabled.
	Class     []string
	Dismissed Dismissed
}

// Scope is where insights are listed: an account or a zone, by id.
type Scope struct {
	AccountID string
	ZoneID    string
}

func (s Scope) path() (string, error) {
	switch {
	case s.AccountID != "" && s.ZoneID != "":
		return "", fmt.Errorf("name an account or a zone, not both")
	case s.AccountID != "":
		return "/accounts/" + url.PathEscape(s.AccountID) + "/security-center/insights", nil
	case s.ZoneID != "":
		return "/zones/" + url.PathEscape(s.ZoneID) + "/security-center/insights", nil
	}

	return "", fmt.Errorf("name an account or a zone")
}

var severities = map[string]string{"low": "Low", "moderate": "Moderate", "critical": "Critical"}

// Query is the URL query a filter makes, for one page.
func (f Filter) Query(page, perPage int) (url.Values, error) {
	q := url.Values{}
	q.Set("page", strconv.Itoa(page))
	q.Set("per_page", strconv.Itoa(perPage))

	for _, s := range f.Severity {
		canon, ok := severities[strings.ToLower(strings.TrimSpace(s))]
		if !ok {
			return nil, fmt.Errorf("severity %q: want Low, Moderate or Critical", s)
		}

		q.Add("severity", canon)
	}

	for _, t := range f.Type {
		q.Add("issue_type", strings.TrimSpace(t))
	}

	for _, c := range f.Class {
		q.Add("issue_class", strings.TrimSpace(c))
	}

	switch f.Dismissed {
	case Active:
		q.Set("dismissed", "false")
	case OnlyDismissed:
		q.Set("dismissed", "true")
	}

	return q, nil
}

// Client reads insights and events with one token.
type Client struct {
	API cfapi.Client
	// PerPage is the page size; zero means 100.
	PerPage int
	// MaxPages bounds a listing; zero means 50.
	MaxPages int
}

// NewClient is a Client with the given token against the public API.
func NewClient(token string) *Client { return &Client{API: cfapi.Client{Token: token}} }

// List returns every insight in scope that passes the filter, following the
// pages up to MaxPages.
func (c *Client) List(ctx context.Context, scope Scope, f Filter) ([]Insight, error) {
	path, err := scope.path()
	if err != nil {
		return nil, err
	}

	perPage, maxPages := c.PerPage, c.MaxPages
	if perPage <= 0 {
		perPage = 100
	}

	if maxPages <= 0 {
		maxPages = 50
	}

	out := []Insight{}

	for page := 1; page <= maxPages; page++ {
		q, err := f.Query(page, perPage)
		if err != nil {
			return nil, err
		}

		env, err := c.API.Do(ctx, "GET", path, q, nil)
		if err != nil {
			return nil, err
		}

		var res struct {
			Count   int       `json:"count"`
			Issues  []Insight `json:"issues"`
			Page    int       `json:"page"`
			PerPage int       `json:"per_page"`
		}

		if err := json.Unmarshal(env.Result, &res); err != nil {
			return nil, fmt.Errorf("decode insights: %w", err)
		}

		out = append(out, res.Issues...)

		if len(res.Issues) == 0 || len(out) >= res.Count {
			return out, nil
		}
	}

	return nil, fmt.Errorf("more than %d pages of insights; narrow the filter", maxPages)
}
