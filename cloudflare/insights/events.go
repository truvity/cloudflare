package insights

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// graphqlPath is the GraphQL Analytics endpoint, below the API root.
const graphqlPath = "/graphql"

// MaxRows is the most groups one query asks for (the dataset's limit).
const MaxRows = 10000

// Window is the time range of an events query.
type Window struct {
	From, To time.Time
}

// EventsQuery asks for the Security Events of one zone.
type EventsQuery struct {
	ZoneID string
	Window Window
	// Host, Action, Source and RuleID narrow the events when non-empty.
	// Action is a Cloudflare action (block, managed_challenge, log, skip...);
	// Source is the product (waf, managed, firewallCustom, rateLimit...).
	Host, Action, Source, RuleID string
	// Limit is the number of groups asked for; zero means MaxRows.
	Limit int
}

// Row is one group of events: how many times one rule took one action on one
// host.
type Row struct {
	Host        string `json:"host"`
	RuleID      string `json:"rule_id"`
	Description string `json:"description,omitempty"`
	Source      string `json:"source"`
	Action      string `json:"action"`
	Count       int64  `json:"count"`
}

// HostSummary is one host's events: the total, and the rows by count.
type HostSummary struct {
	Host  string `json:"host"`
	Total int64  `json:"total"`
	// Blocking is the part of Total whose action stops the request (block and
	// the challenge actions): the figure a false-positive review reads first.
	Blocking int64 `json:"blocking"`
	Rows     []Row `json:"rows"`
}

// Summary is the answer: the window, whether the dataset's row limit cut it,
// and the hosts by total.
type Summary struct {
	ZoneID    string        `json:"zone_id"`
	From      time.Time     `json:"from"`
	To        time.Time     `json:"to"`
	Truncated bool          `json:"truncated,omitempty"`
	Hosts     []HostSummary `json:"hosts"`
}

// eventsQuery is the query text; %s is the filter object, built from values
// that went through json.Marshal (a JSON string is a GraphQL string), so no
// caller text reaches the query unquoted.
const eventsQuery = `query SecurityEvents($zone: string!, $limit: uint64!) {
  viewer {
    zones(filter: {zoneTag: $zone}) {
      firewallEventsAdaptiveGroups(limit: $limit, filter: %s, orderBy: [count_DESC]) {
        count
        dimensions {
          clientRequestHTTPHost
          ruleId
          description
          source
          action
        }
      }
    }
  }
}`

// filter is the GraphQL filter object of a query, as text.
func (q EventsQuery) filter() string {
	pairs := [][2]string{
		{"datetime_geq", q.Window.From.UTC().Format(time.RFC3339)},
		{"datetime_leq", q.Window.To.UTC().Format(time.RFC3339)},
		{"clientRequestHTTPHost", strings.ToLower(q.Host)},
		{"action", q.Action},
		{"source", q.Source},
		{"ruleId", q.RuleID},
	}

	var b strings.Builder

	b.WriteByte('{')

	for _, p := range pairs {
		if p[1] == "" {
			continue
		}

		quoted, _ := json.Marshal(p[1]) // a string always marshals

		if b.Len() > 1 {
			b.WriteString(", ")
		}

		b.WriteString(p[0] + ": " + string(quoted))
	}

	b.WriteByte('}')

	return b.String()
}

// Events reads the groups and summarises them per host.
func (c *Client) Events(ctx context.Context, q EventsQuery) (*Summary, error) {
	switch {
	case q.ZoneID == "":
		return nil, errors.New("events: a zone id is required")
	case q.Window.From.IsZero() || q.Window.To.IsZero() || !q.Window.To.After(q.Window.From):
		return nil, errors.New("events: the window needs a start before its end")
	}

	limit := q.Limit
	if limit <= 0 || limit > MaxRows {
		limit = MaxRows
	}

	body, err := json.Marshal(map[string]any{
		"query":     fmt.Sprintf(eventsQuery, q.filter()),
		"variables": map[string]any{"zone": q.ZoneID, "limit": limit},
	})
	if err != nil {
		return nil, err
	}

	// The GraphQL endpoint answers {data, errors}, not the REST envelope, so
	// it is called with the REST client only for the transport; a failure is
	// read from the body.
	raw, err := c.API.Raw(ctx, "POST", graphqlPath, body)
	if err != nil {
		return nil, err
	}

	var res struct {
		Data struct {
			Viewer struct {
				Zones []struct {
					Groups []struct {
						Count      int64 `json:"count"`
						Dimensions struct {
							Host        string `json:"clientRequestHTTPHost"`
							RuleID      string `json:"ruleId"`
							Description string `json:"description"`
							Source      string `json:"source"`
							Action      string `json:"action"`
						} `json:"dimensions"`
					} `json:"firewallEventsAdaptiveGroups"`
				} `json:"zones"`
			} `json:"viewer"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("decode events: %w", err)
	}

	if len(res.Errors) > 0 {
		msgs := make([]string, 0, len(res.Errors))
		for _, e := range res.Errors {
			msgs = append(msgs, e.Message)
		}

		return nil, errors.New("graphql: " + strings.Join(msgs, "; "))
	}

	var rows []Row

	for _, z := range res.Data.Viewer.Zones {
		for _, g := range z.Groups {
			rows = append(rows, Row{
				Host: g.Dimensions.Host, RuleID: g.Dimensions.RuleID, Description: g.Dimensions.Description,
				Source: g.Dimensions.Source, Action: g.Dimensions.Action, Count: g.Count,
			})
		}
	}

	s := Summarise(rows)
	s.ZoneID = q.ZoneID
	s.From, s.To = q.Window.From.UTC(), q.Window.To.UTC()
	s.Truncated = len(rows) >= limit

	return s, nil
}

// blocking are the actions that stop or challenge a request.
func blocking(action string) bool {
	switch action {
	case "block", "challenge", "managed_challenge", "js_challenge", "legacy_captcha":
		return true
	}

	return false
}

// Summarise groups rows per host: hosts by total (then name), each host's rows
// by count (then rule, action). Rows that repeat a host, rule, source and
// action are added together.
func Summarise(rows []Row) *Summary {
	type key struct{ host, rule, source, action string }

	merged := map[key]Row{}

	for _, r := range rows {
		k := key{r.Host, r.RuleID, r.Source, r.Action}
		if m, ok := merged[k]; ok {
			m.Count += r.Count
			merged[k] = m
		} else {
			merged[k] = r
		}
	}

	byHost := map[string]*HostSummary{}

	for _, r := range merged {
		h := byHost[r.Host]
		if h == nil {
			h = &HostSummary{Host: r.Host}
			byHost[r.Host] = h
		}

		h.Total += r.Count
		if blocking(r.Action) {
			h.Blocking += r.Count
		}

		h.Rows = append(h.Rows, r)
	}

	out := &Summary{Hosts: make([]HostSummary, 0, len(byHost))}

	for _, h := range byHost {
		sort.Slice(h.Rows, func(i, j int) bool {
			a, b := h.Rows[i], h.Rows[j]
			if a.Count != b.Count {
				return a.Count > b.Count
			}

			if a.RuleID != b.RuleID {
				return a.RuleID < b.RuleID
			}

			return a.Action < b.Action
		})

		out.Hosts = append(out.Hosts, *h)
	}

	sort.Slice(out.Hosts, func(i, j int) bool {
		a, b := out.Hosts[i], out.Hosts[j]
		if a.Total != b.Total {
			return a.Total > b.Total
		}

		return a.Host < b.Host
	})

	return out
}
