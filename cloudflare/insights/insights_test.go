package insights_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/edge/v3/cloudflare/insights"
)

func fixture(t *testing.T, name string) string {
	b, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)

	return string(b)
}

func TestListFollowsPagesAndFilters(t *testing.T) {
	var queries []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/accounts/acct1/security-center/insights", r.URL.Path)
		assert.Equal(t, "Bearer tok-secret", r.Header.Get("Authorization"))
		queries = append(queries, r.URL.RawQuery)

		if r.URL.Query().Get("page") == "1" {
			_, _ = io.WriteString(w, fixture(t, "insights_page1.json"))

			return
		}

		_, _ = io.WriteString(w, fixture(t, "insights_page2.json"))
	}))
	defer srv.Close()

	c := insights.NewClient("tok-secret")
	c.API.Base = srv.URL
	c.PerPage = 2

	got, err := c.List(context.Background(), insights.Scope{AccountID: "acct1"},
		insights.Filter{Severity: []string{"critical", "Moderate"}, Type: []string{"insecure_configuration"}})
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, "Critical", got[0].Severity)
	require.Len(t, queries, 2)
	assert.Contains(t, queries[0], "severity=Critical&severity=Moderate")
	assert.Contains(t, queries[0], "issue_type=insecure_configuration")
	assert.Contains(t, queries[0], "dismissed=false")
}

func TestDismissedAnyOmitsTheParameter(t *testing.T) {
	q, err := insights.Filter{Dismissed: insights.AnyState}.Query(1, 10)
	require.NoError(t, err)
	assert.False(t, q.Has("dismissed"))

	q, _ = insights.Filter{Dismissed: insights.OnlyDismissed}.Query(1, 10)
	assert.Equal(t, "true", q.Get("dismissed"))

	_, err = insights.Filter{Severity: []string{"huge"}}.Query(1, 10)
	require.Error(t, err)
}

func TestScopeNeedsExactlyOne(t *testing.T) {
	c := insights.NewClient("t")
	_, err := c.List(context.Background(), insights.Scope{}, insights.Filter{})
	require.Error(t, err)
	_, err = c.List(context.Background(), insights.Scope{AccountID: "a", ZoneID: "z"}, insights.Filter{})
	require.Error(t, err)
}

func TestEventsSummarisesPerHost(t *testing.T) {
	var body struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/graphql", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		_, _ = io.WriteString(w, fixture(t, "events.json"))
	}))
	defer srv.Close()

	c := insights.NewClient("tok-secret")
	c.API.Base = srv.URL
	to := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

	s, err := c.Events(context.Background(), insights.EventsQuery{
		ZoneID: "zone1", Window: insights.Window{From: to.Add(-24 * time.Hour), To: to}, Host: "API.example.com\" } evil",
	})
	require.NoError(t, err)

	assert.Contains(t, body.Query, "firewallEventsAdaptiveGroups")
	assert.Contains(t, body.Query, `datetime_geq: "2026-10-14T12:00:00Z"`)
	assert.Contains(t, body.Query, `clientRequestHTTPHost: "api.example.com\" } evil"`, "values are quoted, not spliced")
	assert.Equal(t, "zone1", body.Variables["zone"])

	require.Len(t, s.Hosts, 2)
	assert.Equal(t, "api.example.com", s.Hosts[0].Host)
	assert.Equal(t, int64(140), s.Hosts[0].Total)
	assert.Equal(t, int64(120), s.Hosts[0].Blocking)
	assert.Equal(t, "100010", s.Hosts[0].Rows[0].RuleID)
	assert.False(t, s.Truncated)
}

func TestEventsGraphQLErrorAndBadWindow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":null,"errors":[{"message":"zone does not have access to the path"}]}`)
	}))
	defer srv.Close()

	c := insights.NewClient("t")
	c.API.Base = srv.URL
	now := time.Now()

	_, err := c.Events(context.Background(), insights.EventsQuery{ZoneID: "z", Window: insights.Window{From: now.Add(-time.Hour), To: now}})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "does not have access"))

	_, err = c.Events(context.Background(), insights.EventsQuery{ZoneID: "z", Window: insights.Window{From: now, To: now}})
	require.Error(t, err)
}

func TestSummariseMergesDuplicates(t *testing.T) {
	s := insights.Summarise([]insights.Row{
		{Host: "a.example.com", RuleID: "r1", Action: "log", Count: 2},
		{Host: "a.example.com", RuleID: "r1", Action: "log", Count: 3},
	})
	require.Len(t, s.Hosts, 1)
	assert.Equal(t, int64(5), s.Hosts[0].Rows[0].Count)
	assert.Zero(t, s.Hosts[0].Blocking)
}
