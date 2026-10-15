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

func TestDismissSendsPutWithBody(t *testing.T) {
	var gotPath, gotMethod, gotBody string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotPath, gotMethod, gotBody = r.URL.Path, r.Method, string(b)
		assert.Equal(t, "Bearer tok-secret", r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, `{"success":true,"errors":[],"result":{}}`)
	}))
	defer srv.Close()

	c := insights.NewClient("tok-secret")
	c.API.Base = srv.URL

	require.NoError(t, c.Dismiss(context.Background(), insights.Scope{AccountID: "acct1"}, "ab12-cd34", true))
	assert.Equal(t, "PUT", gotMethod)
	assert.Equal(t, "/accounts/acct1/security-center/insights/ab12-cd34/dismiss", gotPath)
	assert.JSONEq(t, `{"dismiss":true}`, gotBody)

	require.NoError(t, c.Dismiss(context.Background(), insights.Scope{ZoneID: "zone1"}, "ab12-cd34", false))
	assert.Equal(t, "/zones/zone1/security-center/insights/ab12-cd34/dismiss", gotPath)
	assert.JSONEq(t, `{"dismiss":false}`, gotBody)
}

func TestDismissRejectsUnsafeIDs(t *testing.T) {
	c := insights.NewClient("t")

	for _, id := range []string{"", "a/b", "../x", "a b", "a?b=1", ".", "..", "a\n"} {
		require.Error(t, c.Dismiss(context.Background(), insights.Scope{AccountID: "a"}, id, true), "%q", id)
	}

	require.Error(t, c.Dismiss(context.Background(), insights.Scope{}, "ok", true))
}

// Cloudflare's DNS insight ids embed the host name, so they carry dots.
func TestDismissAcceptsHostNameIDs(t *testing.T) {
	var gotPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = io.WriteString(w, `{"success":true,"errors":[],"result":{}}`)
	}))
	defer srv.Close()

	c := insights.NewClient("t")
	c.API.Base = srv.URL

	id := "0123456789abcdef0123456789abcdef-www.example.com-123-cname_record_not_proxied"
	require.NoError(t, c.Dismiss(context.Background(), insights.Scope{ZoneID: "zone1"}, id, true))
	assert.Equal(t, "/zones/zone1/security-center/insights/"+id+"/dismiss", gotPath)
}

func TestDismissMatchingIsDryRunUnlessApplied(t *testing.T) {
	var puts []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			puts = append(puts, r.URL.Path)
			_, _ = io.WriteString(w, `{"success":true,"errors":[],"result":{}}`)

			return
		}

		assert.Equal(t, "false", r.URL.Query().Get("dismissed"))
		assert.Equal(t, "Low", r.URL.Query().Get("severity"))
		_, _ = io.WriteString(w, `{"success":true,"errors":[],"result":{"count":2,"page":1,"per_page":100,"issues":[`+
			`{"id":"aa11","severity":"Low","issue_type":"t","issue_class":"c","subject":"example.com"},`+
			`{"id":"bb22","severity":"Low","issue_type":"t","issue_class":"c","subject":"example.org"}]}}`)
	}))
	defer srv.Close()

	c := insights.NewClient("tok")
	c.API.Base = srv.URL

	f := insights.Filter{Severity: []string{"low"}, Dismissed: insights.AnyState}

	got, err := c.DismissMatching(context.Background(), insights.Scope{ZoneID: "z1"}, f, "accepted risk")
	require.NoError(t, err)
	assert.Len(t, got, 2)
	assert.Empty(t, puts, "dry run writes nothing")

	c.Apply = true
	got, err = c.DismissMatching(context.Background(), insights.Scope{ZoneID: "z1"}, f, "accepted risk")
	require.NoError(t, err)
	assert.Len(t, got, 2)
	assert.Equal(t, []string{
		"/zones/z1/security-center/insights/aa11/dismiss",
		"/zones/z1/security-center/insights/bb22/dismiss",
	}, puts)

	_, err = c.DismissMatching(context.Background(), insights.Scope{ZoneID: "z1"}, f, "bad\nreason")
	require.Error(t, err)
}

func TestDismissMatchingStopsAtFirstFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			if strings.Contains(r.URL.Path, "bb22") {
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"result":null}`)

				return
			}

			_, _ = io.WriteString(w, `{"success":true,"errors":[],"result":{}}`)

			return
		}

		_, _ = io.WriteString(w, `{"success":true,"errors":[],"result":{"count":2,"page":1,"per_page":100,"issues":[{"id":"aa11"},{"id":"bb22"}]}}`)
	}))
	defer srv.Close()

	c := insights.NewClient("tok-secret")
	c.API.Base = srv.URL
	c.Apply = true

	got, err := c.DismissMatching(context.Background(), insights.Scope{AccountID: "a1"}, insights.Filter{}, "")
	require.ErrorContains(t, err, "bb22")
	assert.NotContains(t, err.Error(), "tok-secret")
	require.Len(t, got, 1)
	assert.Equal(t, "aa11", got[0].ID)
}

func TestDismissMatchingUndoListsDismissedAndRestores(t *testing.T) {
	var body string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			b, _ := io.ReadAll(r.Body)
			body = string(b)
			_, _ = io.WriteString(w, `{"success":true,"errors":[],"result":{}}`)

			return
		}

		assert.Equal(t, "true", r.URL.Query().Get("dismissed"))
		_, _ = io.WriteString(w, `{"success":true,"errors":[],"result":{"count":1,"page":1,"per_page":100,"issues":[{"id":"aa11","dismissed":true}]}}`)
	}))
	defer srv.Close()

	c := insights.NewClient("tok")
	c.API.Base = srv.URL
	c.Apply, c.Undo = true, true

	got, err := c.DismissMatching(context.Background(), insights.Scope{AccountID: "a1"}, insights.Filter{}, "")
	require.NoError(t, err)
	assert.Len(t, got, 1)
	assert.JSONEq(t, `{"dismiss":false}`, body)
}
