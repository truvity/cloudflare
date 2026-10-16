package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func env(k string) string {
	if k == "CLOUDFLARE_API_TOKEN" {
		return "tok-secret"
	}

	return ""
}

func TestListAndEvents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" {
			_, _ = io.WriteString(w, `{"data":{"viewer":{"zones":[{"firewallEventsAdaptiveGroups":[`+
				`{"count":3,"dimensions":{"clientRequestHTTPHost":"a.example.com","ruleId":"r1",`+
				`"description":"d","source":"managed","action":"block"}}]}]}},"errors":null}`)

			return
		}

		assert.Equal(t, "/zones/zone1/security-center/insights", r.URL.Path)
		_, _ = io.WriteString(w, `{"success":true,"errors":[],"result":{"count":1,"page":1,"per_page":100,"issues":[`+
			`{"id":"x","severity":"Low","issue_type":"insecure_configuration","issue_class":"c",`+
			`"subject":"example.com","dismissed":false,"timestamp":"2026-10-01T00:00:00Z"}]}}`)
	}))
	defer srv.Close()

	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)

	var out bytes.Buffer

	require.NoError(t, run(context.Background(), []string{"list", "-zone", "zone1", "-severity", "low,moderate"}, &out, env, now, srv.URL))
	assert.Contains(t, out.String(), "insecure_configuration")
	assert.Contains(t, out.String(), "1 insight(s)")

	out.Reset()
	require.NoError(t, run(context.Background(), []string{"events", "-zone", "zone1", "-format", "json"}, &out, env, now, srv.URL))

	var got struct{ Hosts []struct{ Host string } }
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	require.Len(t, got.Hosts, 1)

	out.Reset()
	require.NoError(t, run(context.Background(), []string{"events", "-zone", "zone1"}, &out, env, now, srv.URL))
	assert.Contains(t, out.String(), "a.example.com")
	assert.NotContains(t, out.String(), "tok-secret")
}

func TestUsage(t *testing.T) {
	require.Error(t, run(context.Background(), nil, io.Discard, env, time.Now(), ""))
	require.Error(t, run(context.Background(), []string{"events", "-zone", "z", "-from", "x"}, io.Discard, env, time.Now(), ""))
}

// serveInsights answers PUTs into puts and, for GETs, lists the issues given
// as JSON objects; a request with issue_class=nothing lists none.
func serveInsights(puts *[]string, issues ...string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			b, _ := io.ReadAll(r.Body)
			*puts = append(*puts, r.URL.Path+" "+string(b))
			_, _ = io.WriteString(w, `{"success":true,"errors":[],"result":{}}`)

			return
		}

		if r.URL.Query().Get("issue_class") == "nothing" {
			_, _ = io.WriteString(w, `{"success":true,"errors":[],"result":{"count":0,"page":1,"per_page":100,"issues":[]}}`)

			return
		}

		_, _ = io.WriteString(w, `{"success":true,"errors":[],"result":{"count":`+strconv.Itoa(len(issues))+
			`,"page":1,"per_page":100,"issues":[`+strings.Join(issues, ",")+`]}}`)
	}))
}

func dismissServer(puts *[]string) *httptest.Server {
	return serveInsights(puts,
		`{"id":"ab12","severity":"Low","issue_type":"t","issue_class":"c","subject":"example.com","dismissed":false}`)
}

// TestDismissTableFillsColumns checks that the dismiss table carries the
// same columns as list, for insights named by id and by filter.
func TestDismissTableFillsColumns(t *testing.T) {
	var puts []string

	srv := serveInsights(&puts,
		`{"id":"x1","severity":"Low","issue_type":"t1","issue_class":"c1","subject":"a.example.com","dismissed":false,"timestamp":"2026-10-01T00:00:00Z"}`,
		`{"id":"x2","severity":"Critical","issue_type":"t2","issue_class":"c2","subject":"b.example.com","dismissed":false,"timestamp":"2026-10-02T00:00:00Z"}`)
	defer srv.Close()

	now := time.Now()
	ctx := context.Background()

	for _, args := range [][]string{
		{"dismiss", "-zone", "z1", "-id", "x1,x2"},
		{"dismiss", "-zone", "z1", "-class", "c1,c2"},
	} {
		var out bytes.Buffer

		require.NoError(t, run(ctx, args, &out, env, now, srv.URL), "%v", args)

		rows := map[string]bool{}
		for _, line := range strings.Split(out.String(), "\n") {
			rows[strings.Join(strings.Fields(line), " ")] = true
		}

		assert.Contains(t, out.String(), "SEVERITY", "%v", args)
		assert.True(t, rows["Low t1 c1 a.example.com false 2026-10-01T00:00:00Z"], "%v: %s", args, out.String())
		assert.True(t, rows["Critical t2 c2 b.example.com false 2026-10-02T00:00:00Z"], "%v: %s", args, out.String())
	}

	assert.Empty(t, puts, "a dry run writes nothing")
}

func TestDismiss(t *testing.T) {
	var puts []string

	srv := dismissServer(&puts)
	defer srv.Close()

	now := time.Now()
	ctx := context.Background()

	var out bytes.Buffer

	// Dry run by filter: lists, writes nothing.
	require.NoError(t, run(ctx, []string{"dismiss", "-zone", "z1", "-class", "c"}, &out, env, now, srv.URL))
	assert.Contains(t, out.String(), "dry run: would dismiss 1 insight(s)")
	assert.Empty(t, puts)

	// Apply by filter.
	out.Reset()
	require.NoError(t, run(ctx, []string{"dismiss", "-zone", "z1", "-class", "c", "-apply"}, &out, env, now, srv.URL))
	assert.Equal(t, []string{`/zones/z1/security-center/insights/ab12/dismiss {"dismiss":true}`}, puts)

	// By id, undo: the ids are looked up in the account first.
	idSrv := serveInsights(&puts,
		`{"id":"x1","severity":"Low","issue_type":"t","issue_class":"c","subject":"a.example.com","dismissed":true}`,
		`{"id":"x2","severity":"Low","issue_type":"t","issue_class":"c","subject":"b.example.com","dismissed":true}`)
	defer idSrv.Close()

	puts = nil
	out.Reset()
	require.NoError(t, run(ctx, []string{"dismiss", "-account", "a1", "-id", "x1,x2", "-undo", "-apply", "-format", "json"}, &out, env, now, idSrv.URL))
	assert.Equal(t, []string{
		`/accounts/a1/security-center/insights/x1/dismiss {"dismiss":false}`,
		`/accounts/a1/security-center/insights/x2/dismiss {"dismiss":false}`,
	}, puts)
	assert.NotContains(t, out.String(), "tok-secret")
	assert.Contains(t, out.String(), `"subject": "b.example.com"`)

	// An id the scope does not list is refused before anything is written.
	puts = nil
	require.Error(t, run(ctx, []string{"dismiss", "-account", "a1", "-id", "x9", "-apply"}, io.Discard, env, now, idSrv.URL))
	assert.Empty(t, puts)

	// A filter that matches nothing is reported, not an error.
	puts = nil
	out.Reset()
	require.NoError(t, run(ctx, []string{"dismiss", "-zone", "z1", "-class", "nothing", "-apply"}, &out, env, now, srv.URL))
	assert.Contains(t, out.String(), "no insight matches")
	assert.Empty(t, puts)

	// Neither or both of id and filter, and an unsafe id.
	require.Error(t, run(ctx, []string{"dismiss", "-zone", "z1"}, io.Discard, env, now, srv.URL))
	require.Error(t, run(ctx, []string{"dismiss", "-zone", "z1", "-id", "a", "-class", "c"}, io.Discard, env, now, srv.URL))
	require.Error(t, run(ctx, []string{"dismiss", "-zone", "z1", "-id", "../x", "-apply"}, io.Discard, env, now, srv.URL))
	assert.Empty(t, puts)
}
