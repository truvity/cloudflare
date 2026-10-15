package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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

func dismissServer(puts *[]string) *httptest.Server {
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

		_, _ = io.WriteString(w, `{"success":true,"errors":[],"result":{"count":1,"page":1,"per_page":100,"issues":[`+
			`{"id":"ab12","severity":"Low","issue_type":"t","issue_class":"c","subject":"example.com","dismissed":false}]}}`)
	}))
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

	// By id, undo.
	puts = nil
	out.Reset()
	require.NoError(t, run(ctx, []string{"dismiss", "-account", "a1", "-id", "x1,x2", "-undo", "-apply", "-format", "json"}, &out, env, now, srv.URL))
	assert.Equal(t, []string{
		`/accounts/a1/security-center/insights/x1/dismiss {"dismiss":false}`,
		`/accounts/a1/security-center/insights/x2/dismiss {"dismiss":false}`,
	}, puts)
	assert.NotContains(t, out.String(), "tok-secret")

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
