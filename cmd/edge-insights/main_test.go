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
