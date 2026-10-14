package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fixture = "../../cloudflare/config/testdata/cloudflare.yaml"

func TestReportThenApply(t *testing.T) {
	var puts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer tok-secret", r.Header.Get("Authorization"))

		if r.Method == http.MethodPut {
			puts.Add(1)
		}

		_, _ = io.WriteString(w, `{"success":true,"errors":[],"result":""}`)
	}))
	defer srv.Close()

	env := func(k string) string {
		if k == "CLOUDFLARE_API_TOKEN" {
			return "tok-secret"
		}

		return ""
	}
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)

	var out bytes.Buffer

	require.NoError(t, runWith(context.Background(), []string{"-config", fixture}, &out, env, now, srv.URL))
	assert.Contains(t, out.String(), "example.com: would change")
	assert.Contains(t, out.String(), "example.org: would change")
	assert.Zero(t, puts.Load())
	assert.NotContains(t, out.String(), "tok-secret")

	out.Reset()
	require.NoError(t, runWith(context.Background(), []string{"-config", fixture, "-zone", "example.org", "-apply"}, &out, env, now, srv.URL))
	assert.Equal(t, int32(1), puts.Load())
	assert.Contains(t, out.String(), "example.org: changed")
}

func TestNoTokenIsRefused(t *testing.T) {
	err := run(context.Background(), []string{"-config", fixture}, io.Discard, func(string) string { return "" }, time.Now())
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "no API token"))
}
