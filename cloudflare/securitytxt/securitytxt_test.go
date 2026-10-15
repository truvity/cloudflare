package securitytxt_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/edge/v3/cloudflare/config"
	"github.com/truvity/edge/v3/cloudflare/securitytxt"
)

var now = time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)

const zoneID = "1111aaaa2222bbbb3333cccc4444dddd"

func TestCheckExpires(t *testing.T) {
	cases := []struct {
		name, in string
		warn     bool
		err      string
	}{
		{"empty", "", false, "required"},
		{"garbage", "tomorrow", false, "RFC 3339"},
		{"past", "2026-10-14T00:00:00Z", false, "passed"},
		{"too far", "2027-12-01T00:00:00Z", false, "more than a year"},
		{"soon", "2026-11-20T00:00:00Z", true, ""},
		{"fine", "2027-06-01T00:00:00Z", false, ""},
		{"a year to the day", "2027-10-15T00:00:00Z", false, ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w, err := securitytxt.CheckExpires(c.in, now)
			if c.err != "" {
				require.ErrorContains(t, err, c.err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, c.warn, w != "")
		})
	}
}

type fake struct {
	mu     sync.Mutex
	doc    string
	puts   []securitytxt.Doc
	tokens []string
}

func (f *fake) server(t *testing.T) *securitytxt.Client {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()

		f.tokens = append(f.tokens, r.Header.Get("Authorization"))
		assert.Equal(t, "/zones/"+zoneID+"/security-center/securitytxt", r.URL.Path)

		switch r.Method {
		case http.MethodGet:
			_, _ = io.WriteString(w, `{"success":true,"errors":[],"result":`+f.doc+`}`)
		case http.MethodPut:
			var d securitytxt.Doc
			assert.NoError(t, json.NewDecoder(r.Body).Decode(&d))
			f.puts = append(f.puts, d)
			_, _ = io.WriteString(w, `{"success":true,"errors":[],"result":{}}`)
		}
	}))
	t.Cleanup(srv.Close)

	c := securitytxt.NewClient("tok-secret")
	c.API.Base = srv.URL

	return c
}

var want = securitytxt.Doc{Enabled: true, Contact: []string{"mailto:security@example.com"}, Expires: "2027-06-01T00:00:00Z"}

func TestPlanThenApply(t *testing.T) {
	f := &fake{doc: `""`}
	c := f.server(t)
	targets := []securitytxt.Target{{Zone: "example.com", ZoneID: zoneID, Want: want}}

	changes, err := c.Plan(context.Background(), targets, now)
	require.NoError(t, err)
	require.Len(t, changes, 1)
	assert.True(t, changes[0].Differs)
	assert.Empty(t, f.puts, "a plan writes nothing")
	assert.Len(t, securitytxt.Diff(changes[0].Live, changes[0].Want), 3)
	assert.Equal(t, "Bearer tok-secret", f.tokens[0])

	require.NoError(t, c.Apply(context.Background(), changes))
	require.Len(t, f.puts, 1)
	assert.Equal(t, want, f.puts[0])
	assert.True(t, changes[0].Applied)
}

func TestUnchangedIsNotWritten(t *testing.T) {
	// The API may spell the same instant differently.
	f := &fake{doc: `{"enabled":true,"contact":["mailto:security@example.com"],"expires":"2027-06-01T02:00:00+02:00"}`}
	c := f.server(t)

	changes, err := c.Plan(context.Background(), []securitytxt.Target{{Zone: "example.com", ZoneID: zoneID, Want: want}}, now)
	require.NoError(t, err)
	assert.False(t, changes[0].Differs)
	require.NoError(t, c.Apply(context.Background(), changes))
	assert.Empty(t, f.puts)
}

func TestExpiredReadsNothing(t *testing.T) {
	f := &fake{doc: `""`}
	c := f.server(t)
	bad := want
	bad.Expires = "2026-01-01T00:00:00Z"

	_, err := c.Plan(context.Background(), []securitytxt.Target{{Zone: "example.com", ZoneID: zoneID, Want: bad}}, now)
	require.ErrorContains(t, err, "example.com")
	assert.Empty(t, f.tokens)
}

func TestErrorNeverCarriesTheToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":9109,"message":"bad token tok-secret"}]}`)
	}))
	defer srv.Close()

	c := securitytxt.NewClient("tok-secret")
	c.API.Base = srv.URL

	_, err := c.Get(context.Background(), zoneID)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "tok-secret")
	assert.Contains(t, err.Error(), "403")
}

func TestRefusesAZoneIDThatIsAPath(t *testing.T) {
	_, err := securitytxt.NewClient("t").Get(context.Background(), "../x")
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "not an id"))
}

func TestTargetsIncludeASecurityTxtOnlyZone(t *testing.T) {
	cfg, err := config.Parse([]byte(`accounts:
  main: {account_id: a1}
zones:
  full.example.com:
    account: main
    zone_id: z1
    ssl_mode: full
    security_txt: {contact: ["mailto:security@example.com"], expires: "2027-01-01T00:00:00Z"}
  held.example.net:
    account: main
    zone_id: z2
    manage: security_txt
    security_txt: {contact: ["https://example.com/contact"], expires: "2027-02-01T00:00:00Z"}
fleets:
  internal: {service: gateway-internal, namespace: envoy-gateway-system}
`))
	require.NoError(t, err)

	got := securitytxt.Targets(cfg, "", "")
	require.Len(t, got, 2)
	assert.Equal(t, "held.example.net", got[1].Zone)
	assert.Equal(t, "z2", got[1].ZoneID)
	assert.Equal(t, []string{"https://example.com/contact"}, got[1].Want.Contact)

	only := securitytxt.Targets(cfg, "held.example.net", "main")
	require.Len(t, only, 1)
}
