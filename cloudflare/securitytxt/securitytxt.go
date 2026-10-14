// Package securitytxt plans and applies a zone's security.txt (RFC 9116)
// through Cloudflare's Security Center API:
//
//	GET|PUT /zones/{zone_id}/security-center/securitytxt
//
// Cloudflare serves the file at /.well-known/security.txt on every proxied
// name of the zone. The Pulumi Cloudflare provider has no resource for it, so
// this package is the tool that applies the `security_txt` block of a
// cloudflare/config zone.
//
// Plan only reads: it compares the live document with the declared one and
// returns the difference. Apply writes the zones whose document differs and
// nothing else. The credential needs Zone Settings Write (the `edge` preset
// kind has it); reading needs only read access to the zone.
package securitytxt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/truvity/edge/v3/cloudflare/config"
	"github.com/truvity/edge/v3/cloudflare/internal/cfapi"
)

const (
	// MaxAhead is how far ahead Expires may lie: RFC 9116 section 2.5.5
	// recommends less than a year, and a day of slack lets a date set to
	// "today plus one year" (a leap year included) be applied the day it is
	// written.
	MaxAhead = 366 * 24 * time.Hour
	// WarnWithin is the horizon inside which Expires draws a warning: renew
	// the date before the file lapses.
	WarnWithin = 60 * 24 * time.Hour
)

// Doc is the endpoint's body, the fields a config decides.
type Doc struct {
	Enabled            bool     `json:"enabled"`
	Contact            []string `json:"contact,omitempty"`
	Expires            string   `json:"expires,omitempty"`
	PreferredLanguages string   `json:"preferred_languages,omitempty"`
}

// Target is one zone to bring to its declared security.txt.
type Target struct {
	Zone   string `json:"zone"`
	ZoneID string `json:"zone_id"`
	Want   Doc    `json:"want"`
}

// Change is the plan for one zone.
type Change struct {
	Zone   string `json:"zone"`
	ZoneID string `json:"zone_id"`
	Live   Doc    `json:"live"`
	Want   Doc    `json:"want"`
	// Differs is true when Apply would write this zone.
	Differs bool `json:"differs"`
	// Warnings are advisories that do not stop an apply.
	Warnings []string `json:"warnings,omitempty"`
	// Applied is true once Apply has written the zone.
	Applied bool `json:"applied,omitempty"`
}

// FromConfig is the document a zone's security_txt block declares.
func FromConfig(c *config.SecurityTxtCfg) Doc {
	return Doc{
		Enabled:            true,
		Contact:            slices.Clone(c.Contact),
		Expires:            c.Expires,
		PreferredLanguages: c.PreferredLanguages,
	}
}

// Targets is every zone of cfg with a security_txt block and a zone id,
// sorted by zone. only restricts it to one zone name; account to one account
// name; both empty means all.
func Targets(cfg *config.Config, only, account string) []Target {
	names := make([]string, 0, len(cfg.Zones))
	for name := range cfg.Zones {
		names = append(names, name)
	}

	sort.Strings(names)

	var out []Target

	for _, name := range names {
		z := cfg.Zones[name]
		if z.SecurityTxt == nil || z.ZoneID == "" {
			continue
		}

		if (only != "" && only != name) || (account != "" && account != z.Account) {
			continue
		}

		out = append(out, Target{Zone: name, ZoneID: z.ZoneID, Want: FromConfig(z.SecurityTxt)})
	}

	return out
}

// CheckExpires holds an Expires value to RFC 9116: required, RFC 3339, in the
// future and less than a year ahead. It returns a warning when the date lies
// within WarnWithin.
func CheckExpires(expires string, now time.Time) (warning string, err error) {
	if expires == "" {
		return "", errors.New("expires is required (RFC 9116 2.5.5)")
	}

	exp, err := time.Parse(time.RFC3339, expires)
	if err != nil {
		return "", fmt.Errorf("expires %q is not an RFC 3339 timestamp", expires)
	}

	switch d := exp.Sub(now); {
	case d <= 0:
		return "", fmt.Errorf("expires %s has passed; renew it", expires)
	case d > MaxAhead:
		return "", fmt.Errorf("expires %s is more than a year ahead (RFC 9116 2.5.5)", expires)
	case d <= WarnWithin:
		return fmt.Sprintf("expires %s is %d days away; renew it", expires, int(d.Hours()/24)), nil
	}

	return "", nil
}

// Same compares what a config decides; Expires as instants, since the API may
// spell the same time differently.
func Same(live, want Doc) bool {
	if live.Enabled != want.Enabled || !slices.Equal(live.Contact, want.Contact) ||
		live.PreferredLanguages != want.PreferredLanguages {
		return false
	}

	a, errA := time.Parse(time.RFC3339, live.Expires)
	b, errB := time.Parse(time.RFC3339, want.Expires)

	return errA == nil && errB == nil && a.Equal(b)
}

// Describe is a one-line form of a document.
func Describe(d Doc) string {
	if !d.Enabled && len(d.Contact) == 0 && d.Expires == "" {
		return "none"
	}

	return fmt.Sprintf("enabled=%t contact=[%s] expires=%s preferred_languages=%q",
		d.Enabled, strings.Join(d.Contact, " "), d.Expires, d.PreferredLanguages)
}

// Diff is the lines that differ between live and want, one per field, empty
// when they are the same.
func Diff(live, want Doc) []string {
	var out []string

	if live.Enabled != want.Enabled {
		out = append(out, fmt.Sprintf("enabled: %t -> %t", live.Enabled, want.Enabled))
	}

	if !slices.Equal(live.Contact, want.Contact) {
		out = append(out, fmt.Sprintf("contact: [%s] -> [%s]", strings.Join(live.Contact, " "), strings.Join(want.Contact, " ")))
	}

	a, errA := time.Parse(time.RFC3339, live.Expires)
	b, errB := time.Parse(time.RFC3339, want.Expires)

	if errA != nil || errB != nil || !a.Equal(b) {
		out = append(out, fmt.Sprintf("expires: %q -> %q", live.Expires, want.Expires))
	}

	if live.PreferredLanguages != want.PreferredLanguages {
		out = append(out, fmt.Sprintf("preferred_languages: %q -> %q", live.PreferredLanguages, want.PreferredLanguages))
	}

	return out
}

// Client reads and writes security.txt documents with one token.
type Client struct {
	API cfapi.Client
}

// NewClient is a Client with the given token against the public API.
func NewClient(token string) *Client { return &Client{API: cfapi.Client{Token: token}} }

func endpoint(zoneID string) (string, error) {
	if zoneID == "" || strings.ContainsAny(zoneID, "/?#") {
		return "", fmt.Errorf("zone id %q is not an id", zoneID)
	}

	return "/zones/" + url.PathEscape(zoneID) + "/security-center/securitytxt", nil
}

// Get reads a zone's live document. A zone with none reads back as the zero
// Doc.
func (c *Client) Get(ctx context.Context, zoneID string) (Doc, error) {
	var out Doc

	path, err := endpoint(zoneID)
	if err != nil {
		return out, err
	}

	env, err := c.API.Do(ctx, "GET", path, nil, nil)
	if err != nil {
		return out, err
	}

	// An unset security.txt reads back as "result": "" (or null).
	if len(env.Result) == 0 || env.Result[0] != '{' {
		return out, nil
	}

	if err := json.Unmarshal(env.Result, &out); err != nil {
		return out, fmt.Errorf("decode result: %w", err)
	}

	return out, nil
}

// Put writes a zone's document.
func (c *Client) Put(ctx context.Context, zoneID string, d Doc) error {
	path, err := endpoint(zoneID)
	if err != nil {
		return err
	}

	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}

	_, err = c.API.Do(ctx, "PUT", path, nil, raw)

	return err
}

// Plan checks every target's expiry (nothing is read until all pass), then
// reads each zone and returns the changes in target order. It writes nothing.
func (c *Client) Plan(ctx context.Context, targets []Target, now time.Time) ([]Change, error) {
	changes := make([]Change, 0, len(targets))

	for _, t := range targets {
		warn, err := CheckExpires(t.Want.Expires, now)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", t.Zone, err)
		}

		ch := Change{Zone: t.Zone, ZoneID: t.ZoneID, Want: t.Want}
		if warn != "" {
			ch.Warnings = append(ch.Warnings, warn)
		}

		changes = append(changes, ch)
	}

	for i := range changes {
		live, err := c.Get(ctx, changes[i].ZoneID)
		if err != nil {
			return nil, fmt.Errorf("%s: read: %w", changes[i].Zone, err)
		}

		changes[i].Live = live
		changes[i].Differs = !Same(live, changes[i].Want)
	}

	return changes, nil
}

// Apply writes every change that differs and marks it Applied. It stops at
// the first failure; the changes written before it stay marked.
func (c *Client) Apply(ctx context.Context, changes []Change) error {
	for i := range changes {
		if !changes[i].Differs {
			continue
		}

		if err := c.Put(ctx, changes[i].ZoneID, changes[i].Want); err != nil {
			return fmt.Errorf("%s: write: %w", changes[i].Zone, err)
		}

		changes[i].Applied = true
	}

	return nil
}
