// Command edge-insights reads, and only reads, what shows a WAF rollout is
// safe and Security Center warnings are clearing.
//
//	edge-insights list   -account ID | -zone ID [-severity S] [-type T] [-dismissed no|yes|any]
//	edge-insights dismiss -account ID | -zone ID (-id ID ... | [-class C] [-type T] [-severity S]) [-apply] [-undo]
//	edge-insights events -zone ID [-since 24h | -from T -to T] [-host H] [-rule R] [-action A] [-source S]
//
// list is the Security Center insights of an account or a zone. events is the
// Security Events (firewall events) of a zone summed per host, rule and
// action, from the GraphQL Analytics API. Both only read. dismiss archives
// insights, by id or by filter; it is a dry run that prints what it would
// dismiss unless -apply is given, and -undo brings dismissed insights back.
// Every command prints a table, or JSON with -format json.
//
// The token comes from the environment variable named by -token-env
// (CLOUDFLARE_API_TOKEN by default) or from the output of -token-cmd. The
// preset kind `insights` is enough for list and events; dismiss needs
// `insights-admin`.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/truvity/edge/v3/cloudflare/insights"
	"github.com/truvity/edge/v3/cmd/internal/token"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Getenv, time.Now(), ""); err != nil {
		fmt.Fprintln(os.Stderr, "edge-insights:", err)
		os.Exit(1)
	}
}

type list []string

func (l *list) String() string { return strings.Join(*l, ",") }

// Set takes a value or a comma-separated list; the flag may repeat.
func (l *list) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*l = append(*l, p)
		}
	}

	return nil
}

func run(ctx context.Context, args []string, out io.Writer, getenv func(string) string, now time.Time, base string) error {
	if len(args) == 0 || (args[0] != "list" && args[0] != "events" && args[0] != "dismiss") {
		return errors.New("usage: edge-insights list|events|dismiss [flags]")
	}

	cmd := args[0]
	fs := flag.NewFlagSet("edge-insights "+cmd, flag.ContinueOnError)
	format := fs.String("format", "table", "table or json")
	tokenEnv := fs.String("token-env", token.DefaultEnv, "environment variable holding the API token")
	tokenCmd := fs.String("token-cmd", "", "credential helper: a command (no shell) whose output is the API token")
	zone := fs.String("zone", "", "zone id")
	account := fs.String("account", "", "account id (list only)")

	var severity, kinds, classes list

	dismissed := fs.String("dismissed", "no", "list: no, yes or any")
	fs.Var(&severity, "severity", "list: Low, Moderate, Critical (repeat or comma-separate)")
	fs.Var(&kinds, "type", "list: issue type (repeat or comma-separate)")
	fs.Var(&classes, "class", "list: issue class (repeat or comma-separate)")

	var ids list

	fs.Var(&ids, "id", "dismiss: insight id (repeat or comma-separate); or use -class, -type and -severity")

	apply := fs.Bool("apply", false, "dismiss: do it; without it, print what would be dismissed")
	undo := fs.Bool("undo", false, "dismiss: bring dismissed insights back instead")

	since := fs.Duration("since", 24*time.Hour, "events: the window ends now and starts this long ago")
	from := fs.String("from", "", "events: window start, RFC 3339 (with -to; replaces -since)")
	to := fs.String("to", "", "events: window end, RFC 3339")
	host := fs.String("host", "", "events: only this host")
	rule := fs.String("rule", "", "events: only this rule id")
	action := fs.String("action", "", "events: only this action")
	source := fs.String("source", "", "events: only this source")
	limit := fs.Int("limit", 0, "events: most groups asked for (default and maximum 10000)")

	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	if *format != "table" && *format != "json" {
		return fmt.Errorf("-format %q: want table or json", *format)
	}

	tok, err := token.Resolve(ctx, *tokenEnv, *tokenCmd, getenv)
	if err != nil {
		return err
	}

	c := insights.NewClient(tok)
	c.API.Base = base

	if cmd == "dismiss" {
		return runDismiss(ctx, c, out, *format, *account, *zone, ids,
			insights.Filter{Severity: severity, Type: kinds, Class: classes}, *apply, *undo)
	}

	if cmd == "list" {
		var d insights.Dismissed

		switch *dismissed {
		case "no":
			d = insights.Active
		case "yes":
			d = insights.OnlyDismissed
		case "any":
			d = insights.AnyState
		default:
			return fmt.Errorf("-dismissed %q: want no, yes or any", *dismissed)
		}

		items, err := c.List(ctx, insights.Scope{AccountID: *account, ZoneID: *zone},
			insights.Filter{Severity: severity, Type: kinds, Class: classes, Dismissed: d})
		if err != nil {
			return err
		}

		if *format == "json" {
			return writeJSON(out, items)
		}

		return listTable(out, items)
	}

	w := insights.Window{From: now.Add(-*since), To: now}

	if *from != "" || *to != "" {
		if w.From, err = time.Parse(time.RFC3339, *from); err != nil {
			return fmt.Errorf("-from %q: want RFC 3339", *from)
		}

		if w.To, err = time.Parse(time.RFC3339, *to); err != nil {
			return fmt.Errorf("-to %q: want RFC 3339", *to)
		}
	}

	sum, err := c.Events(ctx, insights.EventsQuery{
		ZoneID: *zone, Window: w, Host: *host, RuleID: *rule, Action: *action, Source: *source, Limit: *limit,
	})
	if err != nil {
		return err
	}

	if *format == "json" {
		return writeJSON(out, sum)
	}

	return eventsTable(out, sum)
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	return enc.Encode(v)
}

func listTable(w io.Writer, items []insights.Insight) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SEVERITY\tTYPE\tCLASS\tSUBJECT\tDISMISSED\tSINCE")

	for k := range items {
		i := &items[k]
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%t\t%s\n", i.Severity, i.IssueType, i.IssueClass, i.Subject, i.Dismissed, i.Timestamp)
	}

	if err := tw.Flush(); err != nil {
		return err
	}

	_, err := fmt.Fprintf(w, "%d insight(s)\n", len(items))

	return err
}

func eventsTable(w io.Writer, s *insights.Summary) error {
	_, _ = fmt.Fprintf(w, "zone %s, %s to %s\n", s.ZoneID, s.From.Format(time.RFC3339), s.To.Format(time.RFC3339))

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "HOST\tRULE\tSOURCE\tACTION\tCOUNT\tDESCRIPTION")

	for _, h := range s.Hosts {
		_, _ = fmt.Fprintf(tw, "%s\t\t\t\t%d\t(total; %d blocking or challenged)\n", h.Host, h.Total, h.Blocking)

		for _, r := range h.Rows {
			_, _ = fmt.Fprintf(tw, "\t%s\t%s\t%s\t%d\t%s\n", r.RuleID, r.Source, r.Action, r.Count, r.Description)
		}
	}

	if err := tw.Flush(); err != nil {
		return err
	}

	if s.Truncated {
		_, _ = fmt.Fprintln(w, "note: the row limit was reached; narrow the window or filter, the counts are a lower bound")
	}

	return nil
}

// runDismiss dismisses (or, with undo, restores) the insights named by id or
// matched by filter. Without apply it only prints what it would change.
func runDismiss(ctx context.Context, c *insights.Client, out io.Writer, format, account, zone string, ids list,
	f insights.Filter, apply, undo bool) error {
	byFilter := len(f.Severity)+len(f.Type)+len(f.Class) > 0
	if (len(ids) > 0) == byFilter {
		return errors.New("dismiss: give -id, or at least one of -class, -type and -severity, not both and not neither")
	}

	scope := insights.Scope{AccountID: account, ZoneID: zone}
	verb := "dismiss"

	if undo {
		verb = "restore"
	}

	var done []insights.Insight

	if len(ids) > 0 {
		for _, id := range ids {
			if err := insights.ValidID(id); err != nil {
				return err
			}
		}

		// Look the ids up first, so the table shows what the list shows and
		// an id that is not in this scope is refused before anything is written.
		listed, err := c.List(ctx, scope, insights.Filter{Dismissed: insights.AnyState})
		if err != nil {
			return err
		}

		byID := make(map[string]insights.Insight, len(listed))
		for k := range listed {
			byID[listed[k].ID] = listed[k]
		}

		for _, id := range ids {
			i, ok := byID[id]
			if !ok {
				return fmt.Errorf("insight %s: not listed in this account or zone", id)
			}

			done = append(done, i)
		}

		if apply {
			for k := range done {
				if err := c.Dismiss(ctx, scope, done[k].ID, !undo); err != nil {
					return fmt.Errorf("insight %s: %w", done[k].ID, err)
				}
			}
		}
	} else {
		c.Apply, c.Undo = apply, undo

		var err error
		if done, err = c.DismissMatching(ctx, scope, f, ""); err != nil {
			return err
		}
	}

	if format == "json" {
		return writeJSON(out, struct {
			Applied  bool               `json:"applied"`
			Undo     bool               `json:"undo"`
			Insights []insights.Insight `json:"insights"`
		}{apply, undo, nonNil(done)})
	}

	if len(done) == 0 {
		_, err := fmt.Fprintln(out, "no insight matches; nothing to "+verb)

		return err
	}

	if err := listTable(out, done); err != nil {
		return err
	}

	if apply {
		_, err := fmt.Fprintf(out, "%sed %d insight(s)\n", strings.TrimSuffix(verb, "e"), len(done))

		return err
	}

	_, err := fmt.Fprintf(out, "dry run: would %s %d insight(s); add -apply to do it\n", verb, len(done))

	return err
}

func nonNil(v []insights.Insight) []insights.Insight {
	if v == nil {
		return []insights.Insight{}
	}

	return v
}
