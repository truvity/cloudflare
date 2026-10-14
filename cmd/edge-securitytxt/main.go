// Command edge-securitytxt plans and applies the security_txt blocks of a
// cloudflare config file: each zone's /.well-known/security.txt (RFC 9116)
// through Cloudflare's Security Center API.
//
// Without -apply it only reads and prints the difference between the live
// document and the declared one. With -apply it writes the zones that differ
// and nothing else. It refuses an `expires` that has passed or lies more than
// a year ahead, and warns inside 60 days.
//
// The token comes from the environment variable named by -token-env
// (CLOUDFLARE_API_TOKEN by default) or from the output of -token-cmd. Writing
// needs Zone Settings Write: the zone settings of the preset kind `edge`.
//
//	edge-securitytxt -config cloudflare.yaml
//	edge-securitytxt -config cloudflare.yaml -zone example.com -apply
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/truvity/edge/v3/cloudflare/config"
	"github.com/truvity/edge/v3/cloudflare/securitytxt"
	"github.com/truvity/edge/v3/cmd/internal/token"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Getenv, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "edge-securitytxt:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer, getenv func(string) string, now time.Time) error {
	return runWith(ctx, args, out, getenv, now, "")
}

// runWith is run with the API root overridden, for tests.
func runWith(ctx context.Context, args []string, out io.Writer, getenv func(string) string, now time.Time, base string) error {
	fs := flag.NewFlagSet("edge-securitytxt", flag.ContinueOnError)
	configPath := fs.String("config", "cloudflare.yaml", "the cloudflare config file")
	zone := fs.String("zone", "", "only this zone name (default: every zone with a security_txt block)")
	acct := fs.String("account", "", "only the zones of this account name")
	apply := fs.Bool("apply", false, "write the zones whose live security.txt differs (default: report only)")
	format := fs.String("format", "text", "text or json")
	tokenEnv := fs.String("token-env", token.DefaultEnv, "environment variable holding the API token")
	tokenCmd := fs.String("token-cmd", "", "credential helper: a command (no shell) whose output is the API token")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *format != "text" && *format != "json" {
		return fmt.Errorf("-format %q: want text or json", *format)
	}

	data, err := os.ReadFile(*configPath)
	if err != nil {
		return err
	}

	// Parse, not Load: Load derives the tunnels from the edge catalog, which
	// this command neither has nor needs. Parse holds every zone, and so its
	// security_txt block, to the same validation.
	cfg, err := config.Parse(data)
	if err != nil {
		return err
	}

	targets := securitytxt.Targets(cfg, *zone, *acct)
	if len(targets) == 0 {
		return fmt.Errorf("no zone declares security_txt (zone %q, account %q)", *zone, *acct)
	}

	tok, err := token.Resolve(ctx, *tokenEnv, *tokenCmd, getenv)
	if err != nil {
		return err
	}

	c := securitytxt.NewClient(tok)
	c.API.Base = base

	changes, err := c.Plan(ctx, targets, now)
	if err != nil {
		return err
	}

	if *apply {
		if err := c.Apply(ctx, changes); err != nil {
			return err
		}
	}

	if *format == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")

		return enc.Encode(changes)
	}

	printChanges(out, changes, *apply)

	return nil
}

func printChanges(w io.Writer, changes []securitytxt.Change, apply bool) {
	for k := range changes {
		ch := &changes[k]
		for _, warn := range ch.Warnings {
			_, _ = fmt.Fprintf(w, "%s: warning: %s\n", ch.Zone, warn)
		}

		switch {
		case !ch.Differs:
			_, _ = fmt.Fprintf(w, "%s: unchanged\n", ch.Zone)
		default:
			verb := "would change"
			if apply {
				verb = "changed"
			}

			_, _ = fmt.Fprintf(w, "%s: %s\n", ch.Zone, verb)

			for _, line := range securitytxt.Diff(ch.Live, ch.Want) {
				_, _ = fmt.Fprintf(w, "    %s\n", line)
			}
		}
	}
}
