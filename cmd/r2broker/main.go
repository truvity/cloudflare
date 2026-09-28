package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/truvity/cloudflare/v2/internal/version"
)

// Exit codes. A script reading them should be able to tell "you typed
// this wrong" from "the broker refused you" from "something downstream
// broke" without parsing English — the same contract access-roster's
// accessctl keeps.
const (
	exitOK       = 0
	exitUsage    = 2
	exitRefused  = 3 // the broker (or the decision it made) refused the request
	exitUpstream = 4 // the issuer or Cloudflare could not be reached, or minting itself failed
)

// stdout and stderr are io.Writer variables (not *os.File) so tests can
// substitute a buffer — exactly like access-roster's own cmd/accessctl
// package-level stdout, generalized one step further since credentials'
// own tests need to assert on exactly what reached stdout.
var (
	stdout io.Writer = os.Stdout
	stderr io.Writer = os.Stderr
)

func main() {
	os.Exit(run(os.Args[1:]))
}

type usageError struct{ error }

func badUsage(format string, args ...any) error {
	return usageError{fmt.Errorf(format, args...)}
}

// refusedError marks a failure as the broker's own decision (an
// unauthenticated or unrecognized token, no matching grant, an ambiguous
// request), as opposed to an upstream problem a retry might fix.
type refusedError struct{ error }

func refused(err error) error {
	if err == nil {
		return nil
	}

	return refusedError{err}
}

func codeFor(err error) int {
	var usage usageError

	var ref refusedError

	switch {
	case errors.As(err, &usage):
		return exitUsage
	case errors.As(err, &ref):
		return exitRefused
	default:
		return exitUpstream
	}
}

func run(args []string) int {
	if len(args) == 0 {
		usage(stderr)

		return exitUsage
	}

	var err error

	switch args[0] {
	case "serve":
		err = serve(args[1:])
	case "credentials":
		err = credentials(args[1:])
	case "help", "-h", "--help":
		usage(stdout)

		return exitOK
	case "version", "-v", "--version":
		_, _ = fmt.Fprintln(stdout, version.Version)

		return exitOK
	default:
		err = badUsage("unknown command %q", args[0])
	}

	if err == nil {
		return exitOK
	}

	_, _ = fmt.Fprintln(stderr, "r2broker: "+err.Error())

	return codeFor(err)
}

func usage(w io.Writer) {
	_, _ = fmt.Fprint(w, `r2broker — R2 temporary-credentials broker (one binary, two modes)

Usage:
  r2broker serve --config <path> [--addr :8080]
  r2broker credentials (--config <path> | --service-url <url>) [flags]

Run "r2broker serve -h" or "r2broker credentials -h" for the flags each
command takes.
`)
}
