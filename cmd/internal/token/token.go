// Package token resolves the API token of the edge commands: from an
// environment variable, or from a credential helper command whose standard
// output is the token. The token is never printed.
package token

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// DefaultEnv is the variable read when no other is named.
const DefaultEnv = "CLOUDFLARE_API_TOKEN"

// Resolve returns the token. A non-empty helper (a program and its arguments,
// split on white space, run without a shell) wins over the environment; its
// standard output, trimmed, is the token. Otherwise envName (DefaultEnv when
// empty) is read with getenv.
func Resolve(ctx context.Context, envName, helper string, getenv func(string) string) (string, error) {
	if fields := strings.Fields(helper); len(fields) > 0 {
		var out bytes.Buffer

		cmd := exec.CommandContext(ctx, fields[0], fields[1:]...) //nolint:gosec // the operator names the helper
		cmd.Stdout = &out
		cmd.Stderr = os.Stderr // prompts and notices; the token is on stdout

		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("token helper %q failed: %w", fields[0], err)
		}

		tok := strings.TrimSpace(out.String())
		if tok == "" {
			return "", fmt.Errorf("token helper %q printed no token", fields[0])
		}

		return tok, nil
	}

	if envName == "" {
		envName = DefaultEnv
	}

	tok := strings.TrimSpace(getenv(envName))
	if tok == "" {
		return "", errors.New("no API token: set " + envName + " or pass -token-cmd")
	}

	return tok, nil
}
