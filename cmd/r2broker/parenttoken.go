package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/truvity/cloudflare/v2/internal/config"
)

// resolveParentTokenValue reads the parent token's secret VALUE from
// wherever acct's config says it lives — exactly one of a file or an
// environment variable, per config.Account's own contract (never an
// inline value in the config file itself). Load already refuses a config
// with both or neither set, so this only has to read the one that is.
//
// A file's contents are trimmed of trailing whitespace: a value written
// with a plain `op read` (or any tool that appends a trailing newline)
// would otherwise sign every credential with a secret that has one
// character too many, and it would look nothing like a bad secret until
// verification failed against real R2.
func resolveParentTokenValue(acct config.Account) (string, error) {
	if acct.ParentTokenFile != "" {
		data, err := os.ReadFile(acct.ParentTokenFile)
		if err != nil {
			return "", fmt.Errorf("reading account.parentTokenFile %s: %w", acct.ParentTokenFile, err)
		}

		value := strings.TrimSpace(string(data))
		if value == "" {
			return "", fmt.Errorf("account.parentTokenFile %s is empty", acct.ParentTokenFile)
		}

		return value, nil
	}

	value := strings.TrimSpace(os.Getenv(acct.ParentTokenEnv))
	if value == "" {
		return "", fmt.Errorf("account.parentTokenEnv %s is unset or empty", acct.ParentTokenEnv)
	}

	return value, nil
}
