package cfnames_test

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/cloudflare/v2/pkg/cfnames"
)

// TestNoNonStdlibImports guards this package's whole reason to exist: a
// caller must be able to import cfnames alone, with no Pulumi or
// Cloudflare SDK riding along. `go list -deps` lists every package this
// one imports, transitively; any import path whose first path segment
// contains a "." is a module outside the standard library (the standard
// library's own packages, and this test binary's test-only synthetic
// packages, never do).
func TestNoNonStdlibImports(t *testing.T) {
	const pkg = "github.com/truvity/cloudflare/v2/pkg/cfnames"

	out, err := exec.Command("go", "list", "-deps", pkg).Output()
	require.NoError(t, err, "go list -deps")

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" || line == pkg {
			continue
		}

		root, _, _ := strings.Cut(line, "/")
		assert.NotContains(t, root, ".", "pkg/cfnames must depend on the standard library only, found %q", line)
	}
}

func TestJurisdictions(t *testing.T) {
	got := cfnames.Jurisdictions()
	assert.ElementsMatch(t, []string{"", "default", "eu", "fedramp", "us"}, got)

	// The returned slice is a copy: mutating it must not affect the next
	// call's result.
	got[0] = "mutated"
	assert.NotContains(t, cfnames.Jurisdictions(), "mutated")
}

func TestValidJurisdiction(t *testing.T) {
	for _, j := range []string{"", "default", "eu", "fedramp", "us"} {
		assert.True(t, cfnames.ValidJurisdiction(j), "%q should be valid", j)
	}

	for _, j := range []string{"EU", "eu ", " eu", "global", "uk"} {
		assert.False(t, cfnames.ValidJurisdiction(j), "%q should be invalid", j)
	}
}

func TestValidBucketName(t *testing.T) {
	valid := []string{"abc", "example-bucket", "a1-b2-c3", strings.Repeat("a", 63)}
	for _, name := range valid {
		assert.True(t, cfnames.ValidBucketName(name), "%q should be valid", name)
	}

	invalid := []string{
		"",
		"ab",                    // too short
		strings.Repeat("a", 64), // too long
		"-abc",                  // leading hyphen
		"abc-",                  // trailing hyphen
		"Abc",                   // uppercase
		"abc_def",               // underscore
		"abc.def",               // dot
		"abc def",               // space
	}
	for _, name := range invalid {
		assert.False(t, cfnames.ValidBucketName(name), "%q should be invalid", name)
	}
}
