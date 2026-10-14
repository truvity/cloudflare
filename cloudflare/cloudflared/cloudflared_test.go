package cloudflared_test

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/edge/v3/cloudflare/cloudflared"
)

// TestChartImageIsThePin keeps charts/cloudflared/values.yaml on the Go pin.
// The chart references the image by tag; a digest, if one is ever added to
// values.yaml, must be this package's ImageDigest.
func TestChartImageIsThePin(t *testing.T) {
	raw, err := os.ReadFile("../../charts/cloudflared/values.yaml")
	require.NoError(t, err)
	values := string(raw)

	repo := regexp.MustCompile(`(?m)^  repository: (\S+)$`).FindStringSubmatch(values)
	require.NotNil(t, repo, "image.repository not found")
	assert.Equal(t, cloudflared.ImageRepository, repo[1])

	tag := regexp.MustCompile(`(?m)^  tag: "([^"]+)"`).FindStringSubmatch(values)
	require.NotNil(t, tag, "image.tag not found")
	assert.Equal(t, cloudflared.Version, tag[1], "run hack/cloudflared-pin.sh %s", cloudflared.Version)

	if digest := regexp.MustCompile(`(?m)^  digest: "?([^"\s]+)"?`).FindStringSubmatch(values); digest != nil {
		assert.Equal(t, cloudflared.ImageDigest, digest[1])
	}
}

func TestPinShape(t *testing.T) {
	hex := regexp.MustCompile(`^[0-9a-f]{64}$`)
	assert.Regexp(t, `^\d{4}\.\d+\.\d+$`, cloudflared.Version)
	assert.Regexp(t, hex, cloudflared.SHA256AMD64)
	assert.Regexp(t, hex, cloudflared.SHA256ARM64)
	assert.NotEqual(t, cloudflared.SHA256AMD64, cloudflared.SHA256ARM64)
	assert.Regexp(t, `^sha256:[0-9a-f]{64}$`, cloudflared.ImageDigest)

	got, ok := cloudflared.BinarySHA256("arm64")
	assert.True(t, ok)
	assert.Equal(t, cloudflared.SHA256ARM64, got)
	_, ok = cloudflared.BinarySHA256("386")
	assert.False(t, ok)
	assert.Equal(t, "https://github.com/cloudflare/cloudflared/releases/download/"+cloudflared.Version+"/cloudflared-linux-amd64",
		cloudflared.BinaryURL("amd64"))
}

func TestNoNonStdlibImports(t *testing.T) {
	const pkg = "github.com/truvity/edge/v3/cloudflare/cloudflared"

	out, err := exec.Command("go", "list", "-deps", pkg).Output()
	require.NoError(t, err, "go list -deps")

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" || line == pkg {
			continue
		}
		root, _, _ := strings.Cut(line, "/")
		assert.NotContains(t, root, ".", "cloudflare/cloudflared must depend on the standard library only, found %q", line)
	}
}
