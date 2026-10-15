package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPerCompanyStackNames(t *testing.T) {
	assert.Equal(t, "cloudflare-acme-zone", StackZone("acme"))
	assert.Equal(t, "cloudflare-acme-services", StackServices("acme"))
	assert.Equal(t, "cloudflare-acme-sts", StackSTS("acme"))
	assert.Equal(t, "cloudflare-acme-zone", StackName(StackKindZone, "acme"))
	assert.Equal(t, "cloudflare-acme-services", StackName("services", "acme"))
	assert.Equal(t, "cloudflare-umbrella-sts", StackName(StackKindSTS, "umbrella"))
}

// The per-account helper keeps its shape: kind first, account last.
func TestPerAccountStackNameUnchanged(t *testing.T) {
	c := &Config{Accounts: map[string]Account{"acme": {}, "old": {LegacyNames: true}}}

	assert.Equal(t, "cloudflare-edge-acme", c.StackName(StackEdge, "acme"))
	assert.Equal(t, "cloudflare-edge", c.StackName(StackEdge, "old"))
}
