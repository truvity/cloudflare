package edge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// render is every resource Deploy registered, "type/name" to inputs, as JSON
// (encoding/json sorts the map keys, so the bytes are stable).
func render(t *testing.T, m *mocks) []byte {
	t.Helper()

	m.mu.Lock()
	defer m.mu.Unlock()

	out := make(map[string]any, len(m.resources))
	for _, r := range m.resources {
		out[r.typ+"/"+r.name] = r.inputs.Mappable()
	}

	b, err := json.MarshalIndent(out, "", "  ")
	require.NoError(t, err)

	return append(b, '\n')
}

// assertGolden compares got with testdata/<name>; UPDATE_GOLDEN=1 rewrites
// it.
func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()

	path := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") != "" {
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(path, got, 0o600))
	}

	want, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(want), string(got))
}

// TestSingleZoneDeployIsUnchanged pins what Deploy registers for tunnels
// whose names each lie in one zone, every resource name and every input,
// byte for byte. The golden was rendered before tunnels could serve names
// in several zones: a single-zone consumer must see no diff.
func TestSingleZoneDeployIsUnchanged(t *testing.T) {
	m, err := run(t, baseArgs((&sunk{}).sink))
	require.NoError(t, err)

	assertGolden(t, "single-zone.json", render(t, m))
}
