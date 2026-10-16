package token_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/edge/v4/cmd/internal/token"
)

func TestResolve(t *testing.T) {
	ctx := context.Background()
	getenv := func(k string) string {
		return map[string]string{"CLOUDFLARE_API_TOKEN": " from-env \n", "OTHER": "o"}[k]
	}

	tok, err := token.Resolve(ctx, "", "", getenv)
	require.NoError(t, err)
	assert.Equal(t, "from-env", tok)

	tok, err = token.Resolve(ctx, "OTHER", "", getenv)
	require.NoError(t, err)
	assert.Equal(t, "o", tok)

	tok, err = token.Resolve(ctx, "", "echo from-helper", getenv)
	require.NoError(t, err)
	assert.Equal(t, "from-helper", tok, "a helper wins over the environment")

	_, err = token.Resolve(ctx, "MISSING", "", getenv)
	require.ErrorContains(t, err, "MISSING")

	_, err = token.Resolve(ctx, "", "false", getenv)
	require.Error(t, err)
}
