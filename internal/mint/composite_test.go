package mint

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeMinter is a Minter whose Mint is a plain function, for composing
// CompositeMinter test scenarios without a real signer or HTTP server.
type fakeMinter struct {
	fn func(ctx context.Context, req Request) (Credential, error)
}

func (f fakeMinter) Mint(ctx context.Context, req Request) (Credential, error) {
	return f.fn(ctx, req)
}

func TestCompositeMinterPrefersLocal(t *testing.T) {
	apiCalled := false

	c := &CompositeMinter{
		Local: fakeMinter{fn: func(context.Context, Request) (Credential, error) {
			return Credential{AccessKeyID: "local"}, nil
		}},
		API: fakeMinter{fn: func(context.Context, Request) (Credential, error) {
			apiCalled = true

			return Credential{AccessKeyID: "api"}, nil
		}},
	}

	var observedPath Path
	var observedErr error
	c.Observe = func(path Path, err error) { observedPath, observedErr = path, err }

	cred, err := c.Mint(context.Background(), Request{})
	require.NoError(t, err)
	assert.Equal(t, "local", cred.AccessKeyID)
	assert.False(t, apiCalled, "local succeeded — api must never be called")
	assert.Equal(t, PathLocal, observedPath)
	assert.NoError(t, observedErr)
}

func TestCompositeMinterFallsBackToAPIOnLocalError(t *testing.T) {
	c := &CompositeMinter{
		Local: fakeMinter{fn: func(context.Context, Request) (Credential, error) {
			return Credential{}, errors.New("local signing broke")
		}},
		API: fakeMinter{fn: func(context.Context, Request) (Credential, error) {
			return Credential{AccessKeyID: "api"}, nil
		}},
	}

	var observedPath Path
	c.Observe = func(path Path, _ error) { observedPath = path }

	cred, err := c.Mint(context.Background(), Request{})
	require.NoError(t, err)
	assert.Equal(t, "api", cred.AccessKeyID)
	assert.Equal(t, PathAPI, observedPath, "the fallback path must be the one recorded, per drift detection")
}

func TestCompositeMinterFailsWhenBothPathsError(t *testing.T) {
	c := &CompositeMinter{
		Local: fakeMinter{fn: func(context.Context, Request) (Credential, error) {
			return Credential{}, errors.New("local broke")
		}},
		API: fakeMinter{fn: func(context.Context, Request) (Credential, error) {
			return Credential{}, errors.New("api broke too")
		}},
	}

	var observedErr error
	c.Observe = func(_ Path, err error) { observedErr = err }

	_, err := c.Mint(context.Background(), Request{})
	require.Error(t, err)
	assert.ErrorContains(t, err, "local broke")
	assert.ErrorContains(t, err, "api broke too")
	assert.Error(t, observedErr)
}

func TestCompositeMinterObserveIsOptional(t *testing.T) {
	c := &CompositeMinter{
		Local: fakeMinter{fn: func(context.Context, Request) (Credential, error) {
			return Credential{AccessKeyID: "local"}, nil
		}},
		API: fakeMinter{fn: func(context.Context, Request) (Credential, error) {
			return Credential{}, nil
		}},
	}

	assert.NotPanics(t, func() {
		_, err := c.Mint(context.Background(), Request{})
		require.NoError(t, err)
	})
}
