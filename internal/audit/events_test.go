package audit_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/truvity/audit/emit"
	auditv1 "github.com/truvity/audit/gen/audit/v1"
	"github.com/truvity/audit/record"
	"github.com/truvity/audit/sink"

	"github.com/truvity/cloudflare/v2/internal/audit"
)

// keepAll is a minimal stand-in for a real installation: it takes every
// record an emitter hands it, keyed in order, under the same catalogue
// validation the emitter always runs before a record reaches a sink at
// all — so a record either constructor built wrong fails here, not in a
// deployment.
type keepAll struct {
	mu      sync.Mutex
	records []*record.Record
}

func (k *keepAll) write(_ context.Context, req *sink.Request) (*sink.Result, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.records = append(k.records, req.Records...)

	return &sink.Result{Accepted: len(req.Records)}, nil
}

func (k *keepAll) all() []*record.Record {
	k.mu.Lock()
	defer k.mu.Unlock()

	return append([]*record.Record(nil), k.records...)
}

func newRecorder(t *testing.T) (*emit.Emitter, *keepAll) {
	t.Helper()

	c, _, err := audit.Catalogue()
	require.NoError(t, err)

	k := &keepAll{}
	// Flush at once: a test asserts on what was recorded right after
	// recording it, and the default one-second flush would make every
	// such test a sleep.
	e, err := emit.New(emit.Options{Source: audit.Source, Catalogue: c, Sink: sink.Func(k.write), Batch: 1, Flush: time.Millisecond})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })

	return e, k
}

func settle(t *testing.T, e *emit.Emitter) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for e.Pending() > 0 {
		if time.Now().After(deadline) {
			t.Fatal("the emitter did not deliver what it was given")
		}

		time.Sleep(time.Millisecond)
	}
}

// every is one record of each action this catalogue declares, built the
// way the code builds them.
func every() []*record.Record {
	minted := audit.Grant{
		Group: "ci:cache:writer", Bucket: "example-bucket", Prefixes: []string{"go-build/"},
		Permission: "object-read-write", TTLSeconds: 900, MintMode: "local",
	}
	requested := audit.Grant{Bucket: "example-bucket"}

	return []*record.Record{
		audit.CredentialMinted(audit.CI("github:example/repo"), minted),
		audit.CredentialRefused(audit.Anonymous(), audit.Grant{}, "no bearer token presented"),
		audit.CredentialRefused(audit.Workload("system:serviceaccount:ci:runner"), requested, "no group in the token maps to a grant"),
	}
}

// Every constructor makes a record the embedded catalogue accepts, and
// every action the catalogue declares has a constructor here: the
// vocabulary is the catalogue, no more and no less — `just
// audit-catalogue` (audit check-emitters) holds the second half of this
// to the actual source tree, not just this test's own list.
func TestTheConstructorsAreTheCatalogue(t *testing.T) {
	e, k := newRecorder(t)

	built := map[string]bool{}

	for _, r := range every() {
		require.NoError(t, e.Record(context.Background(), r))

		built[r.GetAction()] = true
	}

	settle(t, e)

	c, _, err := audit.Catalogue()
	require.NoError(t, err)

	for _, name := range c.ActionNames() {
		assert.True(t, built[name], "%s is declared and no constructor in this test builds it", name)
	}

	assert.Len(t, k.all(), len(every()))
}

func TestCredentialMintedIsTheInstallationsOwn(t *testing.T) {
	e, k := newRecorder(t)

	r := audit.CredentialMinted(audit.CI("github:example/repo"), audit.Grant{
		Group: "ci:cache:writer", Bucket: "example-bucket", Prefixes: []string{"go-build/"},
		Permission: "object-read-write", TTLSeconds: 900, MintMode: "local",
	})
	require.NoError(t, e.Record(context.Background(), r))
	settle(t, e)

	got := k.all()[0]
	assert.Equal(t, "r2broker", got.GetSource())
	assert.Equal(t, record.TenantPlatform, got.GetTenantId())
	assert.Equal(t, auditv1.Operation_OPERATION_CREATE, got.GetOperation())
	assert.Equal(t, auditv1.Outcome_RESULT_SUCCESS, got.GetOutcome().GetResult())
	require.Len(t, got.GetTargets(), 1)
	assert.Equal(t, "bucket", got.GetTargets()[0].GetType())
	assert.Equal(t, "example-bucket", got.GetTargets()[0].GetId())
	assert.Equal(t, "ci:cache:writer", got.GetData().GetFields()["group"].GetStringValue())
	assert.Equal(t, "local", got.GetData().GetFields()["mint_mode"].GetStringValue())
	// Never the credential itself: nothing this constructor takes could
	// even carry one (Grant has no field for it), which is the whole
	// point of Grant's own shape.
}

func TestCredentialRefusedCarriesTheReasonAndNoTarget(t *testing.T) {
	e, k := newRecorder(t)

	r := audit.CredentialRefused(audit.Anonymous(), audit.Grant{}, "no bearer token presented")
	require.NoError(t, e.Record(context.Background(), r))
	settle(t, e)

	got := k.all()[0]
	assert.Equal(t, auditv1.Outcome_RESULT_DENIED, got.GetOutcome().GetResult())
	assert.Equal(t, "no bearer token presented", got.GetOutcome().GetReason())
	assert.Empty(t, got.GetTargets(), "no bucket was ever resolved, so there is nothing to target")
	assert.Equal(t, "anonymous", got.GetActor().GetKind())
}

func TestIdentifiedNamesAWorkloadOrACIJob(t *testing.T) {
	assert.Equal(t, audit.Workload("system:serviceaccount:ci:runner"), audit.Identified("system:serviceaccount:ci:runner"))
	assert.Equal(t, audit.CI("github:example/repo"), audit.Identified("github:example/repo"))
}
