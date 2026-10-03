// Package audit is what r2broker tells the audit trail.
//
// It is the broker's OWN audit installation (design decision R4): its own
// catalogue (catalogue/r2broker.yaml, source "r2broker"), registered and
// emitted independently of whatever else on the shared platform emits
// `roster.*` actions. This mirrors access-roster's own internal/audit
// package (github.com/truvity/access-roster/internal/audit) — same
// shape, down to embedding the catalogue's JSON Schemas alongside its
// YAML and registering both — no shared code, since neither repository
// depends on the other.
//
// The vocabulary is fixed here and nowhere else: every action has one
// constructor in events.go, the catalogue declares every one of them, and
// `just audit-catalogue` (audit validate + audit check-emitters) fails
// the gate when the two disagree.
//
// Recording never fails a mint: an async delivery (both of this
// catalogue's actions are async) queues in memory and is retried until
// the receiver acknowledges it, so a slow or unreachable audit
// installation degrades to "this mint is not yet recorded", never to
// "this mint was refused."
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path"
	"strings"
	"time"

	"github.com/truvity/audit/sdk/auth"
	"github.com/truvity/audit/sdk/catalogue"
	"github.com/truvity/audit/sdk/emit"
	"github.com/truvity/audit/sdk/record"
	"github.com/truvity/audit/sdk/sink"

	cloudflare "github.com/truvity/cloudflare/v2"
)

// Source is the catalogue's source: every action is under it.
const Source = "r2broker"

// Tenant is the tenant every record is written under. One r2broker
// installation mints for one Cloudflare account, and its trail is that
// installation's own rather than a per-caller tenant's — the same
// reasoning access-roster's own package gives for TenantPlatform.
const Tenant = record.TenantPlatform

// Document is the catalogue as it is registered: the YAML document and
// every JSON Schema it references, keyed by $id.
type Document struct {
	YAML    []byte
	Schemas map[string][]byte
}

// LoadDocument reads the embedded catalogue and its two data schemas
// (catalogue/credential-minted.json, catalogue/credential-refused.json).
func LoadDocument() (Document, error) {
	yaml, err := cloudflare.R2BrokerCatalogueFS.ReadFile("catalogue/r2broker.yaml")
	if err != nil {
		return Document{}, err
	}

	d := Document{YAML: yaml, Schemas: map[string][]byte{}}

	entries, err := fs.ReadDir(cloudflare.R2BrokerCatalogueFS, "catalogue")
	if err != nil {
		return Document{}, err
	}

	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}

		raw, err := cloudflare.R2BrokerCatalogueFS.ReadFile(path.Join("catalogue", e.Name()))
		if err != nil {
			return Document{}, err
		}

		id, err := schemaID(raw)
		if err != nil {
			return Document{}, fmt.Errorf("audit: %s: %w", e.Name(), err)
		}

		d.Schemas[id] = raw
	}

	return d, nil
}

// Catalogue loads and validates the embedded catalogue.
func Catalogue() (*catalogue.Catalogue, Document, error) {
	d, err := LoadDocument()
	if err != nil {
		return nil, Document{}, err
	}

	schemas := make([][]byte, 0, len(d.Schemas))
	for _, raw := range d.Schemas {
		schemas = append(schemas, raw)
	}

	c, err := catalogue.Load(d.YAML, schemas)
	if err != nil {
		return nil, Document{}, err
	}

	if c.Source != Source {
		return nil, Document{}, fmt.Errorf("audit: the catalogue is for %q, and this package records as %q", c.Source, Source)
	}

	return c, d, nil
}

// schemaID reads a schema's $id, which is how the catalogue names it —
// copied from access-roster's own internal/audit.schemaID (same job, no
// shared code between the two repositories).
func schemaID(raw []byte) (string, error) {
	var head struct {
		ID string `json:"$id"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return "", err
	}

	if head.ID == "" {
		return "", errors.New("a schema without an $id")
	}

	return head.ID, nil
}

// Config says which installation to connect to, if any.
type Config struct {
	// ReceiverURL is the installation's receiver: the address records are
	// sent to, and the same address the catalogue is registered with.
	// Empty means no installation: every record is validated against the
	// catalogue and logged, and kept nowhere else.
	ReceiverURL string
	// TokenFile is this pod's projected ServiceAccount token (audience
	// "audit"), presented on every call — the broker needs no audit
	// credential of its own, matching every other application on the
	// shared platform (design §2.8).
	TokenFile string
	Version   string
	Instance  string
	Logger    *slog.Logger
}

func (c Config) connected() bool { return c.ReceiverURL != "" }

// Trail is the recorder: an emitter bound to the catalogue, delivering to
// the installation when one is configured.
type Trail struct {
	emitter *emit.Emitter
	logger  *slog.Logger
}

const registerTimeout = 10 * time.Second

// Open connects to the installation cfg names, or opens a trail that only
// logs when it names none. A catalogue the installation refuses stops the
// start, the same reasoning access-roster's Open gives: writing records
// against a description nobody accepted is worse than not starting.
func Open(ctx context.Context, cfg Config) (*Trail, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	c, doc, err := Catalogue()
	if err != nil {
		return nil, err
	}

	hooks := emit.Hooks{
		OnRefused: func(r *record.Record, err error) {
			logger.Error("an audit record does not satisfy the catalogue", "action", r.GetAction(), "error", err)
		},
		OnFailed: func(err error, delivery sink.Delivery, n int) {
			logger.Warn("audit records could not be delivered yet", "records", n, "delivery", delivery.String(), "error", err)
		},
		OnDropped: func(r *record.Record, reason string) {
			logger.Error("audit record dropped and is not in the trail",
				"audit.id", r.GetId(), "audit.action", r.GetAction(), "reason", reason)
		},
	}

	options := emit.Options{Source: Source, Catalogue: c, Version: cfg.Version, Instance: cfg.Instance, Hooks: hooks, Logger: logger}

	if !cfg.connected() {
		logger.Warn("no audit installation is connected: records are validated and logged, and kept nowhere else")

		options.Sink = sink.Discard

		emitter, err := emit.New(options)
		if err != nil {
			return nil, err
		}

		return &Trail{emitter: emitter, logger: logger}, nil
	}

	if cfg.TokenFile == "" {
		return nil, errors.New("audit: a token file is required when an installation is connected")
	}

	client := auth.TokenFile(cfg.TokenFile)
	options.Sink = sink.NewClient(client, cfg.ReceiverURL)

	emitter, err := emit.New(options)
	if err != nil {
		return nil, err
	}

	registerCtx, cancel := context.WithTimeout(ctx, registerTimeout)
	defer cancel()

	err = emit.Register(registerCtx, emit.Registration{
		URL: cfg.ReceiverURL, Source: c.Source, Version: c.Version, Document: doc.YAML, Schemas: doc.Schemas, HTTP: client,
	})
	switch {
	case errors.Is(err, emit.ErrCatalogueRefused):
		_ = emitter.Close()

		return nil, err
	case err != nil:
		logger.Warn("the audit installation could not be reached at startup; records wait in the emitter's queue",
			"receiver", cfg.ReceiverURL, "error", err)
	default:
		logger.Info("audit installation connected", "receiver", cfg.ReceiverURL, "catalogue", c.Source+"@"+c.Version)
	}

	return &Trail{emitter: emitter, logger: logger}, nil
}

// Record hands a record to the trail. It never fails the caller: a
// record that cannot be kept is logged as such by the emitter's own
// hooks, and the mint it describes has already happened either way —
// both of this catalogue's actions are `async` (design §2.8), so nothing
// here ever blocks a caller waiting on a credential.
func (t *Trail) Record(ctx context.Context, r *record.Record) {
	if t == nil || r == nil {
		return
	}

	if err := t.emitter.Record(ctx, r); err != nil {
		t.logger.WarnContext(ctx, "audit record not kept", "action", r.GetAction(), "error", err)
	}
}

// Close delivers what the emitter's queue still holds, within its
// timeout.
func (t *Trail) Close() error {
	if t == nil || t.emitter == nil {
		return nil
	}

	return t.emitter.Close()
}
