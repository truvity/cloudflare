package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	auditpkg "github.com/truvity/cloudflare/v2/internal/audit"
	"github.com/truvity/cloudflare/v2/internal/broker"
	"github.com/truvity/cloudflare/v2/internal/config"
	"github.com/truvity/cloudflare/v2/internal/mint"
	"github.com/truvity/cloudflare/v2/internal/version"
)

// requestTimeout bounds one /v1/credentials call: OIDC signature checks
// and, on the composite path's fallback, a real Cloudflare API round
// trip, both included.
const requestTimeout = 15 * time.Second

// serve runs the long-running HTTP service.
func serve(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := flags.String("config", os.Getenv("R2BROKER_CONFIG"), "path to the broker's config file (or $R2BROKER_CONFIG)")
	addr := flags.String("addr", envOr("R2BROKER_ADDR", ":8080"), "address to listen on (or $R2BROKER_ADDR)")
	auditReceiverURL := flags.String("audit-receiver-url", os.Getenv("R2BROKER_AUDIT_RECEIVER_URL"),
		"the audit installation's receiver (or $R2BROKER_AUDIT_RECEIVER_URL); empty logs records and keeps them nowhere else")
	auditTokenFile := flags.String("audit-token-file", os.Getenv("R2BROKER_AUDIT_TOKEN_FILE"),
		"this pod's projected ServiceAccount token, audience \"audit\" (or $R2BROKER_AUDIT_TOKEN_FILE)")

	if err := flags.Parse(args); err != nil {
		return usageError{err}
	}

	if strings.TrimSpace(*configPath) == "" {
		return badUsage("--config is required (or set $R2BROKER_CONFIG)")
	}

	f, err := os.Open(*configPath)
	if err != nil {
		return fmt.Errorf("opening %s: %w", *configPath, err)
	}
	defer func() { _ = f.Close() }()

	cfg, err := config.Load(f)
	if err != nil {
		return err
	}

	tokenValue, err := resolveParentTokenValue(cfg.Account)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	logger := slog.New(slog.NewJSONHandler(stderr, nil))

	observe := func(path mint.Path, mintErr error) {
		if path == mint.PathAPI {
			// A shift from "local" to "api" for a mint that would
			// otherwise have signed locally is the drift-detection
			// signal design §1.2 asks for: alert on it, don't just log
			// it and move on, once this installation has anywhere to
			// alert to.
			logger.WarnContext(ctx, "mint fell back to the Cloudflare API", "error", errString(mintErr))
		}
	}

	b, err := broker.New(ctx, cfg, mint.ParentToken{ID: cfg.Account.ParentTokenID, Value: tokenValue}, http.DefaultClient, observe)
	if err != nil {
		return err
	}

	trail, err := auditpkg.Open(ctx, auditpkg.Config{
		ReceiverURL: *auditReceiverURL, TokenFile: *auditTokenFile,
		Version: version.Version, Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("opening the audit trail: %w", err)
	}
	defer func() { _ = trail.Close() }()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.Handle("POST /v1/credentials", &credentialsHandler{broker: b, logger: logger, trail: trail})

	server := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	errCh := make(chan error, 1)

	go func() {
		logger.Info("r2broker listening", "addr", *addr)

		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()

		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// credentialsHandler answers POST /v1/credentials, per design §2.1.
type credentialsHandler struct {
	broker *broker.Broker
	logger *slog.Logger
	// trail records every mint and refusal (design §2.8/R4). Never nil in
	// practice — serve always opens one, logging-only when no
	// installation is configured — but a nil trail is also handled
	// (Trail.Record is a no-op on it), which is what keeps every test
	// that builds a bare credentialsHandler without one working.
	trail *auditpkg.Trail
}

func (h *credentialsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()

	token := bearerToken(r.Header.Get("Authorization"))

	body, err := readRequestBody(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)

		return
	}

	result := h.broker.Mint(ctx, broker.Request{
		Token: token, Bucket: body.Bucket, Prefixes: body.Prefixes, Permission: body.Permission,
	})

	h.record(ctx, result, body)

	switch result.Outcome {
	case broker.OutcomeMinted:
		writeJSON(w, http.StatusOK, credentialsResponseBody{
			AccessKeyID:     result.Credential.AccessKeyID,
			SecretAccessKey: result.Credential.SecretAccessKey,
			SessionToken:    result.Credential.SessionToken,
			Expiration:      result.Credential.Expiration.UTC().Format(time.RFC3339),
			Bucket:          result.Decision.Bucket,
			Prefixes:        result.Decision.Prefixes,
		})
	case broker.OutcomeUnauthenticated:
		writeError(w, http.StatusUnauthorized, result.Err)
	case broker.OutcomeRefused:
		writeError(w, http.StatusForbidden, result.Err)
	case broker.OutcomeMintFailed:
		h.logger.ErrorContext(ctx, "mint failed after a successful decision", "error", errString(result.Err))
		writeError(w, http.StatusBadGateway, result.Err)
	default:
		writeError(w, http.StatusInternalServerError, fmt.Errorf("unhandled outcome"))
	}
}

// record tells the audit trail what result was, matching whichever of
// this catalogue's two actions fits (design §2.8): OutcomeMinted is
// r2broker.credential.minted, everything else is
// r2broker.credential.refused — an unauthenticated caller has no known
// actor or scope; a decide refusal has an actor and whatever the request
// itself asked for; a mint failure has both an actor and a fully resolved
// decision, since it was authorized right up to the mint call itself.
func (h *credentialsHandler) record(ctx context.Context, result broker.Result, body credentialsRequestBody) {
	switch result.Outcome {
	case broker.OutcomeMinted:
		h.trail.Record(ctx, auditpkg.CredentialMinted(auditpkg.Identified(result.Subject), auditpkg.Grant{
			Group: result.Decision.Group, Bucket: result.Decision.Bucket, Prefixes: result.Decision.Prefixes,
			Permission: string(result.Decision.Permission), TTLSeconds: result.Decision.TTLSeconds,
			MintMode: string(result.MintPath),
		}))
	case broker.OutcomeUnauthenticated:
		h.trail.Record(ctx, auditpkg.CredentialRefused(auditpkg.Anonymous(), auditpkg.Grant{}, errString(result.Err)))
	case broker.OutcomeRefused:
		h.trail.Record(ctx, auditpkg.CredentialRefused(auditpkg.Identified(result.Subject), auditpkg.Grant{
			Bucket: body.Bucket, Prefixes: body.Prefixes, Permission: string(body.Permission),
		}, errString(result.Err)))
	case broker.OutcomeMintFailed:
		h.trail.Record(ctx, auditpkg.CredentialRefused(auditpkg.Identified(result.Subject), auditpkg.Grant{
			Group: result.Decision.Group, Bucket: result.Decision.Bucket, Prefixes: result.Decision.Prefixes,
			Permission: string(result.Decision.Permission),
		}, errString(result.Err)))
	}
}

// readRequestBody decodes an optional JSON body. No body at all (a
// request whose token's groups reach exactly one bucket with no prefix
// restriction to narrow) is not an error — every field it would have set
// is already optional.
func readRequestBody(r io.Reader) (credentialsRequestBody, error) {
	data, err := io.ReadAll(io.LimitReader(r, 1<<16))
	if err != nil {
		return credentialsRequestBody{}, fmt.Errorf("reading request body: %w", err)
	}

	if len(strings.TrimSpace(string(data))) == 0 {
		return credentialsRequestBody{}, nil
	}

	var body credentialsRequestBody
	if err := json.Unmarshal(data, &body); err != nil {
		return credentialsRequestBody{}, fmt.Errorf("decoding request body: %w", err)
	}

	return body, nil
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}

	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, errorResponseBody{Error: errString(err)})
}

func errString(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return fallback
}
