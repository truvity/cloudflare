package r2

import (
	"fmt"
	"log/slog"
	"sort"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/cloudflare/v2/pkg/account"
)

// stackProviderName is the Pulumi name of the account provider a bucket
// stack registers.
const stackProviderName = "r2"

type (
	// Declaration is one bucket as a registry declares it.
	Declaration struct {
		// Name keys the Pulumi resources ("r2-"+Name) and the registry.
		Name string
		// Enabled false creates nothing.
		Enabled bool
		// Account must be the stack's own account: a bucket stack runs as
		// one account's admin child.
		Account      string
		Bucket       string
		Jurisdiction string
		// Lifecycle expires objects after a fixed age; nil creates none.
		Lifecycle *Lifecycle
	}

	// StackArgs is a bucket stack: every enabled bucket of one account.
	StackArgs struct {
		// AccountName and AccountID are the stack's account.
		AccountName string
		AccountID   string
		// Token is the already-resolved bucket-admin token (the caller
		// reads it before the program runs: it configures a provider).
		Token   string
		Buckets []Declaration
		Logger  *slog.Logger
	}
)

// DeployStack creates every enabled bucket of one account, as that account's
// bucket-admin child.
//
// It mints no tokens. A bucket's own bucket-scoped credential is minted
// elsewhere (pkg/tokensplit, from the same declaration), so the stack that
// touches a bucket is never the stack that mints the credential scoped to
// it: a bug in one cannot widen what the other reaches. Every bucket is
// created with Config.Token at its zero value.
func DeployStack(ctx *pulumi.Context, args StackArgs) error {
	logger := args.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	acct, err := account.New(ctx, stackProviderName, account.Args{AccountID: args.AccountID}, pulumi.String(args.Token))
	if err != nil {
		return fmt.Errorf("account provider: %w", err)
	}

	buckets := append([]Declaration(nil), args.Buckets...)
	sort.Slice(buckets, func(i, j int) bool { return buckets[i].Name < buckets[j].Name })

	deployed := 0

	for _, b := range buckets {
		if !b.Enabled {
			logger.InfoContext(ctx.Context(), "r2 bucket disabled, skipping", slog.String("name", b.Name))

			continue
		}

		if b.Account != args.AccountName {
			return fmt.Errorf("bucket %s: account %q is not %q, the only account this stack's admin child covers", b.Name, b.Account, args.AccountName)
		}

		cfg := Config{
			AccountID:    args.AccountID,
			Bucket:       b.Bucket,
			Jurisdiction: b.Jurisdiction,
			Lifecycle:    b.Lifecycle,
		}

		if _, err := New(ctx, "r2-"+b.Name, cfg, acct.Use()); err != nil {
			return fmt.Errorf("bucket %s: %w", b.Name, err)
		}

		deployed++

		logger.InfoContext(ctx.Context(), "r2 bucket deployed",
			slog.String("name", b.Name),
			slog.String("account", b.Account),
			slog.String("bucket", b.Bucket),
		)
	}

	logger.InfoContext(ctx.Context(), "cloudflare-r2 buckets deployed", slog.Int("count", deployed))

	return nil
}
