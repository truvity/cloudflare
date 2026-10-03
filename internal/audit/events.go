package audit

import (
	"strings"

	auditv1 "github.com/truvity/audit/sdk/gen/audit/v1"
	"github.com/truvity/audit/sdk/record"
	"google.golang.org/protobuf/types/known/structpb"
)

// This file is the whole vocabulary: one constructor per action
// catalogue/r2broker.yaml declares, each spelling its action once. A
// caller says what happened in Go types; the kind, target and data are
// chosen here, so they cannot drift between call sites. Mirrors
// access-roster's internal/audit/events.go in shape, independently
// implemented (no shared code between the two repositories).

// Actor is who asked for a credential.
type Actor struct {
	Kind string
	ID   string
}

// CI is a CI job, by the repository the token's issuer named it for.
func CI(id string) Actor { return Actor{Kind: "ci", ID: id} }

// Workload is a cluster workload, by the service account the token's
// issuer named it for.
func Workload(id string) Actor { return Actor{Kind: "workload", ID: id} }

// Anonymous is a caller refused before its token could be verified at
// all — there is no verify.Result to name it by.
func Anonymous() Actor { return Actor{Kind: "anonymous", ID: "anonymous"} }

// Identified is whoever a verified token's subject names: a service
// account is a workload, anything else (a repository slug, or any other
// shape an issuer other than this estate's own gives a subject) is a CI
// job — the broker's own catalogue only distinguishes "a workload" from
// "everything else with a subject," since, per design §2.8, it reuses
// access-roster's actor-kind vocabulary without depending on
// access-roster's own logic for assigning it.
func Identified(subject string) Actor {
	if strings.HasPrefix(subject, "system:serviceaccount:") {
		return Workload(subject)
	}

	return CI(subject)
}

// Grant is the scope a credential was minted for, or requested under.
type Grant struct {
	Group      string
	Bucket     string
	Prefixes   []string
	Permission string
	// TTLSeconds and MintMode are set only on a successful mint: a
	// refused request was never assigned a TTL or a minting path.
	TTLSeconds int
	MintMode   string
}

// CredentialMinted is a temporary R2 credential minted for actor. Never
// the credential itself.
func CredentialMinted(actor Actor, g Grant) *record.Record {
	d := data{
		"group": g.Group, "bucket": g.Bucket, "prefixes": g.Prefixes,
		"permission": g.Permission, "ttl_seconds": g.TTLSeconds, "mint_mode": g.MintMode,
	}

	return build("r2broker.credential.minted", actor, succeeded(), targetsOf(g.Bucket), d)
}

// CredentialRefused is a request for a temporary R2 credential refused,
// at any stage: an unverifiable token (actor is Anonymous, g is the zero
// Grant), no matching group or an ambiguous request (decide's own
// refusal, actor known, g partially known from what was requested), or
// the mint itself failing after a request was otherwise authorized (actor
// and g both fully known). reason is the failing stage's own sentence —
// "the description is the issuer's own sentence" (design §2.1, quoting
// ADR 0008).
func CredentialRefused(actor Actor, g Grant, reason string) *record.Record {
	d := data{"group": g.Group, "bucket": g.Bucket, "prefixes": g.Prefixes, "permission": g.Permission}

	return build("r2broker.credential.refused", actor, denied(reason), targetsOf(g.Bucket), d)
}

// ------------------------------------------------------------- helpers

type data map[string]any

// outcome is a plain Go value standing in for *record.Outcome (a
// protobuf message, which carries a sync.Mutex in its generated state and
// so must never be copied by value — `go vet` catches exactly that).
// succeeded and denied build one; build turns it into the pointer a
// record actually carries, once, at the end.
type outcome struct {
	result auditv1.Outcome_Result
	reason string
}

func build(action string, actor Actor, o outcome, targets []*record.Target, d data) *record.Record {
	r := &record.Record{
		Action:   action,
		TenantId: Tenant,
		Actor:    &record.Actor{Kind: actor.Kind, Id: actor.ID},
		Targets:  targets,
		Outcome:  &record.Outcome{Result: o.result, Reason: o.reason},
	}
	if s := d.proto(); s != nil {
		r.Data = s
	}

	return r
}

func succeeded() outcome { return outcome{result: auditv1.Outcome_RESULT_SUCCESS} }

func denied(reason string) outcome {
	return outcome{result: auditv1.Outcome_RESULT_DENIED, reason: reason}
}

func targetsOf(bucket string) []*record.Target {
	if bucket == "" {
		return nil
	}

	return []*record.Target{{Type: "bucket", Id: bucket}}
}

// proto is the data as a record carries it, leaving out what is empty: an
// absent property says "not known", an empty one would say "known to be
// nothing" — the same convention access-roster's own events.go uses.
func (d data) proto() *structpb.Struct {
	fields := map[string]*structpb.Value{}

	for k, v := range d {
		switch v := v.(type) {
		case string:
			if v != "" {
				fields[k] = structpb.NewStringValue(v)
			}
		case int:
			if v != 0 {
				fields[k] = structpb.NewNumberValue(float64(v))
			}
		case []string:
			if len(v) > 0 {
				list := make([]*structpb.Value, 0, len(v))
				for _, s := range v {
					list = append(list, structpb.NewStringValue(s))
				}

				fields[k] = structpb.NewListValue(&structpb.ListValue{Values: list})
			}
		}
	}

	if len(fields) == 0 {
		return nil
	}

	return &structpb.Struct{Fields: fields}
}
