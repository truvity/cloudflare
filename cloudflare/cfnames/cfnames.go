// Package cfnames holds pure Cloudflare naming and validity rules — no
// Cloudflare API call, no Pulumi resource, no SDK import of any kind, not
// even this module's own cloudflare/account or cloudflare/r2.
//
// cloudflare/account's ValidR2Jurisdiction and ValidR2BucketName are the single
// source of truth cloudflare/r2 and cloudflare/account's own R2BucketScope validate
// against — but cloudflare/account imports the Pulumi/Cloudflare SDK for
// unrelated reasons (minting a child token), so a caller that only wants
// "is 'eu' a valid R2 jurisdiction?" or "is this a legal bucket name?"
// before the value ever reaches either package — a chart's
// values.schema.json generator, a config-linting step in an estate's own
// repository — had no way to ask without pulling in the whole SDK, and
// downstream config layers kept their own copies of the jurisdiction list
// instead. This package is that answer.
//
// The name is "cfnames", not "cloudflare/r2/jurisdiction": it holds a bucket-name
// rule too, not just jurisdictions, and nesting it under cloudflare/r2 would
// suggest cloudflare/r2 is upstream of cloudflare/account, which is backwards — cloudflare/r2
// imports cloudflare/account, never the reverse (see cloudflare/r2's own package doc).
// A standalone package implies no direction either way, and leaves room
// for another pure Cloudflare-naming rule later (a zone id's shape, a
// token name's charset) without relitigating where it lives.
//
// This package's whole reason to exist is enforced, not just documented:
// TestNoNonStdlibImports fails the moment it imports anything outside the
// standard library.
package cfnames

import "slices"

// jurisdictions is every value ValidJurisdiction accepts: Cloudflare's R2
// data-residency jurisdictions, plus the two spellings of "none" a
// non-jurisdictional bucket uses ("" and "default" — see cloudflare/r2's own
// Config.Jurisdiction and cloudflare/account's R2BucketScope.Jurisdiction, which
// both accept either).
var jurisdictions = []string{"", "default", "eu", "fedramp", "us"}

// Jurisdictions returns every value ValidJurisdiction accepts. It returns
// a fresh slice on every call, so a caller may mutate or sort the result
// (for a message, an error list, a schema enum) without corrupting this
// package's own state or any earlier caller's copy.
func Jurisdictions() []string {
	return slices.Clone(jurisdictions)
}

// ValidJurisdiction reports whether jurisdiction is one of Jurisdictions:
// "" or "default" for a non-jurisdictional bucket, or one of Cloudflare's
// three R2 jurisdictions ("eu", "fedramp", "us").
func ValidJurisdiction(jurisdiction string) bool {
	return slices.Contains(jurisdictions, jurisdiction)
}

// ValidBucketName reports whether name follows Cloudflare's R2 bucket
// naming rules: https://developers.cloudflare.com/r2/buckets/create-buckets/
// (accessed 2026-09-27) — "Bucket names can only contain lowercase letters
// (a-z), numbers (0-9), and hyphens (-)", "cannot begin or end with a
// hyphen", "3-63 characters in length".
func ValidBucketName(name string) bool {
	if len(name) < 3 || len(name) > 63 {
		return false
	}

	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-':
			if i == 0 || i == len(name)-1 {
				return false
			}
		default:
			return false
		}
	}

	return true
}

// Permission levels an R2 token config accepts. cloudflare/r2 re-exports them as
// r2.PermissionObjectReadWrite and r2.PermissionObjectReadOnly.
const (
	R2PermissionObjectReadWrite = "object-read-write"
	R2PermissionObjectReadOnly  = "object-read-only"
)

// R2Permissions lists the permission levels an R2 token config accepts, so
// a caller validating its own input does not restate them. It returns a
// fresh slice on every call.
func R2Permissions() []string {
	return []string{R2PermissionObjectReadWrite, R2PermissionObjectReadOnly}
}
