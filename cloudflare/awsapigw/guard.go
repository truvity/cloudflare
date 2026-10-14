package awsapigw

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ProtectedPrefix is a key prefix writable by the listed identities only: the
// truststore guard. It is the same statement a blob bucket must carry when the
// truststore lives in it (Truststore.Existing.GuardedPrefix attests to it).
type ProtectedPrefix struct {
	// Prefix is the key prefix, ending in "/" and not starting with one:
	// "truststore/". Required.
	Prefix string
	// AllowedPrincipalArns are the identities that may still write under it:
	// the role the stack is applied with, the operators' admin role, a
	// break-glass role. The ARN of a role, never of a session of it. Required:
	// an empty list would lock the applier out too.
	AllowedPrincipalArns []string
}

// protectedWrites are the actions the guard denies: whatever creates, replaces,
// deletes or re-labels an object.
var protectedWrites = []string{
	"s3:PutObject", "s3:PutObjectAcl", "s3:PutObjectVersionAcl", "s3:PutObjectTagging", "s3:PutObjectVersionTagging",
	"s3:DeleteObject", "s3:DeleteObjectVersion", "s3:DeleteObjectTagging", "s3:DeleteObjectVersionTagging", "s3:AbortMultipartUpload",
}

// Validate refuses a prefix that would guard nothing, or everything.
func (p ProtectedPrefix) Validate() error {
	switch {
	case p.Prefix == "" || p.Prefix[0] == '/' || p.Prefix[len(p.Prefix)-1] != '/':
		return fmt.Errorf("awsapigw: ProtectedPrefix.Prefix %q is a key prefix ending in \"/\" and not starting with one", p.Prefix)
	case len(p.AllowedPrincipalArns) == 0:
		return fmt.Errorf("awsapigw: ProtectedPrefix %q has no AllowedPrincipalArns: the identity that applies the stack would be denied too", p.Prefix)
	}
	for _, a := range p.AllowedPrincipalArns {
		if !strings.HasPrefix(a, "arn:") {
			return fmt.Errorf("awsapigw: ProtectedPrefix %q: %q is not an ARN", p.Prefix, a)
		}
	}
	return nil
}

// Statement is the bucket-policy statement that guards the prefix in the
// bucket whose ARN is given: Deny the writes to every principal whose ARN is not
// one of AllowedPrincipalArns.
func (p ProtectedPrefix) Statement(bucketArn string) map[string]any {
	return map[string]any{
		"Sid": "ProtectPrefix" + sidOf(p.Prefix), "Effect": "Deny", "Principal": "*",
		"Action": protectedWrites, "Resource": []string{bucketArn + "/" + p.Prefix + "*"},
		"Condition": map[string]any{"ArnNotEquals": map[string]any{"aws:PrincipalArn": p.AllowedPrincipalArns}},
	}
}

func sidOf(prefix string) string {
	var b strings.Builder
	for _, r := range prefix {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func jsonDocument(st []map[string]any) (string, error) {
	raw, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": st})
	return string(raw), err
}
