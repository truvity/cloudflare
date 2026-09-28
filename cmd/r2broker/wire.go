package main

import "github.com/truvity/cloudflare/v2/internal/config"

// The wire shapes of POST /v1/credentials (design §2.1), shared by
// serve.go (which writes credentialsResponseBody and errorResponseBody,
// and reads credentialsRequestBody) and credentials.go's --service-url
// client mode (the reverse), so the two sides of this one HTTP contract
// are defined exactly once.

// credentialsRequestBody is the request's optional JSON body. Every field
// narrows an already-authorized request; none of them can widen past what
// the token's groups hold (internal/decide enforces that).
type credentialsRequestBody struct {
	Bucket     string            `json:"bucket,omitempty"`
	Prefixes   []string          `json:"prefixes,omitempty"`
	Permission config.Permission `json:"permission,omitempty"`
}

// credentialsResponseBody is the 200 response: an AWS-shaped credential
// triple plus, for the caller's own confirmation, exactly what it was
// minted for.
type credentialsResponseBody struct {
	AccessKeyID     string   `json:"accessKeyId"`
	SecretAccessKey string   `json:"secretAccessKey"`
	SessionToken    string   `json:"sessionToken"`
	Expiration      string   `json:"expiration"`
	Bucket          string   `json:"bucket"`
	Prefixes        []string `json:"prefixes,omitempty"`
}

// errorResponseBody is every non-200 response: "the description is the
// issuer's own sentence" (design §2.1, quoting ADR 0008) — decide's and
// verify's own error text, passed through rather than mapped to a code.
type errorResponseBody struct {
	Error string `json:"error"`
}
