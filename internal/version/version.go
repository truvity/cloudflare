// Package version holds the one build-time value goreleaser stamps into
// the r2broker binary, so an operator can tell which release a running
// service or a downloaded CLI actually is — the same
// -ldflags -X mechanism access-roster's own binaries use.
package version

// Version is overwritten at build time via
// -ldflags "-X github.com/truvity/cloudflare/v2/internal/version.Version=...".
// "dev" is what `go build`/`go run` leave it at, so a local build never
// claims to be a real release.
var Version = "dev"
