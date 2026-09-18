# Development commands. Everything CI runs is a recipe here — the shared
# check workflow (truvity/ci-workflows) runs each one as its own job.

charts := "cloudflared"

# Lint every chart and the Go module. The schema is part of the lint:
# an unknown key must fail the render, not be silently ignored, and every
# negative fixture under tests/invalid/<chart>/ must fail — one that
# renders is a hole in the validation nobody would otherwise notice.
lint:
    #!/usr/bin/env bash
    set -euo pipefail
    for chart in {{ charts }}; do
      helm lint "charts/$chart"
      ! helm template x "charts/$chart" --set bogusKey=1 >/dev/null 2>&1
      for values in tests/invalid/"$chart"/*.yaml; do
        if helm template invalid "charts/$chart" -f "$values" >/dev/null 2>&1; then
          echo "RENDERED BUT SHOULD HAVE FAILED: $values" >&2
          exit 1
        fi
      done
      echo "$chart: schema and $(ls tests/invalid/"$chart"/*.yaml | wc -l | tr -d ' ') negative fixtures OK"
    done
    golangci-lint config verify
    golangci-lint run ./...

# Golden renders: render every test case and compare with tests/golden.
test:
    hack/golden.sh
    go test ./...

# Regenerate the golden renders — review the diff before committing.
golden:
    hack/golden.sh update

# The reason this repository can be public. Runs in CI as its own job.
leak-canary:
    hack/leak-canary.sh

# Compile check (library — nothing to run).
build:
    go build ./...

# Format Go files.
fmt:
    golangci-lint fmt ./...

# Reachable Go advisories (security.yaml, daily).
vuln:
    govulncheck ./...

# Run go mod tidy.
tidy:
    go mod tidy

# Package every chart locally (the release workflow stamps the version from the tag).
package:
    helm package charts/cloudflared --destination dist/

# Everything CI runs on a pull request.
check: build lint test leak-canary vuln
