# Development commands. Everything CI runs is a recipe here — the shared
# check workflow (truvity/ci-workflows) runs each one as its own job.

# Lint every chart.
# The schema is part of the lint: an unknown key — top level or inside a
# fleet — must fail the render, not be silently ignored.
lint:
    helm lint charts/envoy-gateway-fleet
    ! helm template x charts/envoy-gateway-fleet --set bogusKey=1 >/dev/null 2>&1
    ! helm template x charts/envoy-gateway-fleet --set fleets.internal.bogus=1 >/dev/null 2>&1
    ! helm template x charts/envoy-gateway-fleet --set fleets.internal.envoyproxy.enabled=false >/dev/null 2>&1

# Golden renders: render every test case and compare with tests/golden.
test:
    hack/golden.sh

# Regenerate the golden renders — review the diff before committing.
golden:
    hack/golden.sh update

# The reason this repository can be public. Runs in CI as its own job.
leak-canary:
    hack/leak-canary.sh

# Package every chart locally (the release workflow stamps the version from the tag).
package:
    helm package charts/envoy-gateway-fleet --destination dist/

# Everything CI runs on a pull request.
check: lint test leak-canary
