# Development commands. Everything CI runs is a recipe here — the shared
# check workflow (truvity/ci-workflows) runs each one as its own job.

# Lint every chart.
# The schema is part of the lint: an unknown key — top level or inside a
# fleet — must fail the render, not be silently ignored.
lint:
    helm lint charts/envoy-gateway-fleet
    ! helm template x charts/envoy-gateway-fleet --set bogusKey=1 >/dev/null 2>&1
    ! helm template x charts/envoy-gateway-fleet --set fleets.internal.bogus=1 >/dev/null 2>&1
    helm template x charts/envoy-gateway-fleet --set fleets.internal.envoyProxy.enabled=false >/dev/null
    ! helm template x charts/envoy-gateway-fleet --set fleets.internal.listeners.test.hostname=gateway.example.com --set fleets.internal.listeners.test.bogus=1 >/dev/null 2>&1
    for values in tests/invalid/*.yaml; do ! helm template invalid charts/envoy-gateway-fleet -f "$values" >/dev/null 2>&1 || exit 1; done
    ! helm template x charts/envoy-gateway-fleet --set-string 'fleets.internal.listeners.test.hostname=*.example.com' >/dev/null 2>&1
    helm template x charts/envoy-gateway-fleet --set fleets.internal.listeners.paused.enabled=false >/dev/null
    helm template x charts/envoy-gateway-fleet --set fleets.internal.listeners.single.hostname=gateway --set fleets.internal.listeners.single.certificate.enabled=false >/dev/null
    helm template x charts/envoy-gateway-fleet --set fleets.internal.listeners.explicit-default.hostname=gateway.example.com --set-string fleets.internal.listeners.explicit-default.listenerName= --set fleets.internal.listeners.explicit-default.certificate.enabled=false >/dev/null
    helm template x charts/envoy-gateway-fleet --set fleets.internal.healthListener.enabled=true --set fleets.internal.healthListener.hostname=health.example.com --set fleets.internal.healthListener.tls.secretName=gateway.tls >/dev/null
    helm template x charts/envoy-gateway-fleet --set fleets.internal.healthListener.enabled=true --set fleets.internal.healthListener.hostname=health.example.com --set fleets.internal.healthListener.allowedRoutes.kinds[0].kind=HTTPRoute >/dev/null
    ! helm template x charts/envoy-gateway-fleet --set fleets.internal.listeners.test.hostname='not a hostname' >/dev/null 2>&1
    ! helm template x charts/envoy-gateway-fleet --set fleets.internal.listeners.test.hostname=test.example.com --set fleets.internal.listeners.test.gatewayName=Invalid_Name >/dev/null 2>&1
    ! helm template x charts/envoy-gateway-fleet --set fleets.internal.healthListener.enabled=true --set fleets.internal.healthListener.hostname=health.example.com --set fleets.internal.listeners.test.hostname=test.example.com --set fleets.internal.listeners.test.gatewayName=internal --set fleets.internal.listeners.test.certificate.enabled=false >/dev/null 2>&1
    ! helm template x charts/envoy-gateway-fleet --set fleets.internal.healthListener.enabled=true --set fleets.internal.healthListener.hostname=same.example.com --set fleets.internal.listeners.test.hostname=same.example.com --set fleets.internal.listeners.test.certificate.enabled=false >/dev/null 2>&1
    ! helm template x charts/envoy-gateway-fleet --set fleets.internal.listeners.one.hostname=same.example.com --set fleets.internal.listeners.one.certificate.enabled=false --set fleets.internal.listeners.two.hostname=same.example.com --set fleets.internal.listeners.two.certificate.enabled=false >/dev/null 2>&1
    ! helm template x charts/envoy-gateway-fleet --set fleets.internal.listeners.one.hostname=one.example.com --set fleets.internal.listeners.one.gatewayName=shared --set fleets.internal.listeners.one.certificate.enabled=false --set fleets.customer.listeners.two.hostname=two.example.com --set fleets.customer.listeners.two.gatewayName=shared --set fleets.customer.listeners.two.certificate.enabled=false >/dev/null 2>&1
    ! helm template x charts/envoy-gateway-fleet --set fleets.internal.listeners.test.hostname=test.example.com --set fleets.internal.listeners.test.clientTrafficPolicy.enabled=true --set-string fleets.internal.listeners.test.clientTrafficPolicy.tls.minVersion=1.3 --set-string fleets.internal.listeners.test.clientTrafficPolicy.tls.maxVersion=1.2 >/dev/null 2>&1

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
