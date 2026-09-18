# gateway-policies

The Envoy Gateway policies that protect what `gateway-fleet` and
`gateway-groups` expose: a TLS floor on every Gateway of a namespace
unless it opts out by label (on by default), stricter TLS per listener, an
OIDC or JWT SecurityPolicy per protected route with an `authenticated` or
`groups` posture and CSRF, and BackendTLSPolicy for private-chain backends.
Nothing authenticates until it is given an issuer.

```sh
helm install policies oci://ghcr.io/truvity/charts/gateway-policies \
  --namespace envoy-gateway-system --values policies-values.yaml
```

- every value and a worked example: [docs/reference.md](../../docs/reference.md#gateway-policies)
- every refusal, the defaults and the CSRF shadow-to-enforce procedure:
  [docs/safety.md](../../docs/safety.md#gateway-policies)
- prerequisites and adopting existing policies: [docs/adoption.md](../../docs/adoption.md)
