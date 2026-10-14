# Documentation

This repository holds two halves of one edge, and each keeps its own
documents. Read the half you adopt.

## Cloudflare half (Go packages under `cloudflare/`, chart `cloudflared`)

- [cloudflare/layout.md](cloudflare/layout.md): the recommended
  root/edge/r2(/status) split, one root token that only mints child tokens
- [cloudflare/adoption.md](cloudflare/adoption.md): prerequisites, install
  order, the zero-diff gate, adopting existing objects, upgrading across
  breaking releases, and the move of the Go module to `edge/v3`
- [cloudflare/safety.md](cloudflare/safety.md): every refusal and the failure
  it prevents; the traps
- [cloudflare/reference.md](cloudflare/reference.md): every chart value, every
  Go input and output, and the child names that are a contract
- [cloudflare/doctrine.md](cloudflare/doctrine.md): what this repository owns
  and what the consuming estate owns

## Envoy half (`catalog/`, charts `gateway-*`)

- [gateway/adoption.md](gateway/adoption.md): prerequisites, install order,
  the zero-diff gate, and upgrading across breaking releases
- [gateway/safety.md](gateway/safety.md): every render-time refusal and the
  failure it prevents; the traps
- [gateway/reference.md](gateway/reference.md): every value of every chart
- [gateway/doctrine.md](gateway/doctrine.md): the ownership contract
- [gateway/CHANGELOG-history.md](gateway/CHANGELOG-history.md): the changelog
  of `truvity/gateway` up to its v1.19.0, before it was folded in here
- [gateway/commit-map.txt](gateway/commit-map.txt): old `truvity/gateway`
  commit to the commit in this history (every imported commit also carries
  an `Origin: truvity/gateway@<sha>` trailer)

## Both

- [../CHANGELOG.md](../CHANGELOG.md): what changed for a consumer, per version
- [../CONTRIBUTING.md](../CONTRIBUTING.md) and [../SECURITY.md](../SECURITY.md)
