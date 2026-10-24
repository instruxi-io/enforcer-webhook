# enforcer-webhook

Shared Go library for the enforcer microservices (`github.com/instruxi-io/enforcer-webhook`),
consumed via a versioned go.mod `require`.

## Packages

### `webhook`
Inbound provider-webhook ingress mechanics, shared so each owning service
(cybrid / wf / geo) supplies only the provider-specific bits instead of
re-implementing the security-sensitive core:

- `IngestHandler` — HMAC-SHA256 verification (fail-closed), body-size + clock-skew
  limits, idempotency (`Deduper`), and publishing the raw payload to a topic via a
  `Publisher`. Provider specifics (signature header, how to read the event id/type
  from the body via an `Extractor`, the topic/route) come from `Config`.
  The signature is checked over the raw wire bytes; a `Content-Encoding` body is
  decoded only after that, by `DecodeBody`, capped at `MaxBodySize` decompressed
  (CVE-2026-111497: never call fiber's `c.Body()` before verifying).
- `Store` + `Entry` + `Replay` — dead-letter persistence interface + re-publish helper.

enforcer-mb stays a pure bus; this is the edge. See the enforcer-v3
`webhook-ingress-architecture` decision.

Usage:

```go
h := webhook.NewIngestHandler(mbClient, webhook.Config{
    Route: "/webhooks/cybrid", SignatureHeader: "X-Cybrid-Signature",
    SigningKey: key, RawTopic: "cybrid.webhook.raw",
    IngestTenant: sentinelTenant, ServiceUser: svcUser,
    Extract: cybridExtract,
}).WithDeduper(kvDedupe).WithLogger(sugar).WithMetrics(m)
h.Register(app)
```

## `outbound` — signed deliveries to customer URLs

Package `github.com/instruxi-io/enforcer-webhook/outbound` is the sending side.

- `Sign` / `SignMulti` — header `t=<unix>,v1=<hex HMAC-SHA256(secret, "<unix>." + body)>`;
  `SignMulti` emits one `v1=` per secret for rotation.
- `Verify(header, body, secrets, tolerance, now)` — constant-time; any `v1` against
  any secret; `ErrMalformed`, `ErrStale`, `ErrNoMatch`. Use `DefaultTolerance` (5m).
- `NewClient(Options)` — no redirects, 10s default timeout, and the destination IP is
  checked in the dialer's `Control` hook after DNS resolution (blocks loopback, RFC1918,
  link-local/metadata, CGNAT, reserved, multicast, ULA, and IPv4 hidden in IPv6).
  `AllowPrivate` is for tests only.
- `ValidateURL` — registration-time check: https, host, no userinfo, port 443, no blocked
  IP literal, no `localhost`/`*.local`/`*.internal`/`*.svc`/`*.cluster.local`.
- `testdata/vector.json` — fixed vector that other implementations (merchant SDK) must reproduce.
