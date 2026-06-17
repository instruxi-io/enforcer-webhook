# platform

Shared Go library for the enforcer microservices (`github.com/instruxi-io/platform`),
consumed via a go.mod `replace` like `protos`.

## Packages

### `webhook`
Inbound provider-webhook ingress mechanics, shared so each owning service
(cybrid / wf / geo) supplies only the provider-specific bits instead of
re-implementing the security-sensitive core:

- `IngestHandler` — HMAC-SHA256 verification (fail-closed), body-size + clock-skew
  limits, idempotency (`Deduper`), and publishing the raw payload to a topic via a
  `Publisher`. Provider specifics (signature header, how to read the event id/type
  from the body via an `Extractor`, the topic/route) come from `Config`.
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
