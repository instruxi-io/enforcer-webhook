// Package webhook is the shared inbound-provider-webhook ingress for the
// enforcer services. The owning product service (cybrid, wf, geo) terminates
// its providers' webhooks; this package centralizes the cross-cutting
// mechanics — HMAC verification, body-size + clock-skew limits, idempotency,
// and publishing the raw payload to a topic — so each service supplies only
// the provider-specific bits (signature header, how to read the event id/type
// from the body, the topic) rather than re-implementing the security-sensitive
// core. enforcer-mb stays a pure bus; this is the edge.
package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// ErrUnknownTenant tells the ingress to reject a webhook as unauthorized (401):
// the tenant has no configured signing key. Any OTHER error a KeyResolver
// returns is treated as transient — the ingress answers 503 so the provider
// retries rather than dead-lettering when the secret store is briefly down.
var ErrUnknownTenant = errors.New("unknown or unconfigured tenant")

// Defaults: webhook bodies are tiny; anything larger is almost certainly an
// attack or misconfiguration. Payloads older than the skew are rejected.
const (
	DefaultMaxBodySize  = 64 * 1024
	DefaultMaxClockSkew = 5 * time.Minute
)

// Publisher is the subset of the message-bus client the handler needs.
type Publisher interface {
	Publish(ctx context.Context, tenantID, userID, topic, key, value string, headers map[string]string) error
}

// Deduper records whether an event id has been seen, atomically: firstSeen=true
// the first time, false on duplicates (replay protection). nil disables dedupe.
type Deduper func(ctx context.Context, eventID string) (firstSeen bool, err error)

// Logger is the minimal structured-logging surface (zap.SugaredLogger satisfies
// it directly; slog adapts trivially). nil disables logging.
type Logger interface {
	Infow(msg string, keysAndValues ...any)
	Warnw(msg string, keysAndValues ...any)
	Errorw(msg string, keysAndValues ...any)
}

// Metrics is an optional counter sink. nil disables metrics.
type Metrics interface {
	Ingested(resource string)
	Duplicate()
}

// Event is what ingest needs from a raw body: the dedup/partition key, the
// event type (carried as an envelope header), and an optional RFC3339 timestamp
// for freshness. The full payload is parsed downstream by the consumer.
type Event struct {
	ID        string
	Type      string
	CreatedAt string // RFC3339; empty skips the freshness check
}

// Extractor pulls the Event fields from a provider's raw body.
type Extractor func(body []byte) (Event, error)

// KeyResolver returns the HMAC signing key for a tenant (central, multi-tenant
// ingress reads the tenant from the URL and looks up its per-tenant secret).
// A nil error with a non-empty key authorizes verification. Return
// ErrUnknownTenant to reject (401); any other error is treated as transient
// and answered 503 so the provider retries.
type KeyResolver func(tenantID string) (signingKey string, err error)

// Verifier validates a request's signature against the resolved key. When set,
// it replaces the default HMAC-SHA256-of-body check, letting providers with
// non-trivial schemes (Coinbase/Hook0's "t=…,h=…,v1=…", Stripe, svix) plug in.
// It receives the full Ctx so it can read whichever headers the provider signs.
// Return false to reject (the handler answers 401). The fail-closed empty-key
// guard still runs before this is called.
type Verifier func(c *fiber.Ctx, body []byte, key string) bool

// Config is the provider-specific ingress configuration.
type Config struct {
	Route           string // mount path, e.g. "/webhooks/cybrid" or "/webhooks/cdp/:tenant_id/routed"
	SignatureHeader string // e.g. "X-Cybrid-Signature"
	SigningKey      string // single-tenant HMAC key; empty + !AllowUnsigned = fail closed
	AllowUnsigned   bool   // local/mock only; production must leave false
	RawTopic        string // topic the raw payload is published to
	IngestTenant    string // single-tenant: sentinel tenant stamped on the publish
	ServiceUser     string // service principal recorded on the publish
	Extract         Extractor
	MaxBodySize     int           // 0 => DefaultMaxBodySize
	MaxClockSkew    time.Duration // 0 => DefaultMaxClockSkew

	// Verifier overrides the default HMAC-SHA256-of-body signature check for
	// providers with custom signing schemes. nil => default check on
	// SignatureHeader. The fail-closed empty-key guard runs regardless.
	Verifier Verifier

	// Multi-tenant (central ingress): when KeyResolver is set, the tenant is
	// read from the URL path param TenantParam, its signing key resolved per
	// request, and the published event is stamped with that tenant (IngestTenant
	// is ignored). The Route must contain :<TenantParam>.
	KeyResolver KeyResolver
	TenantParam string // path param name; "" => "tenant_id"
}

// IngestHandler receives provider webhooks and forwards them to the bus.
type IngestHandler struct {
	cfg     Config
	pub     Publisher
	dedupe  Deduper
	log     Logger
	metrics Metrics
}

// NewIngestHandler builds the handler. Attach optional collaborators with the
// With* methods.
func NewIngestHandler(pub Publisher, cfg Config) *IngestHandler {
	if cfg.MaxBodySize <= 0 {
		cfg.MaxBodySize = DefaultMaxBodySize
	}
	if cfg.MaxClockSkew <= 0 {
		cfg.MaxClockSkew = DefaultMaxClockSkew
	}
	return &IngestHandler{cfg: cfg, pub: pub}
}

func (h *IngestHandler) WithDeduper(d Deduper) *IngestHandler { h.dedupe = d; return h }
func (h *IngestHandler) WithLogger(l Logger) *IngestHandler   { h.log = l; return h }
func (h *IngestHandler) WithMetrics(m Metrics) *IngestHandler { h.metrics = m; return h }

// Register mounts the (unauthenticated, signature-verified) webhook route.
func (h *IngestHandler) Register(r fiber.Router) { r.Post(h.cfg.Route, h.handle) }

func (h *IngestHandler) tenantParam() string {
	if h.cfg.TenantParam != "" {
		return h.cfg.TenantParam
	}
	return "tenant_id"
}

func (h *IngestHandler) handle(c *fiber.Ctx) error {
	body := c.Body()
	if len(body) > h.cfg.MaxBodySize {
		return c.Status(fiber.StatusRequestEntityTooLarge).JSON(fiber.Map{"error": "payload_too_large"})
	}

	// Resolve the publish tenant + signing key. Central (multi-tenant) ingress
	// reads the tenant from the URL and looks up its per-tenant key; single-
	// tenant ingress uses the static key + sentinel tenant.
	tenant := h.cfg.IngestTenant
	signingKey := h.cfg.SigningKey
	if h.cfg.KeyResolver != nil {
		tenant = c.Params(h.tenantParam())
		if tenant == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing_tenant"})
		}
		key, err := h.cfg.KeyResolver(tenant)
		switch {
		case errors.Is(err, ErrUnknownTenant):
			h.warnw("webhook for unknown/unconfigured tenant", "tenant_id", tenant)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unknown_tenant"})
		case err != nil:
			// Transient (secret store down): 503 so the provider retries rather
			// than dead-lettering an otherwise-valid webhook.
			h.errorw("webhook secret resolver unavailable; asking for retry", "tenant_id", tenant, "err", err)
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "resolver_unavailable"})
		case key == "":
			h.warnw("webhook resolver returned empty key", "tenant_id", tenant)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unknown_tenant"})
		}
		signingKey = key
	}

	// Signature check. Fails closed: with no key configured we reject unless
	// AllowUnsigned (local/mock) is set. A custom Verifier (e.g. Hook0's
	// t=,h=,v1= scheme) replaces the default HMAC-SHA256-of-body check.
	signature := c.Get(h.cfg.SignatureHeader)
	if !h.cfg.AllowUnsigned {
		if signingKey == "" {
			h.errorw("SECURITY: webhook signing key not configured - rejecting", "tenant_id", tenant)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid_signature"})
		}
		valid := ValidSignature(signature, body, signingKey)
		if h.cfg.Verifier != nil {
			valid = h.cfg.Verifier(c, body, signingKey)
		}
		if !valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid_signature"})
		}
	}

	ev, err := h.cfg.Extract(body)
	if err != nil || ev.ID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_payload"})
	}

	// Freshness (best-effort: only when a parseable timestamp is present).
	if ev.CreatedAt != "" {
		if ts, perr := time.Parse(time.RFC3339, ev.CreatedAt); perr == nil && time.Since(ts) > h.cfg.MaxClockSkew {
			h.warnw("rejecting stale webhook", "event_id", ev.ID, "age", time.Since(ts).String())
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "stale_webhook"})
		}
	}

	// Replay protection: first delivery wins; duplicates are acked (200) but not
	// re-published. Fails open to availability.
	if h.dedupe != nil {
		firstSeen, derr := h.dedupe(c.Context(), ev.ID)
		if derr != nil {
			h.warnw("dedupe check failed; processing anyway", "event_id", ev.ID, "err", derr)
		} else if !firstSeen {
			h.duplicate()
			h.infow("duplicate webhook ignored", "event_id", ev.ID)
			return c.SendStatus(fiber.StatusOK)
		}
	}

	headers := map[string]string{"event_type": ev.Type}
	if signature != "" {
		headers["x-webhook-signature"] = signature // carried for audit/replay fidelity
	}
	if err := h.pub.Publish(c.Context(), tenant, h.cfg.ServiceUser, h.cfg.RawTopic, ev.ID, string(body), headers); err != nil {
		// 500 so the provider retries; we must not drop a webhook.
		h.errorw("failed to publish raw webhook", "event_id", ev.ID, "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "publish_failed"})
	}
	resource, _, _ := strings.Cut(ev.Type, ".")
	if resource == "" {
		resource = "unknown"
	}
	h.ingested(resource)
	h.infow("webhook accepted", "event_id", ev.ID, "event_type", ev.Type)
	return c.SendStatus(fiber.StatusOK)
}

// ValidSignature checks an HMAC-SHA256 hex digest (tolerating a "sha256="
// prefix) against the body in constant time.
func ValidSignature(provided string, body []byte, key string) bool {
	if provided == "" {
		return false
	}
	provided = strings.TrimPrefix(provided, "sha256=")
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(provided))
}

// nil-safe logging/metrics shims.
func (h *IngestHandler) infow(m string, kv ...any) {
	if h.log != nil {
		h.log.Infow(m, kv...)
	}
}
func (h *IngestHandler) warnw(m string, kv ...any) {
	if h.log != nil {
		h.log.Warnw(m, kv...)
	}
}
func (h *IngestHandler) errorw(m string, kv ...any) {
	if h.log != nil {
		h.log.Errorw(m, kv...)
	}
}
func (h *IngestHandler) ingested(resource string) {
	if h.metrics != nil {
		h.metrics.Ingested(resource)
	}
}
func (h *IngestHandler) duplicate() {
	if h.metrics != nil {
		h.metrics.Duplicate()
	}
}
