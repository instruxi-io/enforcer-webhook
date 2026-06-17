package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type capturePub struct {
	calls   int
	tenant  string
	topic   string
	key     string
	value   string
	headers map[string]string
	err     error
}

func (p *capturePub) Publish(_ context.Context, tenant, _, topic, key, value string, headers map[string]string) error {
	p.calls++
	p.tenant, p.topic, p.key, p.value, p.headers = tenant, topic, key, value, headers
	return p.err
}

// jsonExtract reads {guid, event_type, created_at}.
func jsonExtract(body []byte) (Event, error) {
	var v struct {
		GUID      string `json:"guid"`
		EventType string `json:"event_type"`
		CreatedAt string `json:"created_at"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return Event{}, err
	}
	return Event{ID: v.GUID, Type: v.EventType, CreatedAt: v.CreatedAt}, nil
}

func baseCfg() Config {
	return Config{
		Route: "/webhooks/test", SignatureHeader: "X-Sig", SigningKey: "secret",
		RawTopic: "test.webhook.raw", IngestTenant: "t-ingest", ServiceUser: "svc",
		Extract: jsonExtract,
	}
}

func sign(body []byte, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func do(t *testing.T, h *IngestHandler, sig, body string) *httptest.ResponseRecorder {
	t.Helper()
	app := fiber.New()
	h.Register(app)
	req := httptest.NewRequest("POST", "/webhooks/test", strings.NewReader(body))
	if sig != "" {
		req.Header.Set("X-Sig", sig)
	}
	res, err := app.Test(req, -1)
	require.NoError(t, err)
	rec := httptest.NewRecorder()
	rec.Code = res.StatusCode
	return rec
}

func TestIngestValidSignaturePublishes(t *testing.T) {
	pub := &capturePub{}
	h := NewIngestHandler(pub, baseCfg())
	body := `{"guid":"evt-1","event_type":"account.created"}`
	rec := do(t, h, sign([]byte(body), "secret"), body)
	assert.Equal(t, fiber.StatusOK, rec.Code)
	require.Equal(t, 1, pub.calls)
	assert.Equal(t, "test.webhook.raw", pub.topic)
	assert.Equal(t, "evt-1", pub.key)
	assert.Equal(t, "account.created", pub.headers["event_type"])
}

// doPath drives a multi-tenant route whose path carries :tenant_id.
func doPath(t *testing.T, h *IngestHandler, route, url, sig, body string) (*httptest.ResponseRecorder, *fiber.Ctx) {
	t.Helper()
	app := fiber.New()
	app.Post(route, h.handle)
	req := httptest.NewRequest("POST", url, strings.NewReader(body))
	if sig != "" {
		req.Header.Set("X-Sig", sig)
	}
	res, err := app.Test(req, -1)
	require.NoError(t, err)
	rec := httptest.NewRecorder()
	rec.Code = res.StatusCode
	return rec, nil
}

func multiTenantCfg(keys map[string]string) Config {
	cfg := baseCfg()
	cfg.Route = "/webhooks/cdp/:tenant_id/routed"
	cfg.IngestTenant = "" // ignored in multi-tenant mode
	cfg.KeyResolver = func(tid string) (string, error) {
		k, ok := keys[tid]
		if !ok {
			return "", ErrUnknownTenant
		}
		return k, nil
	}
	return cfg
}

func TestIngestMultiTenantResolvesKeyAndStampsTenant(t *testing.T) {
	pub := &capturePub{}
	h := NewIngestHandler(pub, multiTenantCfg(map[string]string{"acme": "acme-secret"}))
	body := `{"guid":"evt-7","event_type":"router.routed"}`
	rec, _ := doPath(t, h, "/webhooks/cdp/:tenant_id/routed", "/webhooks/cdp/acme/routed",
		sign([]byte(body), "acme-secret"), body)
	assert.Equal(t, fiber.StatusOK, rec.Code)
	require.Equal(t, 1, pub.calls)
	assert.Equal(t, "acme", pub.tenant, "publish is stamped with the URL tenant")
}

func TestIngestMultiTenantRejectsUnknownTenant(t *testing.T) {
	pub := &capturePub{}
	h := NewIngestHandler(pub, multiTenantCfg(map[string]string{"acme": "acme-secret"}))
	body := `{"guid":"e","event_type":"x"}`
	rec, _ := doPath(t, h, "/webhooks/cdp/:tenant_id/routed", "/webhooks/cdp/ghost/routed",
		sign([]byte(body), "acme-secret"), body)
	assert.Equal(t, fiber.StatusUnauthorized, rec.Code)
	assert.Zero(t, pub.calls)
}

func TestIngestMultiTenantTransientResolverIs503(t *testing.T) {
	// A transient resolver error (secret store down) must be 503 so the
	// provider retries — not 401, which would dead-letter a valid webhook.
	pub := &capturePub{}
	cfg := baseCfg()
	cfg.Route = "/webhooks/cdp/:tenant_id/routed"
	cfg.KeyResolver = func(string) (string, error) { return "", errors.New("v3 unreachable") }
	h := NewIngestHandler(pub, cfg)
	body := `{"guid":"e","event_type":"x"}`
	rec, _ := doPath(t, h, "/webhooks/cdp/:tenant_id/routed", "/webhooks/cdp/acme/routed",
		sign([]byte(body), "whatever"), body)
	assert.Equal(t, fiber.StatusServiceUnavailable, rec.Code)
	assert.Zero(t, pub.calls)
}

func TestIngestMultiTenantUsesPerTenantKey(t *testing.T) {
	// A signature valid for tenant A must not be accepted on tenant B's path.
	pub := &capturePub{}
	h := NewIngestHandler(pub, multiTenantCfg(map[string]string{"a": "key-a", "b": "key-b"}))
	body := `{"guid":"e","event_type":"x"}`
	rec, _ := doPath(t, h, "/webhooks/cdp/:tenant_id/routed", "/webhooks/cdp/b/routed",
		sign([]byte(body), "key-a"), body)
	assert.Equal(t, fiber.StatusUnauthorized, rec.Code)
	assert.Zero(t, pub.calls)
}

func TestIngestCustomVerifierReplacesDefault(t *testing.T) {
	// A custom verifier accepts on a provider-specific header the default
	// HMAC-of-body check would never pass.
	pub := &capturePub{}
	cfg := baseCfg()
	cfg.SignatureHeader = "X-Hook0-Signature"
	cfg.Verifier = func(c *fiber.Ctx, body []byte, key string) bool {
		return c.Get("X-Hook0-Signature") == "scheme-ok" && key == "secret"
	}
	h := NewIngestHandler(pub, cfg)

	app := fiber.New()
	h.Register(app)
	body := `{"guid":"evt-9","event_type":"router.routed"}`
	req := httptest.NewRequest("POST", "/webhooks/test", strings.NewReader(body))
	req.Header.Set("X-Hook0-Signature", "scheme-ok")
	res, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, res.StatusCode)
	require.Equal(t, 1, pub.calls)

	// Same handler, wrong scheme value -> rejected, not published.
	pub2 := &capturePub{}
	cfg.Verifier = func(c *fiber.Ctx, body []byte, key string) bool { return false }
	h2 := NewIngestHandler(pub2, cfg)
	app2 := fiber.New()
	h2.Register(app2)
	req2 := httptest.NewRequest("POST", "/webhooks/test", strings.NewReader(body))
	req2.Header.Set("X-Hook0-Signature", "scheme-ok")
	res2, err := app2.Test(req2, -1)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, res2.StatusCode)
	assert.Zero(t, pub2.calls)
}

func TestIngestCustomVerifierStillFailsClosedWithoutKey(t *testing.T) {
	// Verifier must not run when no key is configured (fail-closed guard).
	called := false
	cfg := baseCfg()
	cfg.SigningKey = ""
	cfg.Verifier = func(c *fiber.Ctx, body []byte, key string) bool { called = true; return true }
	h := NewIngestHandler(&capturePub{}, cfg)
	rec := do(t, h, "", `{"guid":"e","event_type":"x"}`)
	assert.Equal(t, fiber.StatusUnauthorized, rec.Code)
	assert.False(t, called, "verifier must not run without a configured key")
}

func TestIngestRejectsBadSignature(t *testing.T) {
	pub := &capturePub{}
	h := NewIngestHandler(pub, baseCfg())
	body := `{"guid":"evt-1","event_type":"x"}`
	rec := do(t, h, "deadbeef", body)
	assert.Equal(t, fiber.StatusUnauthorized, rec.Code)
	assert.Zero(t, pub.calls, "unverified webhook is never published")
}

func TestIngestFailsClosedWithoutKey(t *testing.T) {
	cfg := baseCfg()
	cfg.SigningKey = "" // no key, not allowing unsigned
	h := NewIngestHandler(&capturePub{}, cfg)
	rec := do(t, h, "", `{"guid":"e","event_type":"x"}`)
	assert.Equal(t, fiber.StatusUnauthorized, rec.Code)
}

func TestIngestAllowUnsignedSkipsVerification(t *testing.T) {
	cfg := baseCfg()
	cfg.SigningKey = ""
	cfg.AllowUnsigned = true
	pub := &capturePub{}
	h := NewIngestHandler(pub, cfg)
	rec := do(t, h, "", `{"guid":"e","event_type":"x"}`)
	assert.Equal(t, fiber.StatusOK, rec.Code)
	assert.Equal(t, 1, pub.calls)
}

func TestIngestRejectsBadPayload(t *testing.T) {
	h := NewIngestHandler(&capturePub{}, baseCfg())
	body := `{"event_type":"x"}` // no guid -> empty ID
	rec := do(t, h, sign([]byte(body), "secret"), body)
	assert.Equal(t, fiber.StatusBadRequest, rec.Code)
}

func TestIngestRejectsStale(t *testing.T) {
	old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	body := `{"guid":"e","event_type":"x","created_at":"` + old + `"}`
	h := NewIngestHandler(&capturePub{}, baseCfg())
	rec := do(t, h, sign([]byte(body), "secret"), body)
	assert.Equal(t, fiber.StatusBadRequest, rec.Code)
}

func TestIngestDedupeIgnoresDuplicate(t *testing.T) {
	pub := &capturePub{}
	seen := map[string]bool{}
	h := NewIngestHandler(pub, baseCfg()).WithDeduper(func(_ context.Context, id string) (bool, error) {
		if seen[id] {
			return false, nil
		}
		seen[id] = true
		return true, nil
	})
	body := `{"guid":"dup","event_type":"x"}`
	s := sign([]byte(body), "secret")
	assert.Equal(t, fiber.StatusOK, do(t, h, s, body).Code)
	assert.Equal(t, fiber.StatusOK, do(t, h, s, body).Code)
	assert.Equal(t, 1, pub.calls, "duplicate is acked but not re-published")
}

func TestIngestTooLarge(t *testing.T) {
	cfg := baseCfg()
	cfg.MaxBodySize = 16
	h := NewIngestHandler(&capturePub{}, cfg)
	body := `{"guid":"e","event_type":"some.long.event.type.value"}`
	rec := do(t, h, sign([]byte(body), "secret"), body)
	assert.Equal(t, fiber.StatusRequestEntityTooLarge, rec.Code)
}

func TestValidSignature(t *testing.T) {
	body := []byte("hello")
	assert.True(t, ValidSignature(sign(body, "k"), body, "k"))
	assert.True(t, ValidSignature("sha256="+sign(body, "k"), body, "k"), "tolerates sha256= prefix")
	assert.False(t, ValidSignature("", body, "k"))
	assert.False(t, ValidSignature(sign(body, "wrong"), body, "k"))
}

func TestReplayRepublishes(t *testing.T) {
	pub := &capturePub{}
	require.NoError(t, Replay(context.Background(), pub, "t", "svc", "topic.raw", "evt-9", `{"x":1}`))
	assert.Equal(t, 1, pub.calls)
	assert.Equal(t, "topic.raw", pub.topic)
	assert.Equal(t, "evt-9", pub.key)
	assert.Equal(t, "true", pub.headers["x-webhook-replay"])
}
