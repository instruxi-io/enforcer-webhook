package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	topic   string
	key     string
	value   string
	headers map[string]string
	err     error
}

func (p *capturePub) Publish(_ context.Context, _, _, topic, key, value string, headers map[string]string) error {
	p.calls++
	p.topic, p.key, p.value, p.headers = topic, key, value, headers
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
