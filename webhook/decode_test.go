package webhook

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression tests for the pre-auth decode path (CVE-2026-111497, the Brotli
// decoder bug): the ingress used to call fiber's c.Body(), which decompresses
// by Content-Encoding before the signature check and with no size cap.

func brotliBytes(t *testing.T, p []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := brotli.NewWriterLevel(&b, brotli.BestCompression)
	_, err := w.Write(p)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return b.Bytes()
}

func gzipBytes(t *testing.T, p []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, err := w.Write(p)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return b.Bytes()
}

// garbageBrotli returns bodies that are not valid brotli streams: random bytes
// and a truncated real stream.
func garbageBrotli(t *testing.T) map[string][]byte {
	t.Helper()
	random := make([]byte, 512)
	_, err := rand.Read(random)
	require.NoError(t, err)
	big := bytes.Repeat([]byte(`{"guid":"g","event_type":"x.y","pad":"0123456789abcdef"}`), 200)
	full := brotliBytes(t, big)
	return map[string][]byte{
		"random":    random,
		"truncated": full[:len(full)/2],
	}
}

// doEnc posts body with Content-Encoding enc and returns the status code. A
// handler panic would propagate out of app.Test; NotPanics makes that explicit.
func doEnc(t *testing.T, h *IngestHandler, sig, enc string, body []byte) int {
	t.Helper()
	app := fiber.New()
	h.Register(app)
	req := httptest.NewRequest("POST", "/webhooks/test", bytes.NewReader(body))
	if enc != "" {
		req.Header.Set("Content-Encoding", enc)
	}
	if sig != "" {
		req.Header.Set("X-Sig", sig)
	}
	code := 0
	assert.NotPanics(t, func() {
		res, err := app.Test(req, -1)
		require.NoError(t, err)
		code = res.StatusCode
	})
	return code
}

// (a) An anonymous caller with a garbage br body and a missing/bad signature is
// rejected 401 by the signature check and never gets a decoder.
func TestIngestGarbageBrotliWithoutValidSignatureIs401(t *testing.T) {
	for name, body := range garbageBrotli(t) {
		for sigName, sig := range map[string]string{
			"missing": "",
			"bogus":   strings.Repeat("ab", 32),
			"other":   sign([]byte(`{"guid":"a"}`), "secret"),
		} {
			t.Run(name+"/"+sigName, func(t *testing.T) {
				pub := &capturePub{}
				h := NewIngestHandler(pub, baseCfg())
				assert.Equal(t, fiber.StatusUnauthorized, doEnc(t, h, sig, "br", body))
				assert.Equal(t, 0, pub.calls)
			})
		}
	}
}

// The Verifier is handed the exact wire bytes — not a decoded body, and not
// fiber's decode-error string — and the request has no Content-Encoding left
// for a Verifier's own c.Body() call to act on.
func TestIngestVerifierSeesRawWireBytes(t *testing.T) {
	for name, body := range garbageBrotli(t) {
		t.Run(name, func(t *testing.T) {
			var seen []byte
			var bodyFromCtx []byte
			cfg := baseCfg()
			cfg.Verifier = func(c *fiber.Ctx, b []byte, _ string) bool {
				seen = append([]byte(nil), b...)
				bodyFromCtx = append([]byte(nil), c.Body()...)
				return false
			}
			h := NewIngestHandler(&capturePub{}, cfg)
			assert.Equal(t, fiber.StatusUnauthorized, doEnc(t, h, "x", "br", body))
			assert.Equal(t, body, seen, "verifier must see the raw wire bytes")
			assert.Equal(t, body, bodyFromCtx, "c.Body() inside a Verifier must not decode")
		})
	}
}

// A tiny br body that expands far past MaxBodySize, sent unsigned: the
// signature check rejects it (401) before anything is inflated. Before the fix
// fiber inflated it first and the size check answered 413.
func TestIngestBrotliBombWithoutSignatureIs401Not413(t *testing.T) {
	plain := []byte(`{"guid":"bomb","pad":"` + strings.Repeat("A", 4<<20) + `"}`)
	bomb := brotliBytes(t, plain)
	require.Less(t, len(bomb), DefaultMaxBodySize, "compressed bomb fits the raw limit")
	h := NewIngestHandler(&capturePub{}, baseCfg())
	assert.Equal(t, fiber.StatusUnauthorized, doEnc(t, h, "", "br", bomb))
	assert.Equal(t, fiber.StatusUnauthorized, doEnc(t, h, "deadbeef", "br", bomb))
}

// The same bomb, correctly signed, is cut off at MaxBodySize decompressed.
func TestIngestSignedBrotliBombIs413(t *testing.T) {
	plain := []byte(`{"guid":"bomb","pad":"` + strings.Repeat("A", 4<<20) + `"}`)
	bomb := brotliBytes(t, plain)
	pub := &capturePub{}
	h := NewIngestHandler(pub, baseCfg())
	assert.Equal(t, fiber.StatusRequestEntityTooLarge, doEnc(t, h, sign(bomb, "secret"), "br", bomb))
	assert.Equal(t, 0, pub.calls)
}

// A correctly signed but corrupt br body is a 400, not a panic or a 500.
func TestIngestSignedGarbageBrotliIs400(t *testing.T) {
	for name, body := range garbageBrotli(t) {
		t.Run(name, func(t *testing.T) {
			pub := &capturePub{}
			h := NewIngestHandler(pub, baseCfg())
			assert.Equal(t, fiber.StatusBadRequest, doEnc(t, h, sign(body, "secret"), "br", body))
			assert.Equal(t, 0, pub.calls)
		})
	}
}

// The raw-size limit applies to compressed bodies too.
func TestIngestRawLimitAppliesToCompressedBody(t *testing.T) {
	cfg := baseCfg()
	cfg.MaxBodySize = 32
	body := make([]byte, 64)
	h := NewIngestHandler(&capturePub{}, cfg)
	assert.Equal(t, fiber.StatusRequestEntityTooLarge, doEnc(t, h, sign(body, "secret"), "br", body))
}

// (b) A valid request signed over the bytes it sends still succeeds — plain,
// br and gzip — and compressed ones are published decoded, as before.
func TestIngestValidSignedRequestsStillSucceed(t *testing.T) {
	plain := []byte(`{"guid":"ok-1","event_type":"transfer.completed"}`)
	for enc, wire := range map[string][]byte{
		"":     plain,
		"br":   brotliBytes(t, plain),
		"gzip": gzipBytes(t, plain),
	} {
		t.Run("enc="+enc, func(t *testing.T) {
			pub := &capturePub{}
			h := NewIngestHandler(pub, baseCfg())
			assert.Equal(t, fiber.StatusOK, doEnc(t, h, sign(wire, "secret"), enc, wire))
			require.Equal(t, 1, pub.calls)
			assert.Equal(t, string(plain), pub.value)
			assert.Equal(t, "ok-1", pub.key)
		})
	}
}

func TestIngestUnsupportedEncodingIs415(t *testing.T) {
	body := []byte(`{"guid":"z"}`)
	h := NewIngestHandler(&capturePub{}, baseCfg())
	assert.Equal(t, fiber.StatusUnsupportedMediaType, doEnc(t, h, sign(body, "secret"), "zstd", body))
}

func TestDecodeBody(t *testing.T) {
	plain := []byte("hello webhook")

	out, err := DecodeBody("", plain, 100)
	require.NoError(t, err)
	assert.Equal(t, plain, out)

	out, err = DecodeBody("identity", plain, 100)
	require.NoError(t, err)
	assert.Equal(t, plain, out)

	// "gzip, br" = gzip applied first, then br; undone in reverse.
	out, err = DecodeBody("gzip, br", brotliBytes(t, gzipBytes(t, plain)), 100)
	require.NoError(t, err)
	assert.Equal(t, plain, out)

	_, err = DecodeBody("br", brotliBytes(t, plain), 5)
	assert.ErrorIs(t, err, ErrDecodedTooLarge)

	_, err = DecodeBody("gzip", []byte("not gzip"), 100)
	assert.ErrorIs(t, err, ErrMalformedEncoding)

	_, err = DecodeBody("compress", plain, 100)
	assert.ErrorIs(t, err, ErrUnsupportedEncoding)

	_, err = DecodeBody("br, br, br", plain, 100)
	assert.ErrorIs(t, err, ErrUnsupportedEncoding)
}
