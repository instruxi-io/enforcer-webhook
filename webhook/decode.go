package webhook

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
)

// Errors DecodeBody returns. The ingress maps them to 4xx responses; none of
// them is a panic, whatever the bytes.
var (
	// ErrDecodedTooLarge: the decompressed body is bigger than the limit (a
	// small compressed body can expand by orders of magnitude).
	ErrDecodedTooLarge = errors.New("webhook: decoded body exceeds size limit")
	// ErrUnsupportedEncoding: a Content-Encoding the ingress does not decode.
	ErrUnsupportedEncoding = errors.New("webhook: unsupported content-encoding")
	// ErrMalformedEncoding: the body is not a valid stream for its declared
	// Content-Encoding (truncated, corrupt, or a decoder that panicked).
	ErrMalformedEncoding = errors.New("webhook: malformed encoded body")
)

// maxStackedEncodings bounds how many Content-Encoding layers we will undo.
// Real providers send zero; anything deeper than two is not a webhook.
const maxStackedEncodings = 2

// DecodeBody undoes a request's Content-Encoding (gzip, br, deflate; identity
// and empty are no-ops) with an explicit cap on the DECOMPRESSED size.
//
// It exists so the ingress never has to call fiber's c.Body(), which decodes
// the body automatically and without a size cap the moment it is read — before
// any signature check, which put the Brotli decoder (CVE-2026-111497) and
// unbounded decompression in front of anonymous callers. Callers must verify
// the signature over the raw wire bytes FIRST and only then call this.
//
// Stacked encodings ("gzip, br") are undone in reverse order of listing, per
// RFC 9110 §8.4. A decoder panic is recovered and reported as
// ErrMalformedEncoding so a decoder bug can never take the process down.
func DecodeBody(contentEncoding string, raw []byte, maxSize int) (out []byte, err error) {
	var encs []string
	for _, e := range strings.Split(contentEncoding, ",") {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" || e == "identity" {
			continue
		}
		encs = append(encs, e)
	}
	if len(encs) == 0 {
		return raw, nil
	}
	if len(encs) > maxStackedEncodings {
		return nil, fmt.Errorf("%w: %d stacked encodings", ErrUnsupportedEncoding, len(encs))
	}

	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("%w: decoder panic: %v", ErrMalformedEncoding, r)
		}
	}()

	body := raw
	for i := len(encs) - 1; i >= 0; i-- {
		var r io.Reader
		switch encs[i] {
		case "br":
			r = brotli.NewReader(bytes.NewReader(body))
		case "gzip", "x-gzip":
			gr, gerr := gzip.NewReader(bytes.NewReader(body))
			if gerr != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedEncoding, gerr)
			}
			defer gr.Close()
			r = gr
		case "deflate":
			// HTTP "deflate" is the zlib format (RFC 9110 §8.4.1.2), which is
			// also what fasthttp's BodyInflate decodes.
			zr, zerr := zlib.NewReader(bytes.NewReader(body))
			if zerr != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedEncoding, zerr)
			}
			defer zr.Close()
			r = zr
		default:
			return nil, fmt.Errorf("%w: %q", ErrUnsupportedEncoding, encs[i])
		}
		if body, err = readCapped(r, maxSize); err != nil {
			return nil, err
		}
	}
	return body, nil
}

// readCapped reads at most maxSize bytes; one byte more means the stream is
// over the limit, and we stop decoding there rather than inflating the rest.
func readCapped(r io.Reader, maxSize int) ([]byte, error) {
	buf, err := io.ReadAll(io.LimitReader(r, int64(maxSize)+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedEncoding, err)
	}
	if len(buf) > maxSize {
		return nil, ErrDecodedTooLarge
	}
	return buf, nil
}
