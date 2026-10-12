// Package outbound is the sending half of webhooks: sign events, verify
// signatures, and an SSRF-guarded HTTP client for POSTing to customer URLs.
package outbound

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// DefaultTolerance is the replay window Verify callers should normally use.
const DefaultTolerance = 5 * time.Minute

var (
	ErrMalformed = errors.New("outbound: malformed signature header")
	ErrStale     = errors.New("outbound: signature timestamp outside tolerance")
	ErrNoMatch   = errors.New("outbound: no signature matches")
)

func mac(secret []byte, unix int64, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(strconv.FormatInt(unix, 10)))
	m.Write([]byte{'.'})
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// Sign returns "t=<unix>,v1=<hex hmac-sha256(secret, "<unix>." + body)>".
func Sign(secret []byte, t time.Time, body []byte) string {
	return SignMulti([][]byte{secret}, t, body)
}

// SignMulti emits one v1= per secret, for secret rotation.
func SignMulti(secrets [][]byte, t time.Time, body []byte) string {
	u := t.Unix()
	parts := []string{"t=" + strconv.FormatInt(u, 10)}
	for _, s := range secrets {
		parts = append(parts, "v1="+mac(s, u, body))
	}
	return strings.Join(parts, ",")
}

// Verify checks header against body. It accepts when any v1 matches any secret
// and |now-t| <= tolerance (DefaultTolerance when tolerance <= 0).
func Verify(header string, body []byte, secrets [][]byte, tolerance time.Duration, now time.Time) error {
	if tolerance <= 0 {
		tolerance = DefaultTolerance
	}
	var (
		ts    int64
		haveT bool
		sigs  [][]byte
	)
	for _, p := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if !ok {
			return ErrMalformed
		}
		switch k {
		case "t":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || haveT {
				return ErrMalformed
			}
			ts, haveT = n, true
		case "v1":
			b, err := hex.DecodeString(v)
			if err != nil || len(b) != sha256.Size {
				return ErrMalformed
			}
			sigs = append(sigs, b)
		}
	}
	if !haveT || len(sigs) == 0 {
		return ErrMalformed
	}
	d := now.Sub(time.Unix(ts, 0))
	if d < 0 {
		d = -d
	}
	if d > tolerance {
		return ErrStale
	}
	matched := false
	for _, s := range secrets {
		want, _ := hex.DecodeString(mac(s, ts, body))
		for _, got := range sigs {
			if hmac.Equal(want, got) {
				matched = true
			}
		}
	}
	if !matched {
		return ErrNoMatch
	}
	return nil
}
