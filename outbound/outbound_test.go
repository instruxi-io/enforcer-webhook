package outbound

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func TestVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Secret string
		T      int64
		Body   string
		Header string
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	got := Sign([]byte(v.Secret), time.Unix(v.T, 0), []byte(v.Body))
	if got != v.Header {
		t.Fatalf("got %s want %s", got, v.Header)
	}
	if err := Verify(v.Header, []byte(v.Body), [][]byte{[]byte(v.Secret)}, 0, time.Unix(v.T, 0)); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyNegative(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := []byte("new")
	body := []byte("hello")
	h := Sign(s, now, body)
	if err := Verify(h, body, [][]byte{s}, 0, now); err != nil {
		t.Fatal(err)
	}
	if err := Verify(h, []byte("hellp"), [][]byte{s}, 0, now); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("tampered: %v", err)
	}
	if err := Verify(h, body, [][]byte{s}, 0, now.Add(6*time.Minute)); !errors.Is(err, ErrStale) {
		t.Fatalf("stale: %v", err)
	}
	if err := Verify(h, body, [][]byte{[]byte("wrong")}, 0, now); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("wrong secret: %v", err)
	}
	for _, bad := range []string{"", "garbage", "t=1", "v1=abcd", "t=x,v1=00", "t=1700000000,v1=zz"} {
		if err := Verify(bad, body, [][]byte{s}, 0, now); !errors.Is(err, ErrMalformed) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
}

func TestVerifyRotation(t *testing.T) {
	now := time.Unix(1700000000, 0)
	body := []byte("x")
	h := SignMulti([][]byte{[]byte("new"), []byte("old")}, now, body)
	if strings.Count(h, "v1=") != 2 {
		t.Fatal(h)
	}
	for _, sec := range []string{"new", "old"} {
		if err := Verify(h, body, [][]byte{[]byte(sec)}, 0, now); err != nil {
			t.Fatalf("%s: %v", sec, err)
		}
	}
	// receiver still on old secret, sender on old only
	if err := Verify(Sign([]byte("old"), now, body), body, [][]byte{[]byte("new"), []byte("old")}, 0, now); err != nil {
		t.Fatal(err)
	}
}

var blocked = []string{
	"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
	"0.0.0.0", "0.1.2.3", "100.64.0.1", "100.127.255.254", "240.0.0.1", "255.255.255.255",
	"224.0.0.1", "::1", "::", "fe80::1", "fc00::1", "fd12::1", "ff02::1",
	"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
	"64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b:1::1",
	"2002:7f00:1::1", "2002:a9fe:a9fe::1", "::7f00:1", "::a00:1",
}

func TestPrivateHelperBlocks(t *testing.T) {
	for _, s := range blocked {
		if IsPubliclyRoutable(netip.MustParseAddr(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "64:ff9b::808:808"} {
		if !IsPubliclyRoutable(netip.MustParseAddr(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
}

// Actual dials: Control fires before connect, so nothing leaves the host.
func TestPrivateDialRefused(t *testing.T) {
	c := NewClient(Options{Timeout: 2 * time.Second})
	for _, s := range blocked {
		host := s
		if strings.Contains(s, ":") {
			host = "[" + s + "]"
		}
		_, err := c.Get("http://" + host + ":8080/")
		if err == nil || !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: want ErrBlocked, got %v", s, err)
		}
	}
}

func TestMetadataDialRefused(t *testing.T) {
	c := NewClient(Options{Timeout: 2 * time.Second})
	_, err := c.Get("http://169.254.169.254/latest/meta-data/")
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("got %v", err)
	}
}

func TestMappedDialRefused(t *testing.T) {
	c := NewClient(Options{Timeout: 2 * time.Second})
	_, err := c.Get("http://[::ffff:127.0.0.1]:1/")
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("got %v", err)
	}
}

func TestRedirectRefused(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, "https://example.com/", http.StatusFound)
	}))
	defer srv.Close()
	c := NewClient(Options{AllowPrivate: true})
	resp, err := c.Post(srv.URL, "application/json", strings.NewReader("{}"))
	if err == nil {
		resp.Body.Close()
		t.Fatal("redirect followed")
	}
	if !errors.Is(err, ErrRedirect) {
		t.Fatalf("got %v", err)
	}
	if hits != 1 {
		t.Fatalf("hits=%d", hits)
	}
}

func TestAllowPrivateReachesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	if resp, err := NewClient(Options{AllowPrivate: true}).Get(srv.URL); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
	}
	if _, err := NewClient(Options{}).Get(srv.URL); !errors.Is(err, ErrBlocked) {
		t.Fatalf("default client reached loopback: %v", err)
	}
}

func TestDefaultTimeout(t *testing.T) {
	if NewClient(Options{}).Timeout != 10*time.Second {
		t.Fatal("timeout")
	}
}

func TestValidateURL(t *testing.T) {
	ok := []string{"https://example.com/hook", "https://example.com:443/x", "https://8.8.8.8/x"}
	bad := []string{
		"http://example.com/", "ftp://example.com/", "https://", "https://u:p@example.com/",
		"https://example.com:8443/", "https://127.0.0.1/", "https://[::1]/", "https://169.254.169.254/",
		"https://[::ffff:10.0.0.1]/", "https://localhost/", "https://foo.local/", "https://a.internal/",
		"https://a.svc/", "https://a.b.cluster.local/", "https://LOCALHOST./", "://bad",
	}
	for _, u := range ok {
		if err := ValidateURL(u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	for _, u := range bad {
		if ValidateURL(u) == nil {
			t.Errorf("%s accepted", u)
		}
	}
}
