package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

var (
	nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96")
	nat64LocalUse  = netip.MustParsePrefix("64:ff9b:1::/48")
	sixToFour      = netip.MustParsePrefix("2002::/16")
	v4Compatible   = netip.MustParsePrefix("::/96")
)

// ErrBlocked is returned when a destination is not publicly routable.
var ErrBlocked = errors.New("outbound: destination not publicly routable")

// IsPubliclyRoutable reports whether addr is a destination safe to deliver to.
// IPv4 embedded in IPv6 (mapped, NAT64, 6to4, v4-compatible) is judged as IPv4.
func IsPubliclyRoutable(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	switch {
	case addr.IsLoopback(), addr.IsPrivate(), addr.IsLinkLocalUnicast(),
		addr.IsLinkLocalMulticast(), addr.IsInterfaceLocalMulticast(),
		addr.IsMulticast(), addr.IsUnspecified():
		return false
	}
	if addr.Is4() {
		b := addr.As4()
		switch {
		case b[0] == 0:
			return false
		case b[0] == 100 && b[1]&0xc0 == 64:
			return false
		case b[0]&0xf0 == 240:
			return false
		}
		return true
	}
	if v4, ok := embeddedIPv4(addr); ok {
		return IsPubliclyRoutable(v4)
	}
	return !nat64LocalUse.Contains(addr)
}

func embeddedIPv4(addr netip.Addr) (netip.Addr, bool) {
	b := addr.As16()
	switch {
	case nat64WellKnown.Contains(addr), v4Compatible.Contains(addr):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixToFour.Contains(addr):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	return netip.Addr{}, false
}

// Options configures NewClient.
type Options struct {
	// Timeout is the whole-request timeout; default 10s.
	Timeout time.Duration
	// AllowPrivate disables the destination check. For tests only.
	AllowPrivate bool
}

// ErrRedirect is returned (wrapped in *url.Error) when a response redirects.
var ErrRedirect = errors.New("outbound: redirects are not followed")

// NewClient returns an http.Client that refuses redirects and checks the
// destination IP in the dialer's Control hook, after DNS resolution, so the
// address actually connected to is the one judged.
func NewClient(opts Options) *http.Client {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	if !opts.AllowPrivate {
		d.Control = func(network, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrBlocked, err)
			}
			if !IsPubliclyRoutable(ap.Addr()) {
				return fmt.Errorf("%w: %s", ErrBlocked, ap.Addr())
			}
			return nil
		}
	}
	tr := &http.Transport{
		DialContext:         func(ctx context.Context, n, a string) (net.Conn, error) { return d.DialContext(ctx, n, a) },
		TLSHandshakeTimeout: 5 * time.Second,
		DisableKeepAlives:   true,
		Proxy:               nil, // a proxy would move the dial away from the destination
	}
	return &http.Client{
		Timeout:   opts.Timeout,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return ErrRedirect
		},
	}
}

// ValidateURL checks a customer-supplied webhook URL at registration time.
func ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("outbound: invalid url: %w", err)
	}
	if u.Scheme != "https" {
		return errors.New("outbound: url must be https")
	}
	if u.User != nil {
		return errors.New("outbound: url must not contain userinfo")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return errors.New("outbound: url has no host")
	}
	if p := u.Port(); p != "" && p != "443" {
		return errors.New("outbound: url port must be 443")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if !IsPubliclyRoutable(ip) {
			return fmt.Errorf("%w: %s", ErrBlocked, ip)
		}
		return nil
	}
	if host == "localhost" {
		return errors.New("outbound: host not allowed")
	}
	for _, suf := range []string{".localhost", ".local", ".internal", ".svc", ".cluster.local"} {
		if strings.HasSuffix(host, suf) {
			return errors.New("outbound: host not allowed")
		}
	}
	return nil
}
