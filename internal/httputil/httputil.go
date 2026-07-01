// Package httputil contains small shared helpers for HTTP request inspection,
// cookie construction scoping, and safe redirect validation. It eliminates
// duplication between the loginpage package and the service package.
package httputil

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/funinthecloud/protosource"
	"golang.org/x/net/publicsuffix"
)

// ReqHost extracts the Host header (set by the adapter even though net/http
// strips it from r.Header). Checks common casings.
func ReqHost(req protosource.Request) string {
	if h := req.Headers["host"]; h != "" {
		return h
	}
	return req.Headers["Host"]
}

// ReqHeader returns the first non-empty value for the given header,
// trying lowercase, the name as-provided, and the canonical (title-case)
// form to accommodate different header canonicalization in adapters/proxies.
func ReqHeader(req protosource.Request, name string) string {
	if v := req.Headers[strings.ToLower(name)]; v != "" {
		return v
	}
	if v := req.Headers[name]; v != "" {
		return v
	}
	if v := req.Headers[http.CanonicalHeaderKey(name)]; v != "" {
		return v
	}
	return ""
}

// IsSecure reports whether the request arrived over HTTPS, per the
// X-Forwarded-Proto header set by the API gateway / load balancer.
// Handles comma-separated values (e.g. "https,http" from chained proxies)
// taking the first (client-facing) value, and is case-insensitive.
func IsSecure(req protosource.Request) bool {
	proto := ReqHeader(req, "X-Forwarded-Proto")
	if proto == "" {
		return false
	}
	if i := strings.IndexByte(proto, ','); i != -1 {
		proto = proto[:i]
	}
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}

// RegistrableDomain extracts the eTLD+1 (registrable domain) from a host
// (with optional port). Returns "" for IPs, localhost, and unparseable hosts.
func RegistrableDomain(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	if net.ParseIP(h) != nil {
		return ""
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil {
		return ""
	}
	return etld1
}

// ParentDomain derives the cookie Domain (".eTLD+1") from a Host header
// so the cookie scopes across subdomains (using publicsuffix). Returns ""
// for IPs / localhost (browser then scopes to the exact host).
//
// Examples:
//
//	auth.drhayt.com    -> .drhayt.com
//	drhayt.com         -> .drhayt.com
//	auth.example.co.uk -> .example.co.uk
//	localhost:8080     -> ""
func ParentDomain(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}

	// Trim IPv6 brackets (SplitHostPort handles this, but the fallback path might not).
	if len(h) > 0 && h[0] == '[' {
		h = h[1:]
		if i := len(h) - 1; i >= 0 && h[i] == ']' {
			h = h[:i]
		}
	}

	if net.ParseIP(h) != nil {
		return ""
	}

	etld1, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil {
		return ""
	}

	return "." + etld1
}

// IsAllowedRedirect validates that a post-login redirect target is HTTPS
// and shares the request host's registrable domain (eTLD+1). This prevents
// open-redirect attacks to third-party sites after login or OAuth callback.
func IsAllowedRedirect(redirect, host string) bool {
	u, err := url.Parse(redirect)
	if err != nil {
		return false
	}
	if u.Scheme != "https" {
		return false
	}
	hostDomain := RegistrableDomain(host)
	if hostDomain == "" {
		return false
	}
	return RegistrableDomain(u.Host) == hostDomain
}

// CookieValue extracts a named cookie from the Cookie header.
// It normalizes via ReqHeader and parses using net/http to handle
// the full "a=1; b=2" form correctly.
func CookieValue(req protosource.Request, name string) string {
	raw := ReqHeader(req, "Cookie")
	if raw == "" {
		return ""
	}
	header := http.Header{"Cookie": {raw}}
	fakeReq := &http.Request{Header: header}
	c, err := fakeReq.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}
