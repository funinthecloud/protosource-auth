package httputil

import (
	"net/http"
	"testing"

	"github.com/funinthecloud/protosource"
)

func TestReqHost(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{"lowercase", map[string]string{"host": "auth.example.com"}, "auth.example.com"},
		{"titlecase", map[string]string{"Host": "todo.example.com"}, "todo.example.com"},
		{"lowercase preferred", map[string]string{"host": "low.example.com", "Host": "high.example.com"}, "low.example.com"},
		{"missing", map[string]string{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := protosource.Request{Headers: tt.headers}
			if got := ReqHost(req); got != tt.want {
				t.Errorf("ReqHost() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReqHeader(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		key     string
		want    string
	}{
		{"lowercase hit", map[string]string{"x-forwarded-proto": "https"}, "X-Forwarded-Proto", "https"},
		{"titlecase hit", map[string]string{"X-Forwarded-Proto": "https"}, "x-forwarded-proto", "https"},
		{"lowercase first", map[string]string{"cookie": "a=1", "Cookie": "b=2"}, "Cookie", "a=1"},
		{"missing", map[string]string{"host": "x"}, "X-Forwarded-Proto", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := protosource.Request{Headers: tt.headers}
			if got := ReqHeader(req, tt.key); got != tt.want {
				t.Errorf("ReqHeader(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestIsSecure(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{"https lowercase", map[string]string{"x-forwarded-proto": "https"}, true},
		{"https titlecase", map[string]string{"X-Forwarded-Proto": "https"}, true},
		{"https uppercase", map[string]string{"x-forwarded-proto": "HTTPS"}, true},
		{"comma separated https first", map[string]string{"x-forwarded-proto": "https,http"}, true},
		{"comma separated with spaces", map[string]string{"x-forwarded-proto": "https , http"}, true},
		{"comma separated http first", map[string]string{"x-forwarded-proto": "http,https"}, false},
		{"http", map[string]string{"x-forwarded-proto": "http"}, false},
		{"missing", map[string]string{}, false},
		{"empty value", map[string]string{"x-forwarded-proto": ""}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := protosource.Request{Headers: tt.headers}
			if got := IsSecure(req); got != tt.want {
				t.Errorf("IsSecure() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRegistrableDomain(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"auth.drhayt.com", "drhayt.com"},
		{"drhayt.com", "drhayt.com"},
		{"sub.auth.drhayt.com:443", "drhayt.com"},
		{"auth.example.co.uk", "example.co.uk"},
		{"localhost:8080", ""},
		{"localhost", ""},
		{"127.0.0.1:8080", ""},
		{"127.0.0.1", ""},
		{"[::1]:8080", ""},
		{"[::1]", ""},
		{"192.168.1.1", ""},
		{"bad:port:too:many", ""},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := RegistrableDomain(tt.host); got != tt.want {
				t.Errorf("RegistrableDomain(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}

func TestParentDomain(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"auth.drhayt.com", ".drhayt.com"},
		{"drhayt.com", ".drhayt.com"},
		{"sub.auth.drhayt.com", ".drhayt.com"},
		{"auth.example.co.uk", ".example.co.uk"},
		{"example.co.uk", ".example.co.uk"},
		{"localhost:8080", ""},
		{"localhost", ""},
		{"127.0.0.1:8080", ""},
		{"127.0.0.1", ""},
		{"[::1]:8080", ""},
		{"[::1]", ""},
		{"192.168.0.1", ""},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := ParentDomain(tt.host); got != tt.want {
				t.Errorf("ParentDomain(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}

func TestIsAllowedRedirect(t *testing.T) {
	tests := []struct {
		name     string
		redirect string
		host     string
		want     bool
	}{
		{"same eTLD+1", "https://auth-admin.drhayt.com/", "auth.drhayt.com", true},
		{"bare domain", "https://drhayt.com/admin", "auth.drhayt.com", true},
		{"cross domain", "https://evil.com/", "auth.drhayt.com", false},
		{"http not allowed", "http://auth-admin.drhayt.com/", "auth.drhayt.com", false},
		{"invalid URL", "://bad", "auth.drhayt.com", false},
		{"localhost host", "https://localhost/", "localhost:8080", false},
		{"ip host", "https://192.168.1.1/", "192.168.1.1", false},
		{"subdomain sibling", "https://todo.drhayt.com/app", "auth.drhayt.com", true},
		{"different port ok if domain match", "https://app.drhayt.com:8443/", "auth.drhayt.com", true},
		{"empty redirect", "", "auth.drhayt.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAllowedRedirect(tt.redirect, tt.host); got != tt.want {
				t.Errorf("IsAllowedRedirect(%q, %q) = %v, want %v", tt.redirect, tt.host, got, tt.want)
			}
		})
	}
}

func TestCookieValue(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		cookie  string
		want    string
	}{
		{"lowercase header", map[string]string{"cookie": "shadow=abc123; other=xyz"}, "shadow", "abc123"},
		{"titlecase header", map[string]string{"Cookie": "shadow=def456"}, "shadow", "def456"},
		{"missing cookie", map[string]string{"cookie": "other=xyz"}, "shadow", ""},
		{"no header", map[string]string{}, "shadow", ""},
		{"multiple cookies", map[string]string{"Cookie": "a=1; shadow=val; b=2"}, "shadow", "val"},
		{"url encoded value", map[string]string{"cookie": "shadow=val%3Due"}, "shadow", "val%3Due"}, // raw value as parsed
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := protosource.Request{Headers: tt.headers}
			if got := CookieValue(req, tt.cookie); got != tt.want {
				t.Errorf("CookieValue(%q) = %q, want %q", tt.cookie, got, tt.want)
			}
		})
	}
}

// Verify CookieValue roundtrips with net/http Set-Cookie style.
func TestCookieValue_RoundTrip(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "shadow=rt123; Path=/; HttpOnly")
	// We simulate incoming Cookie header as would be sent back.
	req := protosource.Request{Headers: map[string]string{"Cookie": "shadow=rt123; Path=/"}}
	if got := CookieValue(req, "shadow"); got != "rt123" {
		t.Errorf("CookieValue roundtrip = %q, want %q", got, "rt123")
	}
}
