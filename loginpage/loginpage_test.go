package loginpage

import (
	"context"
	"strings"
	"testing"

	"github.com/funinthecloud/protosource"
)

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
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := parentDomain(tt.host)
			if got != tt.want {
				t.Errorf("parentDomain(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}

func TestHandlePage(t *testing.T) {
	p := New("test-issuer", nil)
	resp := p.handlePage(context.Background(), protosource.Request{})

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Headers["Content-Type"]; ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html; charset=utf-8", ct)
	}
	if !strings.Contains(resp.Body, "Sign In") {
		t.Error("response body missing form title")
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
		{"http", map[string]string{"x-forwarded-proto": "http"}, false},
		{"missing", map[string]string{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := protosource.Request{Headers: tt.headers}
			if got := isSecure(req); got != tt.want {
				t.Errorf("isSecure() = %v, want %v", got, tt.want)
			}
		})
	}
}
