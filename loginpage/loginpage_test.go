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
		{"localhost:8080", ""},
		{"localhost", ""},
		{"127.0.0.1:8080", ""},
		{"auth.example.co.uk", ".co.uk"}, // simplified; good enough for our use
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

func TestHandle(t *testing.T) {
	p := New("test-issuer")
	resp := p.handle(context.Background(), protosource.Request{
		Headers: map[string]string{"host": "auth.drhayt.com"},
	})

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Headers["Content-Type"]; ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(resp.Body, "test-issuer") {
		t.Error("response body missing issuer ID")
	}
	if !strings.Contains(resp.Body, ".drhayt.com") {
		t.Error("response body missing cookie domain")
	}
}
