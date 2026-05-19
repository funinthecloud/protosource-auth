package app

import (
	"strings"
	"testing"
)

// TestNewCosmosClient covers the auth-precedence and configuration
// gates on NewCosmosClient. An integration test against a live Cosmos
// account / emulator would also validate the request path, but is
// deferred — these tests catch regressions in the wiring without
// needing a real endpoint.
func TestNewCosmosClient(t *testing.T) {
	cases := []struct {
		name        string
		cfg         Config
		wantErr     bool
		errContains string
	}{
		{
			name:    "key auth wins when CosmosKey is set",
			cfg:     Config{CosmosEndpoint: "https://acct.documents.azure.com:443/", CosmosKey: "Zm9v"},
			wantErr: false,
		},
		{
			name:    "default credential when CosmosKey empty and UseDefaultCredential true",
			cfg:     Config{CosmosEndpoint: "https://acct.documents.azure.com:443/", CosmosUseDefaultCredential: true},
			wantErr: false,
		},
		{
			name:        "no endpoint",
			cfg:         Config{CosmosKey: "Zm9v"},
			wantErr:     true,
			errContains: "CosmosEndpoint",
		},
		{
			name:        "no auth configured",
			cfg:         Config{CosmosEndpoint: "https://acct.documents.azure.com:443/"},
			wantErr:     true,
			errContains: "no Cosmos auth",
		},
		{
			name: "insecure TLS allowed for localhost",
			cfg: Config{
				CosmosEndpoint:    "https://localhost:8081/",
				CosmosKey:         "Zm9v",
				CosmosInsecureTLS: true,
			},
			wantErr: false,
		},
		{
			name: "insecure TLS allowed for 127.0.0.1",
			cfg: Config{
				CosmosEndpoint:    "https://127.0.0.1:8081/",
				CosmosKey:         "Zm9v",
				CosmosInsecureTLS: true,
			},
			wantErr: false,
		},
		{
			name: "insecure TLS refused for non-loopback host",
			cfg: Config{
				CosmosEndpoint:    "https://acct.documents.azure.com:443/",
				CosmosKey:         "Zm9v",
				CosmosInsecureTLS: true,
			},
			wantErr:     true,
			errContains: "CosmosInsecureTLS",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client, err := NewCosmosClient(&c.cfg)
			if c.wantErr {
				if err == nil {
					t.Fatalf("NewCosmosClient: want error, got nil")
				}
				if c.errContains != "" && !strings.Contains(err.Error(), c.errContains) {
					t.Errorf("NewCosmosClient: error %q does not contain %q", err.Error(), c.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewCosmosClient: %v", err)
			}
			if client == nil {
				t.Fatal("NewCosmosClient: client is nil with no error")
			}
		})
	}
}

func TestConfigNormalizeCosmosBackend(t *testing.T) {
	cases := []struct {
		name        string
		cfg         Config
		wantErr     bool
		errContains string
	}{
		{
			name: "valid with key auth",
			cfg: Config{
				IssuerIss:      "https://auth.example",
				Backend:        BackendCosmosDB,
				CosmosEndpoint: "https://acct.documents.azure.com:443/",
				CosmosKey:      "Zm9v",
			},
			wantErr: false,
		},
		{
			name: "valid with default credential",
			cfg: Config{
				IssuerIss:                  "https://auth.example",
				Backend:                    BackendCosmosDB,
				CosmosEndpoint:             "https://acct.documents.azure.com:443/",
				CosmosUseDefaultCredential: true,
			},
			wantErr: false,
		},
		{
			name: "missing endpoint",
			cfg: Config{
				IssuerIss: "https://auth.example",
				Backend:   BackendCosmosDB,
				CosmosKey: "Zm9v",
			},
			wantErr:     true,
			errContains: "CosmosEndpoint",
		},
		{
			name: "missing auth",
			cfg: Config{
				IssuerIss:      "https://auth.example",
				Backend:        BackendCosmosDB,
				CosmosEndpoint: "https://acct.documents.azure.com:443/",
			},
			wantErr:     true,
			errContains: "Cosmos auth",
		},
		{
			name: "default database applied",
			cfg: Config{
				IssuerIss:      "https://auth.example",
				Backend:        BackendCosmosDB,
				CosmosEndpoint: "https://acct.documents.azure.com:443/",
				CosmosKey:      "Zm9v",
			},
			// Validated by inspecting cfg.CosmosDatabase below.
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Normalize()
			if c.wantErr {
				if err == nil {
					t.Fatalf("Normalize: want error, got nil")
				}
				if c.errContains != "" && !strings.Contains(err.Error(), c.errContains) {
					t.Errorf("Normalize: error %q does not contain %q", err.Error(), c.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			if c.cfg.Backend == BackendCosmosDB && c.cfg.CosmosDatabase == "" {
				t.Error("Normalize: CosmosDatabase default not applied")
			}
		})
	}
}

func TestRequireLoopbackEndpoint(t *testing.T) {
	cases := []struct {
		endpoint string
		wantOK   bool
	}{
		{"https://localhost:8081/", true},
		{"https://127.0.0.1:8081/", true},
		{"https://[::1]:8081/", true},
		{"https://acct.documents.azure.com:443/", false},
		{"https://192.168.1.10:8081/", false},
		{"https://10.0.0.1:8081/", false}, // RFC 1918 private but not loopback — reject.
		{"://broken", false},
		{"https://", false},
	}
	for _, c := range cases {
		t.Run(c.endpoint, func(t *testing.T) {
			err := requireLoopbackEndpoint(c.endpoint)
			if c.wantOK && err != nil {
				t.Errorf("requireLoopbackEndpoint(%q) = %v, want nil", c.endpoint, err)
			}
			if !c.wantOK && err == nil {
				t.Errorf("requireLoopbackEndpoint(%q) = nil, want error", c.endpoint)
			}
		})
	}
}
