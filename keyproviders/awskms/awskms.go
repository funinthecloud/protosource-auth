// Package awskms implements [keyproviders.KeyProvider] using AWS KMS
// direct encryption. Signing key private material (~32-64 bytes for
// Ed25519/RSA seeds) is well under KMS's 4 KiB plaintext limit, so no
// envelope encryption is needed.
//
// The masterKeyRef parameter is the KMS key ARN or alias
// (e.g. "arn:aws:kms:us-east-1:123456:key/abc-def" or
// "alias/protosource-auth-signing").
package awskms

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/funinthecloud/protosource-auth/keyproviders"
)

// KMSClient is the narrow interface the Provider needs from the AWS KMS
// SDK, allowing tests to supply a mock without a real endpoint.
type KMSClient interface {
	Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// Provider wraps and unwraps signing-key material using AWS KMS.
type Provider struct {
	client KMSClient
}

// New constructs a Provider backed by the given KMS client.
func New(client KMSClient) *Provider {
	if client == nil {
		panic("awskms.New: client must not be nil")
	}
	return &Provider{client: client}
}

// Name returns "awskms", persisted on the Key aggregate so the resolver
// knows which provider to route Decrypt through.
func (p *Provider) Name() string { return "awskms" }

// Encrypt wraps plaintext under the KMS key identified by masterKeyRef.
func (p *Provider) Encrypt(ctx context.Context, masterKeyRef string, plaintext []byte) ([]byte, error) {
	out, err := p.client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     &masterKeyRef,
		Plaintext: plaintext,
	})
	if err != nil {
		return nil, fmt.Errorf("awskms: encrypt: %w", err)
	}
	return out.CiphertextBlob, nil
}

// Decrypt unwraps a blob previously produced by this provider's Encrypt.
func (p *Provider) Decrypt(ctx context.Context, masterKeyRef string, wrapped []byte) ([]byte, error) {
	out, err := p.client.Decrypt(ctx, &kms.DecryptInput{
		KeyId:          &masterKeyRef,
		CiphertextBlob: wrapped,
	})
	if err != nil {
		return nil, fmt.Errorf("awskms: %w: %w", keyproviders.ErrDecrypt, err)
	}
	return out.Plaintext, nil
}

var _ keyproviders.KeyProvider = (*Provider)(nil)
