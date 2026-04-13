// Package awskms implements [keyproviders.KeyProvider] using AWS KMS
// direct encryption. Ed25519 signing key material is 32-64 bytes,
// well under KMS's 4 KiB plaintext limit, so no envelope encryption
// is needed.
//
// masterKeyRef is used as the KeyId for Encrypt calls only. Decrypt
// omits KeyId so KMS infers the correct key from the ciphertext blob,
// which is safe even if an alias is repointed after encryption.
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
// KeyId is omitted so KMS infers the correct key from the ciphertext
// metadata. This is safe even if masterKeyRef is an alias that has been
// repointed since the blob was encrypted.
func (p *Provider) Decrypt(ctx context.Context, _ string, wrapped []byte) ([]byte, error) {
	out, err := p.client.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: wrapped,
	})
	if err != nil {
		return nil, fmt.Errorf("awskms: %w: %w", keyproviders.ErrDecrypt, err)
	}
	return out.Plaintext, nil
}

var _ keyproviders.KeyProvider = (*Provider)(nil)
