package app

import (
	"context"
	"fmt"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/funinthecloud/protosource-auth/keyproviders"
	"github.com/funinthecloud/protosource-auth/keyproviders/awskms"
	"github.com/funinthecloud/protosource-auth/keyproviders/azurekeyvault"
	"github.com/funinthecloud/protosource-auth/keyproviders/local"
)

// BuildKeyProvider constructs the [keyproviders.KeyProvider] selected
// by cfg.KeyProvider. The returned masterKeyRef is the value the
// resolver passes to Encrypt — for [KeyProviderLocal] it is the
// literal "local-master" sentinel; for the cloud providers it is the
// operator-supplied cfg.MasterKeyRef (a KMS ARN or Key Vault key
// identifier URL).
//
// Exposed so binaries that need the *protosource.Router (e.g. the
// Lambda entry point wrapping with awslambda.WrapRouter) can build
// the same provider stack [Run] does without going through the HTTP
// adapter.
func BuildKeyProvider(ctx context.Context, cfg *Config) (keyproviders.KeyProvider, string, error) {
	switch cfg.KeyProvider {
	case KeyProviderLocal:
		if len(cfg.MasterKey) == 0 {
			return nil, "", fmt.Errorf("app: MasterKey is required for KeyProvider=local (set %s)", EnvMasterKey)
		}
		p, err := local.New(cfg.MasterKey)
		if err != nil {
			return nil, "", fmt.Errorf("app: init local key provider: %w", err)
		}
		return p, cfg.MasterKeyRef, nil

	case KeyProviderAWSKMS:
		var loadOpts []func(*awsconfig.LoadOptions) error
		if cfg.AWSRegion != "" {
			loadOpts = append(loadOpts, awsconfig.WithRegion(cfg.AWSRegion))
		}
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
		if err != nil {
			return nil, "", fmt.Errorf("app: aws config for kms: %w", err)
		}
		return awskms.New(kms.NewFromConfig(awsCfg)), cfg.MasterKeyRef, nil

	case KeyProviderAzureKeyVault:
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, "", fmt.Errorf("app: default azure credential: %w", err)
		}
		return azurekeyvault.New(cred), cfg.MasterKeyRef, nil

	default:
		return nil, "", fmt.Errorf("app: unknown KeyProvider %q", cfg.KeyProvider)
	}
}
