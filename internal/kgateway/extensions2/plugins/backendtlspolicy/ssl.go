package backendtlspolicy

import (
	envoytlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	corev1 "k8s.io/api/core/v1"

	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/extensions2/common/tls"
)

func ResolveUpstreamSslConfig(cm *corev1.ConfigMap, validation *envoytlsv3.CertificateValidationContext, sni string) (*envoytlsv3.UpstreamTlsContext, error) {
	common, err := ResolveCommonSslConfig(cm, validation, false)
	if err != nil {
		return nil, err
	}

	return tls.CreateUpstreamTLSContext(common, sni, false), nil
}

func ResolveCommonSslConfig(cm *corev1.ConfigMap, validation *envoytlsv3.CertificateValidationContext, mustHaveCert bool) (*envoytlsv3.CommonTlsContext, error) {
	// Validate CA certificate
	caCrt, err := tls.ValidateCASecret(cm.Data)
	if err != nil {
		return nil, err
	}

	// Create provider
	provider := tls.NewConfigMapSecretProvider(cm.Data)

	// Build common TLS context
	builder := tls.NewCommonTLSContextBuilder()
	
	// Set basic validation context with CA
	if err := builder.WithValidation(provider, nil, true); err != nil {
		return nil, err
	}

	commonTLS := builder.Build()

	// Override validation context with provided one if needed
	if validation != nil {
		validation.TrustedCa = tls.CreateInlineDataSource(caCrt)
		validationCtx := &envoytlsv3.CommonTlsContext_ValidationContext{
			ValidationContext: validation,
		}
		commonTLS.ValidationContextType = validationCtx
	}

	return commonTLS, nil
}