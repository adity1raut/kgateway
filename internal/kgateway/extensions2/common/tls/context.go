package tls

import (
	"errors"

	envoytlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
)

// CommonTLSContextBuilder helps build common TLS contexts
type CommonTLSContextBuilder struct {
	context *envoytlsv3.CommonTlsContext
}

// NewCommonTLSContextBuilder creates a new builder
func NewCommonTLSContextBuilder() *CommonTLSContextBuilder {
	return &CommonTLSContextBuilder{
		context: &envoytlsv3.CommonTlsContext{
			TlsParams: &envoytlsv3.TlsParameters{}, // default params
		},
	}
}

// WithTLSParameters sets TLS parameters
func (b *CommonTLSContextBuilder) WithTLSParameters(params *envoytlsv3.TlsParameters) *CommonTLSContextBuilder {
	if params != nil {
		b.context.TlsParams = params
	}
	return b
}

// WithALPNProtocols sets ALPN protocols
func (b *CommonTLSContextBuilder) WithALPNProtocols(protocols []string) *CommonTLSContextBuilder {
	if protocols != nil {
		b.context.AlpnProtocols = protocols
	}
	return b
}

// WithCertificates sets TLS certificates
func (b *CommonTLSContextBuilder) WithCertificates(provider SecretDataProvider, inline bool) error {
	certChain := provider.GetCertChain()
	privateKey := provider.GetPrivateKey()

	if certChain == "" && privateKey == "" {
		return nil // No certificates to set
	}

	if certChain == "" || privateKey == "" {
		return errors.New("invalid TLS config: certChain and privateKey must both be provided")
	}

	// Validate and clean certificate
	cleanedCertChain, err := ValidateAndCleanCertKeyPair(certChain, privateKey, provider.GetRootCA())
	if err != nil {
		return err
	}

	dataSourceGen := DataSourceGenerator(inline)
	
	b.context.TlsCertificates = []*envoytlsv3.TlsCertificate{
		{
			CertificateChain: dataSourceGen(cleanedCertChain),
			PrivateKey:       dataSourceGen(privateKey),
		},
	}

	return nil
}

// WithValidation sets certificate validation context
func (b *CommonTLSContextBuilder) WithValidation(provider SecretDataProvider, sanList []string, inline bool) error {
	rootCA := provider.GetRootCA()
	if rootCA == "" && len(sanList) != 0 {
		return errors.New("a root_ca must be provided if verify_subject_alt_name is not empty")
	}

	if rootCA == "" {
		return nil // No validation to set
	}

	dataSourceGen := DataSourceGenerator(inline)
	validationCtx := &envoytlsv3.CommonTlsContext_ValidationContext{
		ValidationContext: &envoytlsv3.CertificateValidationContext{
			TrustedCa: dataSourceGen(rootCA),
		},
	}

	if len(sanList) > 0 {
		validationCtx.ValidationContext.MatchTypedSubjectAltNames = CreateSANMatchers(sanList)
	}

	b.context.ValidationContextType = validationCtx
	return nil
}

// WithInsecureSkipVerify sets insecure skip verify
func (b *CommonTLSContextBuilder) WithInsecureSkipVerify(skip bool) *CommonTLSContextBuilder {
	if skip {
		b.context.ValidationContextType = &envoytlsv3.CommonTlsContext_ValidationContext{}
	}
	return b
}

// WithOneWayTLS disables validation for one-way TLS
func (b *CommonTLSContextBuilder) WithOneWayTLS(oneWay bool) *CommonTLSContextBuilder {
	if oneWay {
		b.context.ValidationContextType = nil
	}
	return b
}

// Build returns the built common TLS context
func (b *CommonTLSContextBuilder) Build() *envoytlsv3.CommonTlsContext {
	return b.context
}

// CreateUpstreamTLSContext creates an upstream TLS context from common context
func CreateUpstreamTLSContext(common *envoytlsv3.CommonTlsContext, sni string, allowRenegotiation bool) *envoytlsv3.UpstreamTlsContext {
	return &envoytlsv3.UpstreamTlsContext{
		CommonTlsContext:   common,
		Sni:                sni,
		AllowRenegotiation: allowRenegotiation,
	}
}