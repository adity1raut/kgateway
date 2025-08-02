
package backendconfigpolicy

import (
	"fmt"

	envoytlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"istio.io/istio/pkg/kube/krt"
	"k8s.io/utils/ptr"

	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/extensions2/common/tls"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/extensions2/pluginutils"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/ir"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/krtcollections"
)

// SecretGetter defines the interface for retrieving secrets
type SecretGetter interface {
	GetSecret(name, namespace string) (*ir.Secret, error)
}

// DefaultSecretGetter implements SecretGetter using the pluginutils.GetSecretIr function
type DefaultSecretGetter struct {
	secrets *krtcollections.SecretIndex
	krtctx  krt.HandlerContext
}

func NewDefaultSecretGetter(secrets *krtcollections.SecretIndex, krtctx krt.HandlerContext) *DefaultSecretGetter {
	return &DefaultSecretGetter{
		secrets: secrets,
		krtctx:  krtctx,
	}
}

func (g *DefaultSecretGetter) GetSecret(name, namespace string) (*ir.Secret, error) {
	return pluginutils.GetSecretIr(g.secrets, g.krtctx, name, namespace)
}

func translateTLSConfig(
	secretGetter SecretGetter,
	tlsConfig *v1alpha1.TLS,
	namespace string,
) (*envoytlsv3.UpstreamTlsContext, error) {
	
	// Create secret provider
	provider, err := createSecretProvider(tlsConfig, secretGetter, namespace)
	if err != nil {
		return nil, err
	}

	// Parse TLS parameters
	tlsParams, err := parseTLSParameters(tlsConfig.Parameters)
	if err != nil {
		return nil, err
	}

	// Build common TLS context
	builder := tls.NewCommonTLSContextBuilder().
		WithTLSParameters(tlsParams).
		WithALPNProtocols(tlsConfig.AlpnProtocols)

	// Handle insecure skip verify
	if tlsConfig.InsecureSkipVerify != nil && *tlsConfig.InsecureSkipVerify {
		builder = builder.WithInsecureSkipVerify(true)
	} else {
		// Set certificates and validation
		inlineDataSource := (tlsConfig.SecretRef != nil)
		
		if err := builder.WithCertificates(provider, inlineDataSource); err != nil {
			return nil, err
		}
		
		if err := builder.WithValidation(provider, tlsConfig.VerifySubjectAltName, inlineDataSource); err != nil {
			return nil, err
		}
	}

	// Handle one-way TLS
	if tlsConfig.OneWayTLS != nil && *tlsConfig.OneWayTLS {
		builder = builder.WithOneWayTLS(true)
	}

	commonTLS := builder.Build()

	return tls.CreateUpstreamTLSContext(
		commonTLS,
		ptr.Deref(tlsConfig.Sni, ""),
		ptr.Deref(tlsConfig.AllowRenegotiation, false),
	), nil
}

func createSecretProvider(tlsConfig *v1alpha1.TLS, secretGetter SecretGetter, namespace string) (tls.SecretDataProvider, error) {
	if tlsConfig.SecretRef != nil {
		secret, err := secretGetter.GetSecret(tlsConfig.SecretRef.Name, namespace)
		if err != nil {
			return nil, err
		}
		return tls.NewKubernetesSecretProvider(
			string(secret.Data["tls.crt"]),
			string(secret.Data["tls.key"]),
			string(secret.Data["ca.crt"]),
		), nil
	} else if tlsConfig.TLSFiles != nil {
		return tls.NewKubernetesSecretProvider(
			ptr.Deref(tlsConfig.TLSFiles.TLSCertificate, ""),
			ptr.Deref(tlsConfig.TLSFiles.TLSKey, ""),
			ptr.Deref(tlsConfig.TLSFiles.RootCA, ""),
		), nil
	}

	// Return empty provider if no configuration
	return tls.NewKubernetesSecretProvider("", "", ""), nil
}

func parseTLSParameters(tlsParameters *v1alpha1.Parameters) (*envoytlsv3.TlsParameters, error) {
	if tlsParameters == nil {
		return nil, nil
	}

	tlsMaxVersion, err := parseTLSVersion(tlsParameters.TLSMaxVersion)
	if err != nil {
		return nil, err
	}
	tlsMinVersion, err := parseTLSVersion(tlsParameters.TLSMinVersion)
	if err != nil {
		return nil, err
	}

	return &envoytlsv3.TlsParameters{
		CipherSuites:              tlsParameters.CipherSuites,
		EcdhCurves:                tlsParameters.EcdhCurves,
		TlsMinimumProtocolVersion: tlsMinVersion,
		TlsMaximumProtocolVersion: tlsMaxVersion,
	}, nil
}

func parseTLSVersion(tlsVersion *v1alpha1.TLSVersion) (envoytlsv3.TlsParameters_TlsProtocol, error) {
	if tlsVersion == nil {
		return envoytlsv3.TlsParameters_TLS_AUTO, nil
	}

	switch *tlsVersion {
	case v1alpha1.TLSVersion1_0:
		return envoytlsv3.TlsParameters_TLSv1_0, nil
	case v1alpha1.TLSVersion1_1:
		return envoytlsv3.TlsParameters_TLSv1_1, nil
	case v1alpha1.TLSVersion1_2:
		return envoytlsv3.TlsParameters_TLSv1_2, nil
	case v1alpha1.TLSVersion1_3:
		return envoytlsv3.TlsParameters_TLSv1_3, nil
	case v1alpha1.TLSVersionAUTO:
		return envoytlsv3.TlsParameters_TLS_AUTO, nil
	default:
		return 0, fmt.Errorf("invalid TLS version: %s", *tlsVersion)
	}
}
