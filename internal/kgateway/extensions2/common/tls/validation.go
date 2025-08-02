
package tls

import (
	"crypto/tls"
	"errors"

	envoytlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoymatcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"k8s.io/client-go/util/cert"
)

// ValidateAndCleanCertKeyPair validates and cleans certificate/key pair
func ValidateAndCleanCertKeyPair(certChain, privateKey, rootCA string) (string, error) {
	// Skip validation if only rootCA is provided
	if certChain == "" && privateKey == "" && rootCA != "" {
		return certChain, nil
	}

	// Validate cert/key pair
	_, err := tls.X509KeyPair([]byte(certChain), []byte(privateKey))
	if err != nil {
		return "", err
	}

	// Clean and validate certificate format
	candidateCert, err := cert.ParseCertsPEM([]byte(certChain))
	if err != nil {
		return "", err
	}

	cleanedChainBytes, err := cert.EncodeCertificates(candidateCert...)
	if err != nil {
		return "", err
	}

	return string(cleanedChainBytes), nil
}

// CreateSANMatchers converts SAN list to Envoy matchers
func CreateSANMatchers(sanList []string) []*envoytlsv3.SubjectAltNameMatcher {
	var matchers []*envoytlsv3.SubjectAltNameMatcher
	for _, san := range sanList {
		matcher := &envoytlsv3.SubjectAltNameMatcher{
			SanType: envoytlsv3.SubjectAltNameMatcher_DNS,
			Matcher: &envoymatcher.StringMatcher{
				MatchPattern: &envoymatcher.StringMatcher_Exact{Exact: san},
			},
		}
		matchers = append(matchers, matcher)
	}
	return matchers
}

// ValidateCASecret validates CA certificate from secret data
func ValidateCASecret(data map[string]string) (string, error) {
	caCrt, ok := data["ca.crt"]
	if !ok {
		return "", errors.New("no key ca.crt found")
	}
	return caCrt, nil
}
