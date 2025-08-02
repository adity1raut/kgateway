package tls

// SecretDataProvider defines interface for getting certificate data
type SecretDataProvider interface {
	GetCertChain() string
	GetPrivateKey() string
	GetRootCA() string
}

// ConfigMapSecretProvider implements SecretDataProvider for ConfigMap
type ConfigMapSecretProvider struct {
	data map[string]string
}

func NewConfigMapSecretProvider(data map[string]string) *ConfigMapSecretProvider {
	return &ConfigMapSecretProvider{data: data}
}

func (p *ConfigMapSecretProvider) GetCertChain() string {
	return p.data["tls.crt"]
}

func (p *ConfigMapSecretProvider) GetPrivateKey() string {
	return p.data["tls.key"]
}

func (p *ConfigMapSecretProvider) GetRootCA() string {
	return p.data["ca.crt"]
}

// KubernetesSecretProvider implements SecretDataProvider for Kubernetes Secret
type KubernetesSecretProvider struct {
	certChain  string
	privateKey string
	rootCA     string
}

func NewKubernetesSecretProvider(certChain, privateKey, rootCA string) *KubernetesSecretProvider {
	return &KubernetesSecretProvider{
		certChain:  certChain,
		privateKey: privateKey,
		rootCA:     rootCA,
	}
}

func (p *KubernetesSecretProvider) GetCertChain() string {
	return p.certChain
}

func (p *KubernetesSecretProvider) GetPrivateKey() string {
	return p.privateKey
}

func (p *KubernetesSecretProvider) GetRootCA() string {
	return p.rootCA
}