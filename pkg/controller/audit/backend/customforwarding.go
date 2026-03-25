package backend

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"maps"
	"path/filepath"
	"strings"

	"github.com/gardener/gardener/pkg/extensions"
	"github.com/gardener/gardener/pkg/utils"
	"github.com/metal-stack/gardener-extension-audit/pkg/apis/audit/v1alpha1"
	"github.com/metal-stack/gardener-extension-audit/pkg/fluentbitconfig"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	customCertsFilePath = "/backends/custom-forwarding/certs"
	customSecretName    = "output-secret"
)

type CustomForwarding struct {
	outputConfig map[string]any
	secret       *corev1.Secret
}

func NewCustomForwarding(outputConfig *corev1.ConfigMap) (CustomForwarding, error) {
	configString, ok := outputConfig.Data["fluent-bit-output.yaml"]
	if !ok {
		return CustomForwarding{}, fmt.Errorf("missing 'fluent-bit-output.yaml' key in ConfigMap")
	}

	config, err := parseFluentBitOutput(configString)
	if err != nil {
		return CustomForwarding{}, fmt.Errorf("failed to parse fluent-bit output config: %w", err)
	}

	return CustomForwarding{outputConfig: config}, nil
}

func (c *CustomForwarding) SetSecret(secret *corev1.Secret) {
	c.secret = secret
}

func parseFluentBitOutput(config string) (map[string]any, error) {
	if strings.TrimSpace(config) == "" {
		return nil, fmt.Errorf("empty configuration")
	}

	parsed, err := fluentbitconfig.ParseConfig(config)
	if err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	if len(parsed.Pipeline.Output) == 0 {
		return nil, fmt.Errorf("missing output section in configuration")
	} else if len(parsed.Pipeline.Output) > 1 {
		return nil, fmt.Errorf("more than one output section in configuration")
	}
	return parsed.Pipeline.Output[0], nil
}

// isValidCertificate checks if the provided data contains a valid PEM-encoded certificate
func isValidCertificate(data []byte) bool {
	block, _ := pem.Decode(data)
	if block == nil {
		return false
	}
	if block.Type != "CERTIFICATE" {
		return false
	}
	_, err := x509.ParseCertificate(block.Bytes)
	return err == nil
}

// isValidPrivateKey checks if the provided data contains a valid PEM-encoded private key
func isValidPrivateKey(data []byte) bool {
	block, _ := pem.Decode(data)
	if block == nil {
		return false
	}
	// Check for common private key types
	switch block.Type {
	case "RSA PRIVATE KEY":
		_, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		return err == nil
	case "EC PRIVATE KEY":
		_, err := x509.ParseECPrivateKey(block.Bytes)
		return err == nil
	case "PRIVATE KEY":
		_, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		return err == nil
	default:
		return false
	}
}

func (c *CustomForwarding) FluentBitConfig(*extensions.Cluster) fluentbitconfig.Config {
	customConfig := maps.Clone(c.outputConfig)

	if c.secret != nil && c.secret.Data != nil {
		if _, ok := c.secret.Data[v1alpha1.SecretCaFileKey]; ok {
			customConfig["tls.ca_file"] = filepath.Join(customCertsFilePath, v1alpha1.SecretCaFileKey)
		}

		if _, ok := c.secret.Data[v1alpha1.SecretTLSPrivateKey]; ok {
			customConfig["tls.key_file"] = filepath.Join(customCertsFilePath, v1alpha1.SecretTLSPrivateKey)
		}

		if _, ok := c.secret.Data[v1alpha1.SecretTLSCertKey]; ok {
			customConfig["tls.crt_file"] = filepath.Join(customCertsFilePath, v1alpha1.SecretTLSCertKey)
		}
	}

	return fluentbitconfig.Config{
		Output: []fluentbitconfig.Output{
			customConfig,
		},
	}
}

func (c *CustomForwarding) PatchAuditWebhook(sts *appsv1.StatefulSet) {
	if c.secret == nil {
		return
	}

	// Make sure that only specified certs are mounted and
	// don't allow mounting anything else from the secret.
	var items []corev1.KeyToPath
	for _, key := range []string{v1alpha1.SecretCaFileKey, v1alpha1.SecretTLSPrivateKey, v1alpha1.SecretTLSCertKey} {
		data, exists := c.secret.Data[key]
		if !exists {
			continue
		}

		// Validate the content based on the key type
		var valid bool
		switch key {
		case v1alpha1.SecretCaFileKey, v1alpha1.SecretTLSCertKey:
			valid = isValidCertificate(data)
		case v1alpha1.SecretTLSPrivateKey:
			valid = isValidPrivateKey(data)
		}

		// Only mount if validation passed
		if valid {
			items = append(items, corev1.KeyToPath{
				Key:  key,
				Path: key,
			})
		}
	}

	if len(items) > 0 {
		sts.Spec.Template.Spec.Volumes = append(sts.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: customSecretName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: c.secret.Name,
					Items:      items,
				},
			},
		})

		sts.Spec.Template.Spec.Containers[0].VolumeMounts = append(sts.Spec.Template.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{
			Name:      customSecretName,
			MountPath: customCertsFilePath,
		})

		sts.Spec.Template.ObjectMeta.Annotations["checksum/"+customSecretName] = utils.ComputeSecretChecksum(c.secret.Data)
	}
}

func (c *CustomForwarding) AdditionalShootObjects(*extensions.Cluster) []client.Object {
	return nil
}

func (c *CustomForwarding) AdditionalSeedObjects(*extensions.Cluster) []client.Object {
	return nil
}
