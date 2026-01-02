package backend

import (
	"fmt"
	"maps"
	"path"
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
	customCertsFilePath = "/backends/custom/certs"
	customSecretName    = "output-secret"
)

type CustomForwarding struct {
	outputConfig map[string]string
	secret       *corev1.Secret
}

func NewCustomForwarding(outputConfig *corev1.ConfigMap) (CustomForwarding, error) {
	configString, ok := outputConfig.Data["fluent-bit-output.conf"]
	if !ok {
		return CustomForwarding{}, fmt.Errorf("missing 'fluent-bit-output.conf' key in ConfigMap")
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

func parseFluentBitOutput(config string) (map[string]string, error) {
	lines := strings.Split(config, "\n")

	if len(lines) == 1 && lines[0] == "" {
		return nil, fmt.Errorf("empty configuration")
	}

	// Find [OUTPUT] section
	hasOutputSection := false
	for _, line := range lines {
		if strings.Contains(strings.TrimSpace(line), "[OUTPUT]") {
			hasOutputSection = true
			break
		}
	}

	if !hasOutputSection {
		return nil, fmt.Errorf("missing [OUTPUT] section in configuration")
	}

	result := make(map[string]string)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "[") {
			// ignore empty lines or section headers
			continue
		}

		// split the line into key/value
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			key := parts[0]
			value := strings.Join(parts[1:], " ")
			result[key] = value
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no valid key-value pairs found in configuration")
	}

	return result, nil
}

func (c CustomForwarding) FluentBitConfig(*extensions.Cluster) fluentbitconfig.Config {
	customConfig := maps.Clone(c.outputConfig)

	if c.secret != nil && c.secret.Data != nil {
		if _, ok := c.secret.Data[v1alpha1.SecretCaFileKey]; ok {
			customConfig["tls.ca_file"] = filepath.Join(customCertsFilePath, "ca.crt")
		}

		if _, ok := c.secret.Data[v1alpha1.SecretTLSPrivateKey]; ok {
			customConfig["tls.key_file"] = filepath.Join(customCertsFilePath, "tls.key")
		}

		if _, ok := c.secret.Data[v1alpha1.SecretTLSCertKey]; ok {
			customConfig["tls.cert_file"] = filepath.Join(customCertsFilePath, "tls.crt")
		}
	}

	return fluentbitconfig.Config{
		Output: []fluentbitconfig.Output{
			customConfig,
		},
	}
}

func (c CustomForwarding) PatchAuditWebhook(sts *appsv1.StatefulSet) {
	if c.secret == nil {
		return
	}

	// Make sure that only specified certs are mounted and
	// don't allow mounting anything else from the secret.
	var items []corev1.KeyToPath
	for _, key := range []string{v1alpha1.SecretCaFileKey, v1alpha1.SecretTLSPrivateKey, v1alpha1.SecretTLSCertKey} {
		if _, exists := c.secret.Data[key]; exists {
			items = append(items, corev1.KeyToPath{
				Key: key,
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
			MountPath: path.Dir(customCertsFilePath),
		})

		sts.Spec.Template.ObjectMeta.Annotations["checksum/"+customSecretName] = utils.ComputeSecretChecksum(c.secret.Data)
	}
}

func (c CustomForwarding) AdditionalShootObjects(*extensions.Cluster) []client.Object {
	return nil
}

func (c CustomForwarding) AdditionalSeedObjects(*extensions.Cluster) []client.Object {
	return nil
}
