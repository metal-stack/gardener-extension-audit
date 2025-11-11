package backend

import (
	"fmt"
	"strings"

	"github.com/gardener/gardener/pkg/extensions"
	"github.com/metal-stack/gardener-extension-audit/pkg/fluentbitconfig"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type CustomForwarding struct{
	outputConfig map[string]string
}

func NewCustomForwarding(outputConfig *corev1.ConfigMap) (CustomForwarding, error) {
	config, err := validateCustomForwardingConfig(outputConfig)
	if err != nil {
		return CustomForwarding{}, err
	}

	return CustomForwarding{outputConfig: config}, nil
}

func validateCustomForwardingConfig(outputConfig *corev1.ConfigMap) (map[string]string, error) {
	conf := outputConfig.Data["fluent-bit-output.conf"]
	
	lines := strings.Split(conf, "\n")

	if len(lines) == 0 || !strings.Contains(lines[0], "[OUTPUT]")  {
		return nil, fmt.Errorf("no valid configuration found")
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
	
	return result, nil
}

func (c CustomForwarding) FluentBitConfig(*extensions.Cluster) fluentbitconfig.Config {
	return fluentbitconfig.Config{
		Output: []fluentbitconfig.Output{
			c.outputConfig,
		},
	}
}

func (c CustomForwarding) PatchAuditWebhook(*appsv1.StatefulSet) {
}

func (c CustomForwarding) AdditionalShootObjects(*extensions.Cluster) []client.Object {
	return nil
}

func (c CustomForwarding) AdditionalSeedObjects(*extensions.Cluster) []client.Object {
	return nil
}
