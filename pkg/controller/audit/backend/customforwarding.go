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
