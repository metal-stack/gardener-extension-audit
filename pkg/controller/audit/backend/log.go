package backend

import (
	"github.com/gardener/gardener/pkg/extensions"
	"github.com/metal-stack/gardener-extension-audit/pkg/fluentbitconfig"
	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Log struct{}

func (l Log) FluentBitConfig(*extensions.Cluster) fluentbitconfig.Config {
	return fluentbitconfig.Config{
		Output: []fluentbitconfig.Output{
			map[string]string{
				"match":                    "audit",
				"name":                     "stdout",
				"retry_limit":              "no_limits", // let fluent-bit never discard any data
				"storage.total_limit_size": "10M",
			},
		},
	}
}

func (l Log) PatchAuditWebhook(*appsv1.StatefulSet) {
}

func (l Log) AdditionalShootObjects(*extensions.Cluster) []client.Object {
	return nil
}

func (l Log) AdditionalSeedObjects(*extensions.Cluster) []client.Object {
	return nil
}
