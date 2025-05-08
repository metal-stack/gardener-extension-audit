package backend

import (
	"github.com/gardener/gardener/pkg/extensions"
	"github.com/metal-stack/gardener-extension-audit/pkg/fluentbitconfig"
	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Backend interface {
	FluentBitConfig(*extensions.Cluster) fluentbitconfig.Config
	PatchAuditWebhook(*appsv1.StatefulSet)
	AdditionalShootObjects(*extensions.Cluster) []client.Object
	AdditionalSeedObjects(*extensions.Cluster) []client.Object
}
