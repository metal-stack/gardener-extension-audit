package kapiserver

import (
	"context"
	"fmt"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gcontext "github.com/gardener/gardener/extensions/pkg/webhook/context"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/metal-stack/gardener-extension-audit/pkg/apis/audit/v1alpha1"
	"github.com/metal-stack/gardener-extension-audit/pkg/controller/audit"
	"github.com/metal-stack/metal-lib/pkg/pointer"

	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	"github.com/go-logr/logr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

// NewEnsurer creates a new controlplane ensurer.
func NewEnsurer(logger logr.Logger, mgr manager.Manager) genericmutator.Ensurer {
	return &ensurer{
		client:  mgr.GetClient(),
		decoder: serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder(),
		logger:  logger.WithName("audit-controlplane-ensurer"),
	}
}

type ensurer struct {
	genericmutator.NoopEnsurer
	client  client.Client
	decoder runtime.Decoder
	logger  logr.Logger
}

// EnsureKubeAPIServerDeployment ensures that the kube-apiserver deployment conforms to the provider requirements.
func (e *ensurer) EnsureKubeAPIServerDeployment(ctx context.Context, gctx gcontext.GardenContext, new, _ *appsv1.Deployment) error {
	cluster, err := gctx.GetCluster(ctx)
	if err != nil {
		return err
	}

	if cluster.Shoot.DeletionTimestamp != nil && !cluster.Shoot.DeletionTimestamp.IsZero() {
		e.logger.Info("skip mutating api server because shoot is in deletion")
		return nil
	}

	namespace := cluster.ObjectMeta.Name

	ex := &extensionsv1alpha1.Extension{
		ObjectMeta: metav1.ObjectMeta{
			Name:      audit.Type,
			Namespace: namespace,
		},
	}
	err = e.client.Get(ctx, client.ObjectKeyFromObject(ex), ex)
	if err != nil {
		return fmt.Errorf("unable to find extension resource. this extension needs to be configured with lifecycle policy BeforeKubeAPIServer")
	}

	auditConfig := &v1alpha1.AuditConfig{}
	if ex.Spec.ProviderConfig != nil {
		if _, _, err := e.decoder.Decode(ex.Spec.ProviderConfig.Raw, nil, auditConfig); err != nil {
			return fmt.Errorf("failed to decode provider config: %w", err)
		}
	}

	var webhookMode v1alpha1.AuditWebhookMode
	switch mode := auditConfig.WebhookMode; mode {
	case v1alpha1.AuditWebhookModeBatch, v1alpha1.AuditWebhookModeBlocking, v1alpha1.AuditWebhookModeBlockingStrict:
		webhookMode = mode
	default:
		webhookMode = v1alpha1.AuditWebhookModeBlockingStrict
	}

	if auditConfig.Backends != nil {
		if pointer.SafeDeref(auditConfig.Backends.ClusterForwarding).Enabled && webhookMode == v1alpha1.AuditWebhookModeBlockingStrict {
			// `blocking-strict` in combination with cluster-forwarding can lead to an unpleasant
			// deadlock from which the kube-apiserver cannot recover: when the kube-apiserver starts
			// blocking, the gateway-forwarder cannot figure out the destination service
			// in the shoot anymore. (#68)
			// TODO: prevent this configuration through admission webhook.
			webhookMode = v1alpha1.AuditWebhookModeBlocking
			e.logger.Info("changing `blocking-strict` to `blocking` because `blocking-strict` can lead to a deadlock in combination with cluster-forwarding backend enabled")
		}
	}

	template := &new.Spec.Template
	ps := &template.Spec
	if c := extensionswebhook.ContainerWithName(ps.Containers, "kube-apiserver"); c != nil {
		e.logger.Info("ensuring kube-apiserver deployment")
		ensureKubeAPIServerCommandLineArgs(c, webhookMode)
		ensureVolumeMounts(c)
		ensureVolumes(ps)
	}

	template.Labels["networking.resources.gardener.cloud/to-audit-webhook-backend-tcp-9880"] = "allowed"

	return nil
}

func ensureVolumeMounts(c *corev1.Container) {
	c.VolumeMounts = extensionswebhook.EnsureVolumeMountWithName(c.VolumeMounts, corev1.VolumeMount{
		Name:      "audit-webhook-config",
		ReadOnly:  true,
		MountPath: "/etc/audit-webhook/config",
	})
}

func ensureVolumes(ps *corev1.PodSpec) {
	ps.Volumes = extensionswebhook.EnsureVolumeWithName(ps.Volumes, corev1.Volume{
		Name: "audit-webhook-config",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: "audit-webhook-config",
			},
		},
	})
}

func ensureKubeAPIServerCommandLineArgs(c *corev1.Container, webhookMode v1alpha1.AuditWebhookMode) {
	c.Command = extensionswebhook.EnsureStringWithPrefix(c.Command, "--audit-webhook-config-file=", "/etc/audit-webhook/config/audit-webhook-config.yaml")
	c.Command = extensionswebhook.EnsureStringWithPrefix(c.Command, "--audit-webhook-mode=", string(webhookMode))

	// Configure log truncation to prevent dropped audit log messages
	// https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/#truncate
	// fluentbit imposes a size limit determined by the buffer used by the http input.
	// Use a size limit slightly below the limit imposed by fluentbit.
	// The max-batch-size let's the kube-api-server split audit event batches once
	// they reach that size. If an individual event exceeds the max-event-size, then
	// the request and response object are dropped. The request metadata and objectRef
	// are still kept. As etcd defaults to a maximum request size of 1.5MB, the overall
	// audit log entry should stay below that limit as well.
	sizeLimit := fmt.Sprintf("%v", 4*1000*1000-25*1000)
	c.Command = extensionswebhook.EnsureStringWithPrefix(c.Command, "--audit-webhook-truncate-enabled=", "true")
	c.Command = extensionswebhook.EnsureStringWithPrefix(c.Command, "--audit-webhook-truncate-max-batch-size=", sizeLimit)
	c.Command = extensionswebhook.EnsureStringWithPrefix(c.Command, "--audit-webhook-truncate-max-event-size=", sizeLimit)
}
