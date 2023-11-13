package kapiserver

import (
	"context"
	"fmt"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gcontext "github.com/gardener/gardener/extensions/pkg/webhook/context"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/metal-stack/gardener-extension-audit/pkg/apis/audit/v1alpha1"
	"github.com/metal-stack/gardener-extension-audit/pkg/controller"

	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	"github.com/go-logr/logr"

	"sigs.k8s.io/controller-runtime/pkg/client"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

// NewEnsurer creates a new controlplane ensurer.
func NewEnsurer(logger logr.Logger) genericmutator.Ensurer {
	return &ensurer{
		logger: logger.WithName("audit-controlplane-ensurer"),
	}
}

type ensurer struct {
	genericmutator.NoopEnsurer
	client  client.Client
	decoder runtime.Decoder
	logger  logr.Logger
}

// InjectClient injects the given client into the ensurer.
func (e *ensurer) InjectClient(client client.Client) error {
	e.client = client
	return nil
}

// InjectScheme injects the given scheme into the reconciler.
func (e *ensurer) InjectScheme(scheme *runtime.Scheme) error {
	e.decoder = serializer.NewCodecFactory(scheme, serializer.EnableStrict).UniversalDecoder()
	return nil
}

// EnsureKubeAPIServerDeployment ensures that the kube-apiserver deployment conforms to the provider requirements.
func (e *ensurer) EnsureKubeAPIServerDeployment(ctx context.Context, gctx gcontext.GardenContext, new, _ *appsv1.Deployment) error {
	cluster, err := gctx.GetCluster(ctx)
	if err != nil {
		return err
	}

	namespace := cluster.ObjectMeta.Name

	ex := &extensionsv1alpha1.Extension{
		ObjectMeta: metav1.ObjectMeta{
			Name:      controller.Type,
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
}
