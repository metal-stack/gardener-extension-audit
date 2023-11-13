package controller

import (
	"context"
	"fmt"
	"path"
	"time"

	"github.com/gardener/gardener/extensions/pkg/controller/extension"

	"github.com/gardener/gardener/extensions/pkg/controller"
	extensionssecretsmanager "github.com/gardener/gardener/extensions/pkg/util/secret/manager"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/extensions"
	"github.com/gardener/gardener/pkg/utils"
	gutil "github.com/gardener/gardener/pkg/utils/gardener"
	kutil "github.com/gardener/gardener/pkg/utils/kubernetes"
	"github.com/gardener/gardener/pkg/utils/managedresources"
	"github.com/gardener/gardener/pkg/utils/secrets"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
	"github.com/go-logr/logr"
	"github.com/metal-stack/gardener-extension-audit/pkg/apis/audit/v1alpha1"
	"github.com/metal-stack/gardener-extension-audit/pkg/apis/config"
	"github.com/metal-stack/gardener-extension-audit/pkg/controller/fluentbitconfig"
	"github.com/metal-stack/gardener-extension-audit/pkg/imagevector"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configlatest "k8s.io/client-go/tools/clientcmd/api/latest"
	configv1 "k8s.io/client-go/tools/clientcmd/api/v1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	defaultAuditPolicy = `
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # The following requests were manually identified as high-volume and low-risk,
  # so drop them.
  - level: None
    resources:
      - group: ""
        resources:
          - endpoints
          - services
          - services/status
    users:
      - 'system:kube-proxy'
    verbs:
      - watch
  - level: None
    resources:
      - group: ""
        resources:
          - nodes
          - nodes/status
    userGroups:
      - 'system:nodes'
    verbs:
      - get
  - level: None
    namespaces:
      - kube-system
    resources:
      - group: ""
        resources:
          - endpoints
    users:
      - 'system:kube-controller-manager'
      - 'system:kube-scheduler'
      - 'system:serviceaccount:kube-system:endpoint-controller'
    verbs:
      - get
      - update
  - level: None
    resources:
      - group: ""
        resources:
          - namespaces
          - namespaces/status
          - namespaces/finalize
    users:
      - 'system:apiserver'
    verbs:
      - get
  # Don't log HPA fetching metrics.
  - level: None
    resources:
      - group: metrics.k8s.io
    users:
      - 'system:kube-controller-manager'
    verbs:
      - get
      - list
  # Don't log these read-only URLs.
  - level: None
    nonResourceURLs:
      - '/healthz*'
      - /version
      - '/swagger*'
  # Don't log events requests.
  - level: None
    resources:
      - group: ""
        resources:
          - events
  # node and pod status calls from nodes are high-volume and can be large, don't log responses for expected updates from nodes
  - level: Request
    omitStages:
      - RequestReceived
    resources:
      - group: ""
        resources:
          - nodes/status
          - pods/status
    users:
      - kubelet
      - 'system:node-problem-detector'
      - 'system:serviceaccount:kube-system:node-problem-detector'
    verbs:
      - update
      - patch
  - level: Request
    omitStages:
      - RequestReceived
    resources:
      - group: ""
        resources:
          - nodes/status
          - pods/status
    userGroups:
      - 'system:nodes'
    verbs:
      - update
      - patch
  # deletecollection calls can be large, don't log responses for expected namespace deletions
  - level: Request
    omitStages:
      - RequestReceived
    users:
      - 'system:serviceaccount:kube-system:namespace-controller'
    verbs:
      - deletecollection
  # Secrets, ConfigMaps, and TokenReviews can contain sensitive & binary data,
  # so only log at the Metadata level.
  - level: Metadata
    omitStages:
      - RequestReceived
    resources:
      - group: ""
        resources:
          - secrets
          - configmaps
      - group: authentication.k8s.io
        resources:
          - tokenreviews
  # Get repsonses can be large; skip them.
  - level: Request
    omitStages:
      - RequestReceived
    resources:
      - group: ""
      - group: admissionregistration.k8s.io
      - group: apiextensions.k8s.io
      - group: apiregistration.k8s.io
      - group: apps
      - group: authentication.k8s.io
      - group: authorization.k8s.io
      - group: autoscaling
      - group: batch
      - group: certificates.k8s.io
      - group: extensions
      - group: metrics.k8s.io
      - group: networking.k8s.io
      - group: policy
      - group: rbac.authorization.k8s.io
      - group: scheduling.k8s.io
      - group: settings.k8s.io
      - group: storage.k8s.io
    verbs:
      - get
      - list
      - watch
  # Default level for known APIs
  - level: RequestResponse
    omitStages:
      - RequestReceived
    resources:
      - group: ""
      - group: admissionregistration.k8s.io
      - group: apiextensions.k8s.io
      - group: apiregistration.k8s.io
      - group: apps
      - group: authentication.k8s.io
      - group: authorization.k8s.io
      - group: autoscaling
      - group: batch
      - group: certificates.k8s.io
      - group: extensions
      - group: metrics.k8s.io
      - group: networking.k8s.io
      - group: policy
      - group: rbac.authorization.k8s.io
      - group: scheduling.k8s.io
      - group: settings.k8s.io
      - group: storage.k8s.io
  # Default level for all other requests.
  - level: Metadata
    omitStages:
      - RequestReceived
`
	defaultPersitenceSize       = "1Gi"
	defaultForwardingBufferSize = "900M"
	defaultSplunkBufferSize     = "900M"
)

// NewActuator returns an actuator responsible for Extension resources.
func NewActuator(config config.ControllerConfiguration) extension.Actuator {
	return &actuator{
		config: config,
	}
}

type actuator struct {
	client  client.Client
	decoder runtime.Decoder
	config  config.ControllerConfiguration
}

// InjectClient injects the controller runtime client into the reconciler.
func (a *actuator) InjectClient(client client.Client) error {
	a.client = client
	return nil
}

// InjectScheme injects the given scheme into the reconciler.
func (a *actuator) InjectScheme(scheme *runtime.Scheme) error {
	a.decoder = serializer.NewCodecFactory(scheme, serializer.EnableStrict).UniversalDecoder()
	return nil
}

// Reconcile the Extension resource.
func (a *actuator) Reconcile(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	auditConfig := &v1alpha1.AuditConfig{}
	if ex.Spec.ProviderConfig != nil {
		if _, _, err := a.decoder.Decode(ex.Spec.ProviderConfig.Raw, nil, auditConfig); err != nil {
			return fmt.Errorf("failed to decode provider config: %w", err)
		}
	}

	if auditConfig.AuditPolicy == nil {
		auditConfig.AuditPolicy = pointer.Pointer(defaultAuditPolicy)
	}

	if auditConfig.Backends == nil {
		auditConfig.Backends = &v1alpha1.AuditBackends{
			Log: &v1alpha1.AuditBackendLog{
				Enabled: true,
			},
		}
	}

	namespace := ex.GetNamespace()

	cluster, err := controller.GetCluster(ctx, a.client, namespace)
	if err != nil {
		return err
	}

	if err := a.createResources(ctx, log, auditConfig, cluster, namespace); err != nil {
		return err
	}

	return nil
}

// Delete the Extension resource.
func (a *actuator) Delete(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return a.deleteResources(ctx, log, ex.GetNamespace())
}

// Restore the Extension resource.
func (a *actuator) Restore(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return a.Reconcile(ctx, log, ex)
}

// Migrate the Extension resource.
func (a *actuator) Migrate(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return nil
}

func (a *actuator) createResources(ctx context.Context, log logr.Logger, auditConfig *v1alpha1.AuditConfig, cluster *extensions.Cluster, namespace string) error {
	const (
		auditForwaderAccessSecretName = gutil.SecretNamePrefixShootAccess + "audit-cluster-forwarding-vpn-gateway"
	)

	shootAccessSecret := gutil.NewShootAccessSecret(auditForwaderAccessSecretName, namespace)
	if err := shootAccessSecret.Reconcile(ctx, a.client); err != nil {
		return err
	}

	secrets, err := a.generateSecrets(ctx, log, cluster)
	if err != nil {
		return err
	}

	shootObjects, err := shootObjects(secrets)
	if err != nil {
		return err
	}

	seedObjects, err := seedObjects(auditConfig, secrets, cluster, shootAccessSecret.Secret.Name, namespace)
	if err != nil {
		return err
	}

	shootResources, err := managedresources.NewRegistry(kubernetes.ShootScheme, kubernetes.ShootCodec, kubernetes.ShootSerializer).AddAllAndSerialize(shootObjects...)
	if err != nil {
		return err
	}

	seedResources, err := managedresources.NewRegistry(kubernetes.SeedScheme, kubernetes.SeedCodec, kubernetes.SeedSerializer).AddAllAndSerialize(seedObjects...)
	if err != nil {
		return err
	}

	if err := managedresources.CreateForShoot(ctx, a.client, namespace, v1alpha1.ShootAuditResourceName, "audit-extension", false, shootResources); err != nil {
		return err
	}

	log.Info("managed resource created successfully", "name", v1alpha1.ShootAuditResourceName)

	if err := managedresources.CreateForSeed(ctx, a.client, namespace, v1alpha1.SeedAuditResourceName, false, seedResources); err != nil {
		return err
	}

	log.Info("managed resource created successfully", "name", v1alpha1.SeedAuditResourceName)

	return nil
}

func (a *actuator) deleteResources(ctx context.Context, log logr.Logger, namespace string) error {
	log.Info("deleting managed resource for registry cache")

	if err := managedresources.Delete(ctx, a.client, namespace, v1alpha1.ShootAuditResourceName, false); err != nil {
		return err
	}

	if err := managedresources.Delete(ctx, a.client, namespace, v1alpha1.SeedAuditResourceName, false); err != nil {
		return err
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	if err := managedresources.WaitUntilDeleted(timeoutCtx, a.client, namespace, v1alpha1.ShootAuditResourceName); err != nil {
		return err
	}

	if err := managedresources.WaitUntilDeleted(timeoutCtx, a.client, namespace, v1alpha1.SeedAuditResourceName); err != nil {
		return err
	}

	return nil
}

func (a *actuator) generateSecrets(ctx context.Context, log logr.Logger, cluster *extensions.Cluster) (map[string]*corev1.Secret, error) {
	const (
		caName = "ca-audittailer"
	)

	secretConfigs := []extensionssecretsmanager.SecretConfigWithOptions{
		{
			Config: &secrets.CertificateSecretConfig{
				Name:       caName,
				CommonName: caName,
				CertType:   secrets.CACert,
			},
			Options: []secretsmanager.GenerateOption{secretsmanager.Persist()},
		},
		{
			Config: &secrets.CertificateSecretConfig{
				Name:       "audittailer-server",
				CommonName: "audittailer",
				DNSNames:   kutil.DNSNamesForService("audittailer", v1alpha1.ShootAudittailerNamespace),
				CertType:   secrets.ServerCert,
			},
			Options: []secretsmanager.GenerateOption{secretsmanager.SignedByCA(caName, secretsmanager.UseCurrentCA)},
		},
		{
			Config: &secrets.CertificateSecretConfig{
				Name:       "audittailer-client",
				CommonName: "audittailer",
				DNSNames:   kutil.DNSNamesForService("audittailer", v1alpha1.ShootAudittailerNamespace),
				CertType:   secrets.ClientCert,
			},
			Options: []secretsmanager.GenerateOption{secretsmanager.SignedByCA(caName, secretsmanager.UseCurrentCA)},
		},
	}

	sm, err := extensionssecretsmanager.SecretsManagerForCluster(ctx, log, clock.RealClock{}, a.client, cluster, "audit", secretConfigs)
	if err != nil {
		return nil, err
	}

	secrets, err := extensionssecretsmanager.GenerateAllSecrets(ctx, sm, secretConfigs)
	if err != nil {
		return nil, err
	}

	return secrets, nil
}

func seedObjects(auditConfig *v1alpha1.AuditConfig, secrets map[string]*corev1.Secret, cluster *extensions.Cluster, shootAccessSecretName, namespace string) ([]client.Object, error) {
	fluentBitImage, err := imagevector.ImageVector().FindImage("fluent-bit")
	if err != nil {
		return nil, fmt.Errorf("failed to find fluent-bit image: %w", err)
	}

	kubeconfig, err := webhookKubeconfig(namespace)
	if err != nil {
		return nil, fmt.Errorf("unable to generate webhook kubeconfig: %w", err)
	}

	var (
		fluentbitConfigMap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "audit-fluent-bit-config",
				Namespace: namespace,
			},
			Data: map[string]string{
				"fluent-bit.conf": fluentbitconfig.Config{
					Service: map[string]string{
						"log_level":                 "info",
						"storage.path":              "/data/",
						"storage.sync":              "normal",
						"storage.checksum":          "off",
						"storage.max_chunks_up":     "128",
						"storage.backlog.mem_limit": "5M",
						"http_server":               "on",
						"http_listen":               "0.0.0.0",
						"http_port":                 "2020",
					},
					Input: []fluentbitconfig.Input{
						map[string]string{
							"storage.type": "filesystem",
							"name":         "http",
						},
					},
					Includes: []fluentbitconfig.Include{
						"*.backend.conf",
					},
				}.Generate(),
			},
		}

		auditPolicyConfigMap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "audit-policy",
				Namespace: namespace,
			},
			Data: map[string]string{
				"audit-policy.yaml": *auditConfig.AuditPolicy,
			},
		}

		auditWebhookConfigSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "audit-webhook-config",
				Namespace: namespace,
			},
			StringData: map[string]string{
				"audit-webhook-config.yaml": string(kubeconfig),
			},
		}

		auditwebhookStatefulSet = &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "audit-webhook-backend",
				Namespace:   namespace,
				Annotations: map[string]string{},
				Labels:      map[string]string{},
			},
			Spec: appsv1.StatefulSetSpec{
				Replicas:    auditConfig.Replicas,
				ServiceName: "audit-webhook-backend",
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "audit-webhook-backend",
					},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"app": "audit-webhook-backend",
							"networking.gardener.cloud/from-prometheus":                                            "allowed",
							"networking.gardener.cloud/to-dns":                                                     "allowed",
							"networking.gardener.cloud/to-public-networks":                                         "allowed",
							"networking.gardener.cloud/from-shoot-apiserver":                                       "allowed",
							"networking.resources.gardener.cloud/to-audit-cluster-forwarding-vpn-gateway-tcp-9876": "allowed",
						},
						Annotations: map[string]string{
							"scheduler.alpha.kubernetes.io/critical-pod": "",
							"prometheus.io/scrape":                       "true",
							"prometheus.io/port":                         "2020",
							"prometheus.io/path":                         "/api/v1/metrics/prometheus",
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "fluent-bit",
								Image: fluentBitImage.String(),
								Args: []string{
									"--storage_path=/data",
									"--config=/config/fluent-bit.conf",
								},
								Ports: []corev1.ContainerPort{
									{
										ContainerPort: 2020,
									},
								},
								ReadinessProbe: &corev1.Probe{
									ProbeHandler: corev1.ProbeHandler{
										HTTPGet: &corev1.HTTPGetAction{
											Path: "/api/v1/metrics/prometheus",
											Port: intstr.FromInt(2020),
										},
									},
								},
								LivenessProbe: &corev1.Probe{
									ProbeHandler: corev1.ProbeHandler{
										HTTPGet: &corev1.HTTPGetAction{
											Path: "/",
											Port: intstr.FromInt(2020),
										},
									},
								},
								Resources: corev1.ResourceRequirements{
									Requests: corev1.ResourceList{
										corev1.ResourceCPU:    resource.MustParse("200m"),
										corev1.ResourceMemory: resource.MustParse("512Mi"),
									},
									Limits: corev1.ResourceList{
										corev1.ResourceCPU:    resource.MustParse("1"),
										corev1.ResourceMemory: resource.MustParse("1Gi"), // should never be reached because max_chunks_up and chunk_size is smaller than 1Gi
									},
								},
								VolumeMounts: []corev1.VolumeMount{
									{
										Name:      "config",
										MountPath: "/config",
									},
									{
										Name:      "audit-data",
										MountPath: "/data",
									},
								},
							},
						},
						Affinity: &corev1.Affinity{
							PodAntiAffinity: &corev1.PodAntiAffinity{
								PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{
									{
										Weight: 100,
										PodAffinityTerm: corev1.PodAffinityTerm{
											LabelSelector: &metav1.LabelSelector{
												MatchLabels: map[string]string{
													"app": "audit-webhook-backend",
												},
											},
											TopologyKey: "kubernetes.io/hostname",
										},
									},
								},
							},
						},
						Volumes: []corev1.Volume{
							{
								Name: "config",
								VolumeSource: corev1.VolumeSource{
									ConfigMap: &corev1.ConfigMapVolumeSource{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "audit-fluent-bit-config",
										},
									},
								},
							},
						},
					},
				},
				VolumeClaimTemplates: []corev1.PersistentVolumeClaim{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "audit-data",
						},
						Spec: corev1.PersistentVolumeClaimSpec{
							AccessModes: []corev1.PersistentVolumeAccessMode{
								corev1.ReadWriteOnce,
							},
							StorageClassName: auditConfig.Persistence.StorageClassName,
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceStorage: *auditConfig.Persistence.Size,
								},
							},
						},
					},
				},
			},
		}
	)

	objects := []client.Object{
		auditwebhookStatefulSet,
		auditWebhookConfigSecret,
		auditPolicyConfigMap,
		fluentbitConfigMap,
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "audit-webhook-backend",
				Namespace: namespace,
			},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{
					"app": "audit-webhook-backend",
				},
				Ports: []corev1.ServicePort{
					{
						Name:     "http",
						Port:     9880,
						Protocol: corev1.ProtocolTCP,
					},
				},
			},
		},
		&policyv1.PodDisruptionBudget{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "audit-webhook-backend",
				Namespace: namespace,
				Labels: map[string]string{
					"app": "audit-webhook-backend",
				},
			},
			Spec: policyv1.PodDisruptionBudgetSpec{
				MinAvailable: utils.IntStrPtrFromInt(1),
				Selector:     auditwebhookStatefulSet.Spec.Selector,
			},
		},
	}

	if pointer.SafeDeref(auditConfig.Backends.Log).Enabled {
		fluentbitConfigMap.Data["log.backend.conf"] = fluentbitconfig.Config{
			Output: []fluentbitconfig.Output{
				map[string]string{
					"match":                    "audit",
					"name":                     "stdout",
					"storage.total_limit_size": "10M",
				},
			},
		}.Generate()
	}

	if pointer.SafeDeref(auditConfig.Backends.ClusterForwarding).Enabled {
		gardenerVpnGatewayImage, err := imagevector.ImageVector().FindImage("gardener-vpn-gateway")
		if err != nil {
			return nil, fmt.Errorf("failed to find gardener-vpn-gateway image: %w", err)
		}

		forwardingConfig := map[string]string{
			"match":                    "audit",
			"name":                     "forward",
			"storage.total_limit_size": defaultForwardingBufferSize,
			"host":                     "audit-cluster-forwarding-vpn-gateway",
			"port":                     "9876",
			"require_ack_response":     "True",
			"compress":                 "gzip",
			"tls":                      "On",
			"tls.verify":               "On",
			"tls.debug":                "2",
			"tls.ca_file":              "/backends/cluster-forwarding/certs/ca.crt",
			"tls.crt_file":             "/backends/cluster-forwarding/certs/tls.crt",
			"tls.key_file":             "/backends/cluster-forwarding/certs/tls.key",
			"tls.vhost":                "audittailer",
		}

		if auditConfig.Backends.ClusterForwarding.FilesystemBufferSize != "" {
			forwardingConfig["storage.total_limit_size"] = auditConfig.Backends.ClusterForwarding.FilesystemBufferSize
		}

		fluentbitConfigMap.Data["clusterforwarding.backend.conf"] = fluentbitconfig.Config{
			Output: []fluentbitconfig.Output{forwardingConfig},
		}.Generate()

		auditwebhookStatefulSet.Spec.Template.Spec.Containers[0].VolumeMounts = append(auditwebhookStatefulSet.Spec.Template.Spec.Containers[0].VolumeMounts,
			corev1.VolumeMount{
				Name:      "audittailer-client",
				MountPath: "/backends/cluster-forwarding/certs",
			})

		auditwebhookStatefulSet.Spec.Template.Spec.Volumes = append(auditwebhookStatefulSet.Spec.Template.Spec.Volumes,
			corev1.Volume{
				Name: "audittailer-client",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: secrets["audittailer-client"].Name,
					},
				},
			},
		)

		auditwebhookStatefulSet.Spec.Template.Annotations["checksum/secret-audittailer-client"] = utils.ComputeSecretChecksum(secrets["audittailer-client"].Data)

		auditwebhookStatefulSet.Spec.Template.Labels["networking.resources.gardener.cloud/to-audit-cluster-forwarding-vpn-gateway-tcp-9876"] = "allowed"

		vpnGateway := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "audit-cluster-forwarding-vpn-gateway",
				Namespace: namespace,
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: pointer.Pointer(int32(1)),
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "audit-cluster-forwarding-vpn-gateway",
					},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"app": "audit-cluster-forwarding-vpn-gateway",

							"networking.gardener.cloud/to-dns":                                        "allowed",
							"networking.gardener.cloud/to-shoot-apiserver":                            "allowed",
							"networking.gardener.cloud/to-private-networks":                           "allowed",
							"networking.gardener.cloud/to-public-networks":                            "allowed", // is this required?
							"networking.gardener.cloud/to-runtime-apiserver":                          "allowed",
							"networking.resources.gardener.cloud/to-kube-apiserver-tcp-443":           "allowed",
							"networking.resources.gardener.cloud/to-vpn-seed-server-tcp-9443":         "allowed",
							"networking.resources.gardener.cloud/from-audit-webhook-backend-tcp-9876": "allowed",
						},
					},
					Spec: corev1.PodSpec{
						ServiceAccountName: "audit-cluster-forwarding-vpn-gateway",
						Containers: []corev1.Container{
							{
								Name:            "gardener-vpn-gateway",
								Image:           gardenerVpnGatewayImage.String(),
								ImagePullPolicy: corev1.PullIfNotPresent,
								Env: []corev1.EnvVar{
									{
										Name:  "GATEWAY_SHOOT_KUBECONFIG",
										Value: path.Join(gutil.VolumeMountPathGenericKubeconfig, "kubeconfig"),
									},
									{
										Name:  "GATEWAY_SEED_NAMESPACE",
										Value: cluster.ObjectMeta.Name,
									},
									{
										Name:  "GATEWAY_NAMESPACE",
										Value: v1alpha1.ShootAudittailerNamespace,
									},
									{
										Name:  "GATEWAY_SERVICE_NAME",
										Value: "audittailer",
									},
								},
							},
						},
					},
				},
			},
		}

		if err := gutil.InjectGenericKubeconfig(vpnGateway, extensions.GenericTokenKubeconfigSecretNameFromCluster(cluster), shootAccessSecretName); err != nil {
			return nil, err
		}

		clusterForwarderObjects := []client.Object{
			vpnGateway,
			&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "audit-cluster-forwarding-vpn-gateway",
					Namespace: namespace,
					Labels: map[string]string{
						"app": "audit-cluster-forwarding-vpn-gateway",
					},
				},
				Spec: corev1.ServiceSpec{
					Selector: map[string]string{
						"app": "audit-cluster-forwarding-vpn-gateway",
					},
					Ports: []corev1.ServicePort{
						{
							Port:       9876,
							TargetPort: intstr.FromInt(9876),
						},
					},
				},
			},
			&corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "audit-cluster-forwarding-vpn-gateway",
					Namespace: namespace,
				},
			},
			&rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "audit-cluster-forwarding-vpn-gateway",
					Namespace: namespace,
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{
							"secrets",
						},
						Verbs: []string{
							"get",
							"list",
						},
					},
				},
			},
			&rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "audit-cluster-forwarding-vpn-gateway",
					Namespace: namespace,
				},
				Subjects: []rbacv1.Subject{
					{
						Kind:      "ServiceAccount",
						Name:      "audit-cluster-forwarding-vpn-gateway",
						Namespace: namespace,
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Role",
					Name:     "audit-cluster-forwarding-vpn-gateway",
				},
			},
		}

		objects = append(objects, clusterForwarderObjects...)
	}

	if pointer.SafeDeref(auditConfig.Backends.Splunk).Enabled {
		splunkConfig := map[string]string{
			"match":                    "audit",
			"name":                     "splunk",
			"storage.total_limit_size": defaultSplunkBufferSize,
			"host":                     auditConfig.Backends.Splunk.Host,
			"port":                     auditConfig.Backends.Splunk.Port,
			"splunk_token":             "${SPLUNK_HEC_TOKEN}",
			"retry_limit":              "False",
			"splunk_send_raw":          "Off",
			"event_source":             "statefulset:audit-webhook-backend",
			"event_sourcetype":         "kube:apiserver:auditlog",
			"event_index":              auditConfig.Backends.Splunk.Index,
			"event_host":               cluster.ObjectMeta.Name,
		}

		if auditConfig.Backends.Splunk.FilesystemBufferSize != "" {
			splunkConfig["storage.total_limit_size"] = auditConfig.Backends.Splunk.FilesystemBufferSize
		}

		if auditConfig.Backends.Splunk.TlsEnabled {
			splunkConfig["tls"] = "on"
			splunkConfig["tls.verify"] = "on"
		}
		if auditConfig.Backends.Splunk.CaFile != "" {
			splunkConfig["tls.ca_file "] = "/backends/splunk/certs/ca.crt"
		}

		fluentbitConfigMap.Data["splunk.backend.conf"] = fluentbitconfig.Config{
			Output: []fluentbitconfig.Output{splunkConfig},
		}.Generate()

		splunkSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "audit-splunk-secret",
				Namespace: namespace,
			},
			StringData: map[string]string{
				"splunk_hec_token": auditConfig.Backends.Splunk.Token,
			},
		}

		if auditConfig.Backends.Splunk.TlsEnabled {
			splunkSecret.StringData["ca.crt"] = auditConfig.Backends.Splunk.CaFile

			auditwebhookStatefulSet.Spec.Template.Spec.Volumes = append(auditwebhookStatefulSet.Spec.Template.Spec.Volumes, corev1.Volume{
				Name: "splunk-secret",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: splunkSecret.Name,
						Items: []corev1.KeyToPath{
							{
								Key:  "ca.crt",
								Path: "ca.crt",
							},
						},
					},
				},
			})
			auditwebhookStatefulSet.Spec.Template.Spec.Containers[0].VolumeMounts = append(auditwebhookStatefulSet.Spec.Template.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{
				Name:      "splunk-secret",
				MountPath: "/backends/splunk/certs",
			})
			auditwebhookStatefulSet.Spec.Template.Spec.Containers[0].Env = append(auditwebhookStatefulSet.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
				Name: "SPLUNK_HEC_TOKEN",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: splunkSecret.ObjectMeta.Name,
						},
						Key: "splunk_hec_token",
					},
				},
			})

			auditwebhookStatefulSet.Spec.Template.ObjectMeta.Annotations["checksum/splunk-secret"] = utils.ComputeSecretChecksum(splunkSecret.Data)

		}
		objects = append(objects, splunkSecret)
	}

	auditwebhookStatefulSet.Spec.Template.ObjectMeta.Annotations["checksum/secret-"+auditWebhookConfigSecret.Name] = utils.ComputeSecretChecksum(auditWebhookConfigSecret.Data)
	auditwebhookStatefulSet.Spec.Template.ObjectMeta.Annotations["checksum/config-"+fluentbitConfigMap.Name] = utils.ComputeConfigMapChecksum(fluentbitConfigMap.Data)

	return objects, nil
}

func webhookKubeconfig(namespace string) ([]byte, error) {
	var (
		contextName = "audit-webhook"
		url         = fmt.Sprintf("http://audit-webhook-backend.%s.svc.cluster.local:9880/audit", namespace)
	)

	config := &configv1.Config{
		CurrentContext: contextName,
		Clusters: []configv1.NamedCluster{
			{
				Name: contextName,
				Cluster: configv1.Cluster{
					Server: url,
				},
			},
		},
		Contexts: []configv1.NamedContext{
			{
				Name: contextName,
				Context: configv1.Context{
					Cluster:  contextName,
					AuthInfo: contextName,
				},
			},
		},
		AuthInfos: []configv1.NamedAuthInfo{
			{
				Name:     contextName,
				AuthInfo: configv1.AuthInfo{},
			},
		},
	}

	kubeconfig, err := runtime.Encode(configlatest.Codec, config)
	if err != nil {
		return nil, fmt.Errorf("unable to encode webhook kubeconfig: %w", err)
	}

	return kubeconfig, nil
}

func shootObjects(secrets map[string]*corev1.Secret) ([]client.Object, error) {
	audittailerImage, err := imagevector.ImageVector().FindImage("audittailer")
	if err != nil {
		return nil, fmt.Errorf("failed to find audittailer image: %w", err)
	}

	var (
		audittailerConfig = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "audittailer-config",
				Namespace: v1alpha1.ShootAudittailerNamespace,
				Labels: map[string]string{
					"app": "audittailer",
				},
			},
			Data: map[string]string{
				"fluent.conf": `
<source>
	@type forward
	port 24224
	bind 0.0.0.0
	<transport tls>
	ca_path                   /fluentd/etc/ssl/ca.crt
	cert_path                 /fluentd/etc/ssl/tls.crt
	private_key_path          /fluentd/etc/ssl/tls.key
	client_cert_auth          true
	</transport>
</source>
<match **>
	@type stdout
	<buffer>
	@type file
	path /fluentbuffer/auditlog-*
	chunk_limit_size          256Mb
	</buffer>
	<format>
	@type json
	</format>
</match>
`,
			},
		}
	)

	audittailerServerSecret := secrets["audittailer-server"].DeepCopy()
	audittailerServerSecret.Namespace = v1alpha1.ShootAudittailerNamespace
	audittailerServerSecret.ObjectMeta.ResourceVersion = ""

	return []client.Object{
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: v1alpha1.ShootAudittailerNamespace,
				Labels: map[string]string{
					"app": "audittailer",
				},
			},
		},
		audittailerServerSecret,
		audittailerConfig,
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "audittailer",
				Namespace: v1alpha1.ShootAudittailerNamespace,
				Labels: map[string]string{
					"app": "audittailer",
				},
			},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "audittailer",
					},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"app": "audittailer",
						},
						Annotations: map[string]string{
							"checksum/secret-audittailer-server":        utils.ComputeSecretChecksum(secrets["audittailer-server"].Data),
							"checksum/config-" + audittailerConfig.Name: utils.ComputeConfigMapChecksum(audittailerConfig.Data),
						},
					},
					Spec: corev1.PodSpec{
						AutomountServiceAccountToken: pointer.Pointer(false),
						Containers: []corev1.Container{
							{
								Name:            "audittailer",
								Image:           audittailerImage.String(),
								ImagePullPolicy: corev1.PullIfNotPresent,
								Env: []corev1.EnvVar{
									{
										// this is supposed to limit fluentd memory usage. See https://docs.fluentd.org/deployment/performance-tuning-single-process#reduce-memory-usage.
										Name:  "RUBY_GC_HEAP_OLDOBJECT_LIMIT_FACTOR",
										Value: "1.2",
									},
								},
								Ports: []corev1.ContainerPort{
									{
										ContainerPort: int32(24224),
										Protocol:      corev1.ProtocolTCP,
									},
								},
								VolumeMounts: []corev1.VolumeMount{
									{
										Name:      "fluentd-config",
										MountPath: "/fluentd/etc",
									},
									{
										Name:      "fluentd-certs",
										MountPath: "/fluentd/etc/ssl",
									},
									{
										Name:      "fluentbuffer",
										MountPath: "/fluentbuffer",
									},
								},
								Resources: corev1.ResourceRequirements{
									Requests: corev1.ResourceList{
										corev1.ResourceCPU:    resource.MustParse("100m"),
										corev1.ResourceMemory: resource.MustParse("200Mi"),
									},
									Limits: corev1.ResourceList{
										corev1.ResourceCPU:    resource.MustParse("150m"),
										corev1.ResourceMemory: resource.MustParse("512Mi"),
									},
								},
								SecurityContext: &corev1.SecurityContext{
									RunAsUser:                pointer.Pointer(int64(65534)),
									AllowPrivilegeEscalation: pointer.Pointer(false),
									SeccompProfile: &corev1.SeccompProfile{
										Type: corev1.SeccompProfileTypeRuntimeDefault,
									},
									Capabilities: &corev1.Capabilities{
										Drop: []corev1.Capability{
											"ALL",
										},
									},
								},
							},
						},
						RestartPolicy: corev1.RestartPolicyAlways,
						Volumes: []corev1.Volume{
							{
								Name: "fluentd-config",
								VolumeSource: corev1.VolumeSource{
									ConfigMap: &corev1.ConfigMapVolumeSource{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "audittailer-config",
										},
									},
								},
							},
							{
								Name: "fluentd-certs",
								VolumeSource: corev1.VolumeSource{
									Secret: &corev1.SecretVolumeSource{
										SecretName: secrets["audittailer-server"].Name,
									},
								},
							},
							{
								Name: "fluentbuffer",
								VolumeSource: corev1.VolumeSource{
									EmptyDir: &corev1.EmptyDirVolumeSource{},
								},
							},
						},
					},
				},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "audittailer",
				Namespace: v1alpha1.ShootAudittailerNamespace,
				Labels: map[string]string{
					"app": "audittailer",
				},
			},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{
					"app": "audittailer",
				},
				Ports: []corev1.ServicePort{
					{
						Port:       24224,
						TargetPort: intstr.FromInt(24224),
					},
				},
			},
		},
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "audittailer",
				Namespace: v1alpha1.ShootAudittailerNamespace,
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{
						"services",
						"secrets",
					},
					Verbs: []string{
						"get",
						"list",
					},
				},
			},
		},
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "audittailer",
				Namespace: v1alpha1.ShootAudittailerNamespace,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "audit-cluster-forwarding-vpn-gateway",
					Namespace: "kube-system",
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     "audittailer",
			},
		},
	}, nil
}
