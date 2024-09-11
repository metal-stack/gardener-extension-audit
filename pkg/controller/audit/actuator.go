package audit

import (
	"context"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/gardener/gardener/extensions/pkg/controller/extension"

	"github.com/gardener/gardener/extensions/pkg/controller"
	extensionssecretsmanager "github.com/gardener/gardener/extensions/pkg/util/secret/manager"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
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
	"github.com/metal-stack/gardener-extension-audit/pkg/fluentbitconfig"
	"github.com/metal-stack/gardener-extension-audit/pkg/imagevector"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	configlatest "k8s.io/client-go/tools/clientcmd/api/latest"
	configv1 "k8s.io/client-go/tools/clientcmd/api/v1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NewActuator returns an actuator responsible for Extension resources.
func NewActuator(mgr manager.Manager, config config.ControllerConfiguration) extension.Actuator {
	return &actuator{
		client:  mgr.GetClient(),
		decoder: serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder(),
		config:  config,
	}
}

type actuator struct {
	client  client.Client
	decoder runtime.Decoder
	config  config.ControllerConfiguration
}

// Reconcile the Extension resource.
func (a *actuator) Reconcile(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	auditConfig := &v1alpha1.AuditConfig{}
	if ex.Spec.ProviderConfig != nil {
		if _, _, err := a.decoder.Decode(ex.Spec.ProviderConfig.Raw, nil, auditConfig); err != nil {
			return fmt.Errorf("failed to decode provider config: %w", err)
		}
	}

	backends, defaultBackendSecrets, err := a.applyDefaultBackends(ctx, log, auditConfig.Backends)
	if err != nil {
		log.Error(err, "unable to apply default backends configured by operator, continuing anyway but configuration of this extension needs to be checked")
	} else {
		auditConfig.Backends = backends
	}

	namespace := ex.GetNamespace()

	cluster, err := controller.GetCluster(ctx, a.client, namespace)
	if err != nil {
		return err
	}

	splunkSecret := &corev1.Secret{}
	if pointer.SafeDeref(auditConfig.Backends.Splunk).Enabled {
		splunkSecret, err = a.findBackendSecret(ctx, cluster, defaultBackendSecrets, auditConfig.Backends.Splunk.SecretResourceName)
		if err != nil {
			return err
		}

		_, ok := splunkSecret.Data[v1alpha1.SplunkSecretTokenKey]
		if !ok {
			return fmt.Errorf("referenced splunk secret does not contain contents under key %q", v1alpha1.SplunkSecretTokenKey)
		}
	}

	if err := a.createResources(ctx, log, auditConfig, cluster, splunkSecret, namespace); err != nil {
		return err
	}

	return nil
}

// applyDefaultBackends adds default backends configured by the operator to the audit config in case this backend is not explcitly defined by the user.
// it returns the backends to which defaults were applied and a map of secrets that contains secrets referenced by the operator's default backends.
func (a *actuator) applyDefaultBackends(ctx context.Context, log logr.Logger, backends *v1alpha1.AuditBackends) (*v1alpha1.AuditBackends, map[string]*corev1.Secret, error) {
	var (
		secrets   = map[string]*corev1.Secret{}
		addSecret = func(secretName string) error {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      os.Getenv("BACKEND_SECRET_PREFIX") + secretName,
					Namespace: os.Getenv("BACKEND_SECRET_NAMESPACE"),
				},
			}

			err := a.client.Get(ctx, client.ObjectKeyFromObject(secret), secret)
			if err != nil {
				return fmt.Errorf("unable to get default backend secret: %w", err)
			}

			secrets[secretName] = secret

			return nil
		}
	)

	if backends == nil {
		backends = &v1alpha1.AuditBackends{}
	}
	defaultedBackends := backends.DeepCopy()

	if a.config.DefaultBackends == nil {
		// no default backends configured by the operator, nothing needs to be defaulted
		return defaultedBackends, secrets, nil
	}

	if a.config.DefaultBackends.Log != nil && backends.Log == nil {
		log.Info(`configuring default backend "log"`)
		defaultedBackends.Log = a.config.DefaultBackends.Log
	}
	if a.config.DefaultBackends.ClusterForwarding != nil && backends.ClusterForwarding == nil {
		log.Info(`configuring default backend "cluster forwarding"`)
		defaultedBackends.ClusterForwarding = a.config.DefaultBackends.ClusterForwarding
	}
	if a.config.DefaultBackends.Splunk != nil && backends.Splunk == nil {
		log.Info(`configuring default backend "splunk"`)
		defaultedBackends.Splunk = a.config.DefaultBackends.Splunk

		err := addSecret(defaultedBackends.Splunk.SecretResourceName)
		if err != nil {
			return defaultedBackends, secrets, err
		}
	}

	v1alpha1.DefaultBackends(defaultedBackends)

	return defaultedBackends, secrets, nil
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

func (a *actuator) createResources(ctx context.Context, log logr.Logger, auditConfig *v1alpha1.AuditConfig, cluster *extensions.Cluster, splunkSecret *corev1.Secret, namespace string) error {
	const (
		auditForwaderAccessSecretName = gutil.SecretNamePrefixShootAccess + "audit-cluster-forwarding-vpn-gateway"
	)

	shootAccessSecret := gutil.NewShootAccessSecret(auditForwaderAccessSecretName, namespace)
	if err := shootAccessSecret.Reconcile(ctx, a.client); err != nil {
		return err
	}

	secrets, err := a.generateCerts(ctx, log, cluster)
	if err != nil {
		return err
	}

	shootObjects, err := shootObjects(auditConfig, secrets)
	if err != nil {
		return err
	}

	seedObjects, err := seedObjects(auditConfig, secrets, cluster, splunkSecret, shootAccessSecret.Secret.Name, namespace)
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

	// TODO: since k8s v1.27 there is a new feature to delete the pvc automatically when the statefulSet is deleted
	// https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/#persistentvolumeclaim-retention
	err := a.client.DeleteAllOf(ctx, &corev1.PersistentVolumeClaim{}, client.MatchingLabels{"app": "audit-webhook-backend"}, client.InNamespace(namespace))
	if err != nil {
		return err
	}

	return nil
}

func (a *actuator) generateCerts(ctx context.Context, log logr.Logger, cluster *extensions.Cluster) (map[string]*corev1.Secret, error) {
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

func seedObjects(auditConfig *v1alpha1.AuditConfig, secrets map[string]*corev1.Secret, cluster *extensions.Cluster, splunkSecretFromResources *corev1.Secret, shootAccessSecretName, namespace string) ([]client.Object, error) {
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
						"log_level": "info",

						"http_server": "on",
						"http_listen": "0.0.0.0",
						"http_port":   "2020",

						"storage.path":              "/data/",
						"storage.sync":              "normal",
						"storage.checksum":          "off",
						"storage.max_chunks_up":     "128",
						"storage.backlog.mem_limit": "5M",

						"scheduler.base": "1",
						"scheduler.cap":  "60", // try to send records every 60s

						"health_check":           "on",
						"hc_errors_count":        "0",
						"hc_retry_failure_count": "0",
						"hc_period":              "60",
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
				"null.backend.conf": fluentbitconfig.Config{
					// the null backend is for the case when no backends are configured and fluentbit will still start up
					// as when this happens, it will fail because the backend conf include does not match any file
					Output: []fluentbitconfig.Output{
						map[string]string{
							"match": "audit",
							"name":  "null",
						},
					},
				}.Generate(),
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
				Replicas:    getReplicas(cluster, auditConfig.Replicas),
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
							"networking.gardener.cloud/to-private-networks":                                        "allowed",
							"networking.gardener.cloud/to-public-networks":                                         "allowed",
							"networking.gardener.cloud/from-shoot-apiserver":                                       "allowed",
							"networking.resources.gardener.cloud/to-audit-cluster-forwarding-vpn-gateway-tcp-9876": "allowed",
						},
						Annotations: map[string]string{
							"scheduler.alpha.kubernetes.io/critical-pod":              "",
							"networking.resources.gardener.cloud/to-world-from-ports": `[{"port":2020,"protocol":"TCP"}]`,
							"prometheus.io/scrape":                                    "true",
							"prometheus.io/port":                                      "2020",
							"prometheus.io/path":                                      "/api/v1/metrics/prometheus",
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
		fluentbitConfigMap,
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "audit-webhook-backend",
				Namespace: namespace,
				Annotations: map[string]string{
					"networking.resources.gardener.cloud/pod-label-selector-namespace-alias": "all-shoots",
					"networking.resources.gardener.cloud/namespace-selectors":                `[{"matchLabels":{"gardener.cloud/role":"extension"}}]`,
				},
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
					{
						Name:     "api",
						Port:     2020,
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
					"retry_limit":              "no_limits", // let fluent-bit never discard any data
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
			"retry_limit":              "no_limits", // let fluent-bit never discard any data
			"storage.total_limit_size": pointer.SafeDeref(auditConfig.Backends.ClusterForwarding.FilesystemBufferSize),
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
				Replicas: getReplicas(cluster, pointer.Pointer(int32(1))),
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
			"retry_limit":              "no_limits", // let fluent-bit never discard any data
			"storage.total_limit_size": pointer.SafeDeref(auditConfig.Backends.Splunk.FilesystemBufferSize),
			"host":                     auditConfig.Backends.Splunk.Host,
			"port":                     auditConfig.Backends.Splunk.Port,
			"splunk_token":             "${SPLUNK_HEC_TOKEN}",
			"splunk_send_raw":          "off",
			"event_source":             "statefulset:" + auditwebhookStatefulSet.Name,
			"event_sourcetype":         "kube:apiserver:auditlog",
			"event_index":              auditConfig.Backends.Splunk.Index,
			"event_host":               cluster.ObjectMeta.Name,
		}

		if auditConfig.Backends.Splunk.TlsEnabled {
			splunkConfig["tls"] = "on"
			splunkConfig["tls.verify"] = "on"
			if auditConfig.Backends.Splunk.TlsHost != "" {
				splunkConfig["tls.vhost"] = auditConfig.Backends.Splunk.TlsHost
			}
		}

		splunkSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "audit-splunk-secret",
				Namespace: namespace,
			},
			Data: map[string][]byte{
				"splunk_hec_token": splunkSecretFromResources.Data[v1alpha1.SplunkSecretTokenKey],
			},
		}

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

		caFile := splunkSecretFromResources.Data[v1alpha1.SplunkSecretCaFileKey]
		if len(caFile) > 0 {
			splunkConfig["tls.ca_file"] = "/backends/splunk/certs/ca.crt"

			splunkSecret.Data["ca.crt"] = caFile

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
		}

		auditwebhookStatefulSet.Spec.Template.ObjectMeta.Annotations["checksum/splunk-secret"] = utils.ComputeSecretChecksum(splunkSecret.Data)

		objects = append(objects, splunkSecret)

		fluentbitConfigMap.Data["splunk.backend.conf"] = fluentbitconfig.Config{
			Output: []fluentbitconfig.Output{splunkConfig},
		}.Generate()
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

func shootObjects(auditConfig *v1alpha1.AuditConfig, secrets map[string]*corev1.Secret) ([]client.Object, error) {
	if !pointer.SafeDeref(auditConfig.Backends.ClusterForwarding).Enabled {
		return nil, nil
	}

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
									RunAsNonRoot:             pointer.Pointer(true),
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

func (a *actuator) findBackendSecret(ctx context.Context, cluster *extensions.Cluster, defaultBackendSecrets map[string]*corev1.Secret, secretName string) (*corev1.Secret, error) {
	fromShootResources := func() (*corev1.Secret, error) {
		secretRef := helper.GetResourceByName(cluster.Shoot.Spec.Resources, secretName)
		if secretRef == nil {
			return nil, nil
		}

		secret := &corev1.Secret{}
		err := controller.GetObjectByReference(ctx, a.client, &secretRef.ResourceRef, cluster.ObjectMeta.Name, secret)
		if err != nil {
			return nil, fmt.Errorf("unable to get referenced secret: %w", err)
		}

		return secret, nil
	}

	secret, err := fromShootResources()
	if err != nil {
		return nil, err
	}

	if secret == nil {
		// if the secret is not referenced in the shoot resources it may be defined in the default backend secrets
		if len(defaultBackendSecrets) > 0 {
			var ok bool
			secret, ok = defaultBackendSecrets[secretName]
			if !ok {
				return nil, fmt.Errorf("secret resource with name %q not found in default backend secrets", secretName)
			}
		} else {
			return nil, fmt.Errorf("secret resource with name %q not found in shoot resources", secretName)
		}
	}

	return secret, nil
}

func getReplicas(cluster *extensions.Cluster, wokenUp *int32) *int32 {
	if controller.IsHibernated(cluster) {
		return pointer.Pointer(int32(0))
	}

	return wokenUp
}
