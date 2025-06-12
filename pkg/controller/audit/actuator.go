package audit

import (
	"context"
	"fmt"
	"maps"
	"os"
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
	"github.com/metal-stack/metal-lib/pkg/pointer"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/metal-stack/gardener-extension-audit/pkg/apis/audit/v1alpha1"
	"github.com/metal-stack/gardener-extension-audit/pkg/apis/config"
	"github.com/metal-stack/gardener-extension-audit/pkg/controller/audit/backend"
	"github.com/metal-stack/gardener-extension-audit/pkg/fluentbitconfig"
	"github.com/metal-stack/gardener-extension-audit/pkg/imagevector"

	configlatest "k8s.io/client-go/tools/clientcmd/api/latest"
	configv1 "k8s.io/client-go/tools/clientcmd/api/v1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
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

	certs, err := a.generateCerts(ctx, log, cluster)
	if err != nil {
		return err
	}

	secrets := make(map[string]*corev1.Secret, len(certs)+len(defaultBackendSecrets))
	maps.Copy(secrets, defaultBackendSecrets)
	maps.Copy(secrets, certs)

	shootBackends, err := a.shootBackends(ctx, cluster, secrets, backends, namespace)
	if err != nil {
		return err
	}

	if err := a.createResources(ctx, log, auditConfig, cluster, shootBackends, namespace); err != nil {
		return err
	}

	return nil
}

func (a *actuator) shootBackends(ctx context.Context, cluster *extensions.Cluster, secrets map[string]*corev1.Secret, backends *v1alpha1.AuditBackends, namespace string) (map[string]backend.Backend, error) {
	backendMap := make(map[string]backend.Backend)
	if pointer.SafeDeref(backends.Log).Enabled {
		backendMap["log"] = backend.Log{}
	}

	if pointer.SafeDeref(backends.ClusterForwarding).Enabled {
		const (
			auditForwaderAccessSecretName = gutil.SecretNamePrefixShootAccess + "audit-cluster-forwarding-vpn-gateway"
		)

		shootAccessSecret := gutil.NewShootAccessSecret(auditForwaderAccessSecretName, namespace)
		if err := shootAccessSecret.Reconcile(ctx, a.client); err != nil {
			return nil, err
		}

		clusterForwardingBackend, err := backend.NewClusterForwarding(backends.ClusterForwarding,
			secrets["audittailer-client"],
			secrets["audittailer-server"],
			shootAccessSecret,
			pointer.SafeDeref(getReplicas(cluster, pointer.Pointer(int32(1)))),
		)
		if err != nil {
			return nil, fmt.Errorf("error creating cluster-forwarding backend: %w", err)
		}

		backendMap["cluster-forwarding"] = clusterForwardingBackend
	}

	if pointer.SafeDeref(backends.Splunk).Enabled {
		splunkSecret, err := a.findBackendSecret(ctx, cluster, secrets, backends.Splunk.SecretResourceName)
		if err != nil {
			return nil, err
		}

		splunkBackend, err := backend.NewSplunk(backends.Splunk, splunkSecret)
		if err != nil {
			return nil, fmt.Errorf("error creating splunk backend: %w", err)
		}

		backendMap["splunk"] = splunkBackend
	}

	if pointer.SafeDeref(backends.S3).Enabled {
		s3Secret, err := a.findBackendSecret(ctx, cluster, secrets, backends.S3.SecretResourceName)
		if err != nil {
			return nil, err
		}

		s3Backend, err := backend.NewS3(backends.S3, s3Secret)
		if err != nil {
			return nil, fmt.Errorf("error creating s3 backend: %w", err)
		}

		backendMap["s3"] = s3Backend
	}

	return backendMap, nil
}

// applyDefaultBackends adds default backends configured by the operator to the audit config in case this backend is not explicitly defined by the user.
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

func (a *actuator) ForceDelete(_ context.Context, _ logr.Logger, _ *extensionsv1alpha1.Extension) error {
	return nil
}

// Restore the Extension resource.
func (a *actuator) Restore(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return a.Reconcile(ctx, log, ex)
}

// Migrate the Extension resource.
func (a *actuator) Migrate(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return nil
}

func (a *actuator) createResources(ctx context.Context, log logr.Logger, auditConfig *v1alpha1.AuditConfig, cluster *extensions.Cluster, backends map[string]backend.Backend, namespace string) error {
	shootObjects := []client.Object{}
	for _, backend := range backends {
		shootObjects = append(shootObjects, backend.AdditionalShootObjects(cluster)...)
	}

	seedObjects, err := seedObjects(auditConfig, cluster, backends, namespace)
	if err != nil {
		return err
	}
	for _, backend := range backends {
		seedObjects = append(seedObjects, backend.AdditionalSeedObjects(cluster)...)
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

func seedObjects(auditConfig *v1alpha1.AuditConfig, cluster *extensions.Cluster, backends map[string]backend.Backend, namespace string) ([]client.Object, error) {
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
				Name:      "audit-webhook-backend",
				Namespace: namespace,
				Annotations: map[string]string{
					"checksum/secret-" + auditWebhookConfigSecret.Name: utils.ComputeSecretChecksum(auditWebhookConfigSecret.Data),
					"checksum/config-" + fluentbitConfigMap.Name:       utils.ComputeConfigMapChecksum(fluentbitConfigMap.Data),
				},
				Labels: map[string]string{},
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
							Resources: corev1.VolumeResourceRequirements{
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
				MinAvailable: pointer.Pointer(intstr.FromInt32(1)),
				Selector:     auditwebhookStatefulSet.Spec.Selector,
			},
		},
	}

	for name, backend := range backends {
		key := fmt.Sprintf("%s.backend.conf", name)
		fluentbitConfigMap.Data[key] = backend.FluentBitConfig(cluster).Generate()
		backend.PatchAuditWebhook(auditwebhookStatefulSet)
	}

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
