package backend

import (
	"errors"
	"fmt"
	"path"

	"github.com/gardener/gardener/pkg/extensions"
	"github.com/gardener/gardener/pkg/utils"
	gutil "github.com/gardener/gardener/pkg/utils/gardener"
	gardener_imagevector "github.com/gardener/gardener/pkg/utils/imagevector"
	"github.com/metal-stack/gardener-extension-audit/pkg/apis/audit/v1alpha1"
	"github.com/metal-stack/gardener-extension-audit/pkg/fluentbitconfig"
	"github.com/metal-stack/gardener-extension-audit/pkg/imagevector"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type ClusterForwarding struct {
	backend                 *v1alpha1.AuditBackendClusterForwarding
	gardenerVpnGatewayImage *gardener_imagevector.Image
	auditTailerImage        *gardener_imagevector.Image
	auditTailerServerSecret *corev1.Secret
	auditTailerClientSecret *corev1.Secret

	vpnGatewayReplicas int32
	shootAccessSecret  *gutil.AccessSecret
}

func NewClusterForwarding(backend *v1alpha1.AuditBackendClusterForwarding, auditTailerClientSecret, auditTailerServerSecret *corev1.Secret, shootAccessSecret *gutil.AccessSecret, vpnGatewayReplicas int32) (ClusterForwarding, error) {
	audittailerImage, err := imagevector.ImageVector().FindImage("audittailer")
	if err != nil {
		return ClusterForwarding{}, fmt.Errorf("failed to find audittailer image: %w", err)
	}

	gardenerVpnGatewayImage, err := imagevector.ImageVector().FindImage("gardener-vpn-gateway")
	if err != nil {
		return ClusterForwarding{}, fmt.Errorf("failed to find gardener-vpn-gateway image: %w", err)
	}

	if auditTailerClientSecret == nil {
		return ClusterForwarding{}, errors.New("secret audittailer-client can't be nil")
	}

	if auditTailerServerSecret == nil {
		return ClusterForwarding{}, errors.New("secret audittailer-server can't be nil")
	}

	return ClusterForwarding{
		backend:                 backend,
		gardenerVpnGatewayImage: gardenerVpnGatewayImage,
		auditTailerImage:        audittailerImage,
		auditTailerServerSecret: auditTailerServerSecret,
		auditTailerClientSecret: auditTailerClientSecret,
		vpnGatewayReplicas:      vpnGatewayReplicas,
		shootAccessSecret:       shootAccessSecret,
	}, nil
}

func (c ClusterForwarding) FluentBitConfig(*extensions.Cluster) fluentbitconfig.Config {
	forwardingConfig := map[string]string{
		"match":                    "audit",
		"name":                     "forward",
		"retry_limit":              "no_limits", // let fluent-bit never discard any data
		"storage.total_limit_size": pointer.SafeDeref(c.backend.FilesystemBufferSize),
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
	return fluentbitconfig.Config{
		Output: []fluentbitconfig.Output{forwardingConfig},
	}
}

func (c ClusterForwarding) PatchAuditWebhook(sts *appsv1.StatefulSet) {
	sts.Spec.Template.Spec.Containers[0].VolumeMounts = append(sts.Spec.Template.Spec.Containers[0].VolumeMounts,
		corev1.VolumeMount{
			Name:      "audittailer-client",
			MountPath: "/backends/cluster-forwarding/certs",
		})

	sts.Spec.Template.Spec.Volumes = append(sts.Spec.Template.Spec.Volumes,
		corev1.Volume{
			Name: "audittailer-client",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: c.auditTailerClientSecret.Name,
				},
			},
		},
	)
	sts.Spec.Template.Annotations["checksum/secret-audittailer-client"] = utils.ComputeSecretChecksum(c.auditTailerClientSecret.Data)
	sts.Spec.Template.Labels["networking.resources.gardener.cloud/to-audit-cluster-forwarding-vpn-gateway-tcp-9876"] = "allowed"
}

func (c ClusterForwarding) AdditionalShootObjects(*extensions.Cluster) []client.Object {
	audittailerConfig := &corev1.ConfigMap{
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

	audittailerServerSecret := c.auditTailerServerSecret.DeepCopy()
	audittailerServerSecret.Namespace = v1alpha1.ShootAudittailerNamespace
	audittailerServerSecret.ObjectMeta.ResourceVersion = ""

	return []client.Object{
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
							"checksum/secret-audittailer-server":        utils.ComputeSecretChecksum(c.auditTailerServerSecret.Data),
							"checksum/config-" + audittailerConfig.Name: utils.ComputeConfigMapChecksum(audittailerConfig.Data),
						},
					},
					Spec: corev1.PodSpec{
						AutomountServiceAccountToken: ptr.To(false),
						Containers: []corev1.Container{
							{
								Name:            "audittailer",
								Image:           c.auditTailerImage.String(),
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
									RunAsUser:                ptr.To(int64(65534)),
									RunAsNonRoot:             ptr.To(true),
									AllowPrivilegeEscalation: ptr.To(false),
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
										SecretName: audittailerServerSecret.Name,
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
	}
}

func (c ClusterForwarding) AdditionalSeedObjects(cluster *extensions.Cluster) []client.Object {
	// namespace of the control plane equals to the name of the cluster object
	namespace := cluster.ObjectMeta.Name

	vpnGateway := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "audit-cluster-forwarding-vpn-gateway",
			Namespace: namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &c.vpnGatewayReplicas,
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
							Image:           c.gardenerVpnGatewayImage.String(),
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

	if err := gutil.InjectGenericKubeconfig(vpnGateway, extensions.GenericTokenKubeconfigSecretNameFromCluster(cluster), c.shootAccessSecret.Secret.Name); err != nil {
		// if this should ever panic, it is a bug. InjectGenericKubeconfig will only error, if function can't inject a kubeconfig into the object.
		// Deployments are always possible to inject kubeconfigs into.
		panic(err)
	}
	return []client.Object{
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
}
