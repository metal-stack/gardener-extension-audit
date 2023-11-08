package kapiserver

import (
	"context"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gcontext "github.com/gardener/gardener/extensions/pkg/webhook/context"

	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	"github.com/go-logr/logr"

	"sigs.k8s.io/controller-runtime/pkg/client"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// NewEnsurer creates a new controlplane ensurer.
func NewEnsurer(logger logr.Logger) genericmutator.Ensurer {
	return &ensurer{
		logger: logger.WithName("audit-controlplane-ensurer"),
	}
}

type ensurer struct {
	genericmutator.NoopEnsurer
	client client.Client
	logger logr.Logger
}

// InjectClient injects the given client into the ensurer.
func (e *ensurer) InjectClient(client client.Client) error {
	e.client = client
	return nil
}

// EnsureKubeAPIServerDeployment ensures that the kube-apiserver deployment conforms to the provider requirements.
func (e *ensurer) EnsureKubeAPIServerDeployment(ctx context.Context, _ gcontext.GardenContext, new, _ *appsv1.Deployment) error {
	template := &new.Spec.Template
	ps := &template.Spec
	if c := extensionswebhook.ContainerWithName(ps.Containers, "kube-apiserver"); c != nil {
		e.logger.Info("ensuring kube-apiserver deployment")
		ensureKubeAPIServerCommandLineArgs(c)
		ensureVolumeMounts(c)
		ensureVolumes(ps)
	}

	return nil
}

func ensureVolumeMounts(c *corev1.Container) {
	c.VolumeMounts = extensionswebhook.EnsureVolumeMountWithName(c.VolumeMounts, corev1.VolumeMount{
		Name:      "audit-policy",
		ReadOnly:  true,
		MountPath: "/etc/audit-webhook/policy",
	})
	c.VolumeMounts = extensionswebhook.EnsureVolumeMountWithName(c.VolumeMounts, corev1.VolumeMount{
		Name:      "audit-webhook-config",
		ReadOnly:  true,
		MountPath: "/etc/audit-webhook/config",
	})
}

func ensureVolumes(ps *corev1.PodSpec) {
	ps.Volumes = extensionswebhook.EnsureVolumeWithName(ps.Volumes, corev1.Volume{
		Name: "audit-policy",
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: "audit-policy",
				},
			},
		},
	})
	ps.Volumes = extensionswebhook.EnsureVolumeWithName(ps.Volumes, corev1.Volume{
		Name: "audit-webhook-config",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: "audit-webhook-config",
			},
		},
	})
}

func ensureKubeAPIServerCommandLineArgs(c *corev1.Container) {
	c.Command = extensionswebhook.EnsureStringWithPrefix(c.Command, "--audit-policy-file=", "/etc/audit-webhook/policy/audit-policy.yaml")
	c.Command = extensionswebhook.EnsureStringWithPrefix(c.Command, "--audit-webhook-config-file=", "/etc/audit-webhook/config/audit-webhook-config.yaml")
	c.Command = extensionswebhook.EnsureStringWithPrefix(c.Command, "--audit-webhook-mode=", "blocking")
}

// makeAuditForwarder := false
// if validation.ClusterAuditEnabled(&e.controllerConfig, cpConfig) {
// 	makeAuditForwarder = true
// }
// if makeAuditForwarder {
// 	audittailersecret := &corev1.Secret{}
// 	if err := e.client.Get(ctx, kutil.Key(cluster.ObjectMeta.Name, gutil.SecretNamePrefixShootAccess+metal.AudittailerClientSecretName), audittailersecret); err != nil {
// 		logger.Error(err, "could not get secret for cluster", "secret", gutil.SecretNamePrefixShootAccess+metal.AudittailerClientSecretName, "cluster name", cluster.ObjectMeta.Name)
// 		makeAuditForwarder = false
// 	}
// 	if len(audittailersecret.Data) == 0 {
// 		logger.Error(err, "token for secret not yet set in cluster", "secret", gutil.SecretNamePrefixShootAccess+metal.AudittailerClientSecretName, "cluster name", cluster.ObjectMeta.Name)
// 		makeAuditForwarder = false
// 	}
// }

// auditToSplunk := false
// if validation.AuditToSplunkEnabled(&e.controllerConfig, cpConfig) {
// 	auditToSplunk = true
// }
// if c := extensionswebhook.ContainerWithName(ps.Containers, "kube-apiserver"); c != nil {
// 	ensureKubeAPIServerCommandLineArgs(c, makeAuditForwarder)
// 	ensureVolumeMounts(c, makeAuditForwarder)
// 	ensureVolumes(ps, makeAuditForwarder, auditToSplunk)
// }
// if c := extensionswebhook.ContainerWithName(ps.Containers, "vpn-seed"); c != nil {
// 	ensureVPNSeedEnvVars(c, nodeCIDR)
// }
// if makeAuditForwarder {
// 	err := ensureAuditForwarder(ps, auditToSplunk)
// 	if err != nil {
// 		logger.Error(err, "could not ensure the audit forwarder", "Cluster name", cluster.ObjectMeta.Name)
// 		return err
// 	}
// 	if auditToSplunk {
// 		err := controlplane.EnsureConfigMapChecksumAnnotation(ctx, &new.Spec.Template, e.client, new.Namespace, metal.AuditForwarderSplunkConfigName)
// 		if err != nil {
// 			logger.Error(err, "could not ensure the splunk config map checksum annotation", "cluster name", cluster.ObjectMeta.Name, "configmap", metal.AuditForwarderSplunkConfigName)
// 			return err
// 		}
// 		err = controlplane.EnsureSecretChecksumAnnotation(ctx, &new.Spec.Template, e.client, new.Namespace, metal.AuditForwarderSplunkSecretName)
// 		if err != nil {
// 			logger.Error(err, "could not ensure the splunk secret checksum annotation", "cluster name", cluster.ObjectMeta.Name, "secret", metal.AuditForwarderSplunkSecretName)
// 			return err
// 		}
// 	}
// }

// pre apiserver
// {{- if .Values.clusterAudit.enabled }}
// apiVersion: v1
// kind: ConfigMap
// metadata:
//   name: audit-policy-override
//   namespace: {{ .Release.Namespace }}
// data:
//   audit-policy.yaml: |
//     ---
//     apiVersion: audit.k8s.io/v1
//     kind: Policy
//     rules:
//       # The following requests were manually identified as high-volume and low-risk,
//       # so drop them.
//       - level: None
//         resources:
//           - group: ""
//             resources:
//               - endpoints
//               - services
//               - services/status
//         users:
//           - 'system:kube-proxy'
//         verbs:
//           - watch
//       - level: None
//         resources:
//           - group: ""
//             resources:
//               - nodes
//               - nodes/status
//         userGroups:
//           - 'system:nodes'
//         verbs:
//           - get
//       - level: None
//         namespaces:
//           - kube-system
//         resources:
//           - group: ""
//             resources:
//               - endpoints
//         users:
//           - 'system:kube-controller-manager'
//           - 'system:kube-scheduler'
//           - 'system:serviceaccount:kube-system:endpoint-controller'
//         verbs:
//           - get
//           - update
//       - level: None
//         resources:
//           - group: ""
//             resources:
//               - namespaces
//               - namespaces/status
//               - namespaces/finalize
//         users:
//           - 'system:apiserver'
//         verbs:
//           - get
//       # Don't log HPA fetching metrics.
//       - level: None
//         resources:
//           - group: metrics.k8s.io
//         users:
//           - 'system:kube-controller-manager'
//         verbs:
//           - get
//           - list
//       # Don't log these read-only URLs.
//       - level: None
//         nonResourceURLs:
//           - '/healthz*'
//           - /version
//           - '/swagger*'
//       # Don't log events requests.
//       - level: None
//         resources:
//           - group: ""
//             resources:
//               - events
//       # node and pod status calls from nodes are high-volume and can be large, don't log responses for expected updates from nodes
//       - level: Request
//         omitStages:
//           - RequestReceived
//         resources:
//           - group: ""
//             resources:
//               - nodes/status
//               - pods/status
//         users:
//           - kubelet
//           - 'system:node-problem-detector'
//           - 'system:serviceaccount:kube-system:node-problem-detector'
//         verbs:
//           - update
//           - patch
//       - level: Request
//         omitStages:
//           - RequestReceived
//         resources:
//           - group: ""
//             resources:
//               - nodes/status
//               - pods/status
//         userGroups:
//           - 'system:nodes'
//         verbs:
//           - update
//           - patch
//       # deletecollection calls can be large, don't log responses for expected namespace deletions
//       - level: Request
//         omitStages:
//           - RequestReceived
//         users:
//           - 'system:serviceaccount:kube-system:namespace-controller'
//         verbs:
//           - deletecollection
//       # Secrets, ConfigMaps, and TokenReviews can contain sensitive & binary data,
//       # so only log at the Metadata level.
//       - level: Metadata
//         omitStages:
//           - RequestReceived
//         resources:
//           - group: ""
//             resources:
//               - secrets
//               - configmaps
//           - group: authentication.k8s.io
//             resources:
//               - tokenreviews
//       # Get repsonses can be large; skip them.
//       - level: Request
//         omitStages:
//           - RequestReceived
//         resources:
//           - group: ""
//           - group: admissionregistration.k8s.io
//           - group: apiextensions.k8s.io
//           - group: apiregistration.k8s.io
//           - group: apps
//           - group: authentication.k8s.io
//           - group: authorization.k8s.io
//           - group: autoscaling
//           - group: batch
//           - group: certificates.k8s.io
//           - group: extensions
//           - group: metrics.k8s.io
//           - group: networking.k8s.io
//           - group: policy
//           - group: rbac.authorization.k8s.io
//           - group: scheduling.k8s.io
//           - group: settings.k8s.io
//           - group: storage.k8s.io
//         verbs:
//           - get
//           - list
//           - watch
//       # Default level for known APIs
//       - level: RequestResponse
//         omitStages:
//           - RequestReceived
//         resources:
//           - group: ""
//           - group: admissionregistration.k8s.io
//           - group: apiextensions.k8s.io
//           - group: apiregistration.k8s.io
//           - group: apps
//           - group: authentication.k8s.io
//           - group: authorization.k8s.io
//           - group: autoscaling
//           - group: batch
//           - group: certificates.k8s.io
//           - group: extensions
//           - group: metrics.k8s.io
//           - group: networking.k8s.io
//           - group: policy
//           - group: rbac.authorization.k8s.io
//           - group: scheduling.k8s.io
//           - group: settings.k8s.io
//           - group: storage.k8s.io
//       # Default level for all other requests.
//       - level: Metadata
//         omitStages:
//           - RequestReceived
// {{- end }}
// {{- if .Values.auditToSplunk.enabled }}
// ---
// apiVersion: v1
// kind: Secret
// metadata:
//   name: audit-to-splunk-secret
//   namespace: {{ .Release.Namespace }}
// type: Opaque
// data:
//   splunk_hec_token: {{ .Values.auditToSplunk.hecToken | b64enc }}
// {{- if .Values.auditToSplunk.hecCAFile }}
//   splunk-ca.pem: {{ .Values.auditToSplunk.hecCAFile | b64enc }}
// {{- end }}
// ---
// apiVersion: v1
// kind: ConfigMap
// metadata:
//   name: audit-to-splunk-config
//   namespace: {{ .Release.Namespace }}
// data:
//   splunk.conf: |
//     [FILTER]
//         Name                rewrite_tag
//         Match               audit
//         Rule                $kind Event tosplunk true

//     [OUTPUT]
//         Name                splunk
//         Match               tosplunk
//         Host                {{ .Values.auditToSplunk.hecHost }}
//         Port                {{ .Values.auditToSplunk.hecPort }}
//         Splunk_Token        ${SPLUNK_HEC_TOKEN}
// {{- if .Values.auditToSplunk.tlsEnabled }}
//         TLS                 On
//         TLS.Verify          On
// {{- end }}
// {{- if .Values.auditToSplunk.hecCAFile }}
//         TLS.CA_File         /fluent-bit/etc/splunkca/splunk-ca.pem
// {{- end }}
//         Retry_Limit         False
//         Splunk_Send_Raw     Off
//         Event_Source        ${MY_POD_NAME}
//         Event_Sourcetype    kube:apiserver:auditlog
//         Event_Index         {{ .Values.auditToSplunk.index }}
//         Event_Host          {{ .Values.auditToSplunk.clusterName }}
// {{- end }}

// func (a *actuator) splunkConfigurationValues(ctx context.Context, cluster *controller.Cluster) (*audit.AuditToSplunk, error) {
// 	config := a.config.AuditToSplunk.DeepCopy()

// 	if controller.IsHibernated(cluster) {
// 		return config, nil
// 	}

// 	shootConfig, _, err := util.NewClientForShoot(ctx, vp.Client(), clusterName, client.Options{}, extensionsconfig.RESTOptions{})
// 	if err != nil {
// 		return auditToSplunkValues, err
// 	}

// 	cs, err := kubernetes.NewForConfig(shootConfig)
// 	if err != nil {
// 		return auditToSplunkValues, err
// 	}

// 	splunkConfigSecret, err := cs.CoreV1().Secrets("kube-system").Get(ctx, "splunk-config", metav1.GetOptions{})
// 	if err != nil {
// 		if apierrors.IsNotFound(err) {
// 			return auditToSplunkValues, nil
// 		}
// 		return nil, err
// 	}

// 	if splunkConfigSecret.Data == nil {
// 		vp.logger.Error(errors.New("secret is empty"), "custom splunk config secret contains no data")
// 		return auditToSplunkValues, nil
// 	}

// 	for key, value := range splunkConfigSecret.Data {
// 		switch key {
// 		case "hecToken":
// 			auditToSplunkValues[key] = string(value)
// 		case "index":
// 			auditToSplunkValues[key] = string(value)
// 		case "hecHost":
// 			auditToSplunkValues[key] = string(value)
// 		case "hecPort":
// 			auditToSplunkValues[key] = string(value)
// 		case "tlsEnabled":
// 			auditToSplunkValues[key] = string(value)
// 		case "hecCAFile":
// 			auditToSplunkValues[key] = string(value)
// 		}
// 	}

// 	return auditToSplunkValues, nil
// }

// var (
// 	// config mount for the audit policy; it gets mounted where the kube-apiserver expects its audit policy.
// 	auditPolicyVolumeMount = corev1.VolumeMount{
// 		Name:      metal.AuditPolicyName,
// 		MountPath: "/etc/kubernetes/audit-override",
// 		ReadOnly:  true,
// 	}
// 	auditPolicyVolume = corev1.Volume{
// 		Name: metal.AuditPolicyName,
// 		VolumeSource: corev1.VolumeSource{
// 			ConfigMap: &corev1.ConfigMapVolumeSource{
// 				LocalObjectReference: corev1.LocalObjectReference{Name: metal.AuditPolicyName},
// 			},
// 		},
// 	}
// 	auditForwarderSplunkConfigVolumeMount = corev1.VolumeMount{
// 		Name:      metal.AuditForwarderSplunkConfigName,
// 		MountPath: "/fluent-bit/etc/add",
// 		ReadOnly:  true,
// 	}
// 	auditForwarderSplunkConfigVolume = corev1.Volume{
// 		Name: metal.AuditForwarderSplunkConfigName,
// 		VolumeSource: corev1.VolumeSource{
// 			ConfigMap: &corev1.ConfigMapVolumeSource{
// 				LocalObjectReference: corev1.LocalObjectReference{Name: metal.AuditForwarderSplunkConfigName},
// 			},
// 		},
// 	}
// 	auditForwarderSplunkSecretVolumeMount = corev1.VolumeMount{
// 		Name:      metal.AuditForwarderSplunkSecretName,
// 		MountPath: "/fluent-bit/etc/splunkca",
// 		ReadOnly:  true,
// 	}
// 	auditForwarderSplunkSecretVolume = corev1.Volume{
// 		Name: metal.AuditForwarderSplunkSecretName,
// 		VolumeSource: corev1.VolumeSource{
// 			Secret: &corev1.SecretVolumeSource{
// 				SecretName: metal.AuditForwarderSplunkSecretName,
// 			},
// 		},
// 	}
// 	auditForwarderSplunkPodNameEnvVar = corev1.EnvVar{
// 		Name: "MY_POD_NAME",
// 		ValueFrom: &corev1.EnvVarSource{
// 			FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"},
// 		},
// 	}
// 	auditForwarderSplunkHECTokenEnvVar = corev1.EnvVar{
// 		Name: "SPLUNK_HEC_TOKEN",
// 		ValueFrom: &corev1.EnvVarSource{
// 			SecretKeyRef: &corev1.SecretKeySelector{
// 				LocalObjectReference: corev1.LocalObjectReference{
// 					Name: metal.AuditForwarderSplunkSecretName,
// 				},
// 				Key: "splunk_hec_token",
// 			},
// 		},
// 	}
// 	auditLogVolumeMount = corev1.VolumeMount{
// 		Name:      "auditlog",
// 		MountPath: "/auditlog",
// 		ReadOnly:  false,
// 	}
// 	auditLogVolume = corev1.Volume{
// 		Name: "auditlog",
// 		VolumeSource: corev1.VolumeSource{
// 			EmptyDir: &corev1.EmptyDirVolumeSource{},
// 		},
// 	}
// 	auditKubeconfig = corev1.Volume{
// 		Name: "kubeconfig",
// 		VolumeSource: corev1.VolumeSource{
// 			Projected: &corev1.ProjectedVolumeSource{
// 				DefaultMode: pointer.Pointer(int32(420)),
// 				Sources: []corev1.VolumeProjection{
// 					{
// 						Secret: &corev1.SecretProjection{
// 							Items: []corev1.KeyToPath{
// 								{
// 									Key:  "kubeconfig",
// 									Path: "kubeconfig",
// 								},
// 							},
// 							Optional: pointer.Pointer(false),
// 							LocalObjectReference: corev1.LocalObjectReference{
// 								Name: v1beta1constants.SecretNameGenericTokenKubeconfig,
// 							},
// 						},
// 					},
// 					{
// 						Secret: &corev1.SecretProjection{
// 							Items: []corev1.KeyToPath{
// 								{
// 									Key:  "token",
// 									Path: "token",
// 								},
// 							},
// 							Optional: pointer.Pointer(false),
// 							LocalObjectReference: corev1.LocalObjectReference{
// 								Name: gutil.SecretNamePrefixShootAccess + metal.AudittailerClientSecretName,
// 							},
// 						},
// 					},
// 				},
// 			},
// 		},
// 	}
// 	reversedVpnVolumeMounts = []corev1.VolumeMount{
// 		{
// 			Name:      "ca-vpn",
// 			MountPath: "/proxy/ca",
// 			ReadOnly:  true,
// 		},
// 		{
// 			Name:      "http-proxy",
// 			MountPath: "/proxy/client",
// 			ReadOnly:  true,
// 		},
// 	}
// 	kubeAggregatorClientTlsEnvVars = []corev1.EnvVar{
// 		{
// 			Name:  "AUDIT_PROXY_CA_FILE",
// 			Value: "/proxy/ca/bundle.crt",
// 		},
// 		{
// 			Name:  "AUDIT_PROXY_CLIENT_CRT_FILE",
// 			Value: "/proxy/client/tls.crt",
// 		},
// 		{
// 			Name:  "AUDIT_PROXY_CLIENT_KEY_FILE",
// 			Value: "/proxy/client/tls.key",
// 		},
// 	}
// 	auditForwarderSidecarTemplate = corev1.Container{
// 		Name: "auditforwarder",
// 		// Image:   // is added from the image vector in the ensure function
// 		ImagePullPolicy: "Always",
// 		Env: []corev1.EnvVar{
// 			{
// 				Name:  "AUDIT_KUBECFG",
// 				Value: path.Join(gutil.VolumeMountPathGenericKubeconfig, "kubeconfig"),
// 			},
// 			{
// 				Name:  "AUDIT_NAMESPACE",
// 				Value: metal.AudittailerNamespace,
// 			},
// 			{
// 				Name:  "AUDIT_SERVICE_NAME",
// 				Value: "audittailer",
// 			},
// 			{
// 				Name:  "AUDIT_SECRET_NAME",
// 				Value: metal.AudittailerClientSecretName,
// 			},
// 			{
// 				Name:  "AUDIT_AUDIT_LOG_PATH",
// 				Value: "/auditlog/audit.log",
// 			},
// 			{
// 				Name:  "AUDIT_TLS_CA_FILE",
// 				Value: "ca.crt",
// 			},
// 			{
// 				Name:  "AUDIT_TLS_CRT_FILE",
// 				Value: "tls.crt",
// 			},
// 			{
// 				Name:  "AUDIT_TLS_KEY_FILE",
// 				Value: "tls.key",
// 			},
// 			{
// 				Name:  "AUDIT_TLS_VHOST",
// 				Value: "audittailer",
// 			},
// 		},
// 		Resources: corev1.ResourceRequirements{
// 			Requests: corev1.ResourceList{
// 				corev1.ResourceCPU:    resource.MustParse("50m"),
// 				corev1.ResourceMemory: resource.MustParse("100Mi"),
// 			},
// 			Limits: corev1.ResourceList{
// 				corev1.ResourceCPU:    resource.MustParse("100m"),
// 				corev1.ResourceMemory: resource.MustParse("500Mi"),
// 			},
// 		},
// 		VolumeMounts: []corev1.VolumeMount{
// 			{
// 				Name:      "kubeconfig",
// 				MountPath: gutil.VolumeMountPathGenericKubeconfig,
// 				ReadOnly:  true,
// 			},
// 			auditLogVolumeMount,
// 		},
// 	}
// )

// func ensureVolumeMounts(c *corev1.Container, makeAuditForwarder bool) {
// 	if makeAuditForwarder {
// 		c.VolumeMounts = extensionswebhook.EnsureVolumeMountWithName(c.VolumeMounts, auditPolicyVolumeMount)
// 		c.VolumeMounts = extensionswebhook.EnsureVolumeMountWithName(c.VolumeMounts, auditLogVolumeMount)
// 	}
// }

// func ensureVolumes(ps *corev1.PodSpec, makeAuditForwarder, auditToSplunk bool) {
// 	if makeAuditForwarder {
// 		ps.Volumes = extensionswebhook.EnsureVolumeWithName(ps.Volumes, auditKubeconfig)
// 		ps.Volumes = extensionswebhook.EnsureVolumeWithName(ps.Volumes, auditPolicyVolume)
// 		ps.Volumes = extensionswebhook.EnsureVolumeWithName(ps.Volumes, auditLogVolume)
// 	}
// 	if auditToSplunk {
// 		ps.Volumes = extensionswebhook.EnsureVolumeWithName(ps.Volumes, auditForwarderSplunkConfigVolume)
// 		ps.Volumes = extensionswebhook.EnsureVolumeWithName(ps.Volumes, auditForwarderSplunkSecretVolume)
// 	}
// }

// func ensureKubeAPIServerCommandLineArgs(c *corev1.Container, makeAuditForwarder bool) {
// 	c.Command = extensionswebhook.EnsureStringWithPrefix(c.Command, "--cloud-provider=", "external")

// 	if makeAuditForwarder {
// 		c.Command = extensionswebhook.EnsureStringWithPrefix(c.Command, "--audit-policy-file=", "/etc/kubernetes/audit-override/audit-policy.yaml")
// 		c.Command = extensionswebhook.EnsureStringWithPrefix(c.Command, "--audit-log-path=", "/auditlog/audit.log")
// 		c.Command = extensionswebhook.EnsureStringWithPrefix(c.Command, "--audit-log-maxsize=", "100")
// 		c.Command = extensionswebhook.EnsureStringWithPrefix(c.Command, "--audit-log-maxbackup=", "1")
// 	}
// }

// func ensureAuditForwarder(ps *corev1.PodSpec, auditToSplunk bool) error {
// 	auditForwarderSidecar := auditForwarderSidecarTemplate.DeepCopy()
// 	auditForwarderImage, err := imagevector.ImageVector().FindImage("auditforwarder")
// 	if err != nil {
// 		logger.Error(err, "Could not find auditforwarder image in imagevector")
// 		return err
// 	}
// 	auditForwarderSidecar.Image = auditForwarderImage.String()

// 	var proxyHost string

// 	for _, volume := range ps.Volumes {
// 		switch volume.Name {
// 		case "egress-selection-config":
// 			proxyHost = "vpn-seed-server"
// 		}
// 	}

// 	if proxyHost != "" {
// 		err := ensureAuditForwarderProxy(auditForwarderSidecar, proxyHost)
// 		if err != nil {
// 			logger.Error(err, "could not ensure auditForwarder proxy")
// 			return err
// 		}
// 	}

// 	if auditToSplunk {
// 		auditForwarderSidecar.VolumeMounts = extensionswebhook.EnsureVolumeMountWithName(auditForwarderSidecar.VolumeMounts, auditForwarderSplunkConfigVolumeMount)
// 		auditForwarderSidecar.VolumeMounts = extensionswebhook.EnsureVolumeMountWithName(auditForwarderSidecar.VolumeMounts, auditForwarderSplunkSecretVolumeMount)
// 		auditForwarderSidecar.Env = extensionswebhook.EnsureEnvVarWithName(auditForwarderSidecar.Env, auditForwarderSplunkPodNameEnvVar)
// 		auditForwarderSidecar.Env = extensionswebhook.EnsureEnvVarWithName(auditForwarderSidecar.Env, auditForwarderSplunkHECTokenEnvVar)
// 	}

// 	logger.Info("ensuring audit forwarder sidecar", "container", auditForwarderSidecar.Name)

// 	ps.Containers = extensionswebhook.EnsureContainerWithName(ps.Containers, *auditForwarderSidecar)
// 	return nil
// }

// func ensureAuditForwarderProxy(auditForwarderSidecar *corev1.Container, proxyHost string) error {
// 	logger.Info("ensureAuditForwarderProxy called", "proxyHost=", proxyHost)
// 	proxyEnvVars := []corev1.EnvVar{
// 		{
// 			Name:  "AUDIT_PROXY_HOST",
// 			Value: proxyHost,
// 		},
// 		{
// 			Name:  "AUDIT_PROXY_PORT",
// 			Value: "9443",
// 		},
// 	}

// 	for _, envVar := range proxyEnvVars {
// 		auditForwarderSidecar.Env = extensionswebhook.EnsureEnvVarWithName(auditForwarderSidecar.Env, envVar)
// 	}

// 	switch proxyHost {
// 	case "vpn-seed-server":
// 		for _, envVar := range kubeAggregatorClientTlsEnvVars {
// 			auditForwarderSidecar.Env = extensionswebhook.EnsureEnvVarWithName(auditForwarderSidecar.Env, envVar)
// 		}
// 		for _, mount := range reversedVpnVolumeMounts {
// 			auditForwarderSidecar.VolumeMounts = extensionswebhook.EnsureVolumeMountWithName(auditForwarderSidecar.VolumeMounts, mount)
// 		}
// 	default:
// 		return fmt.Errorf("%q is not a valid proxy name", proxyHost)
// 	}

// 	return nil
// }
