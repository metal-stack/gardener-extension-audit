package backend

import (
	"fmt"
	"path"
	"regexp"

	"github.com/gardener/gardener/pkg/extensions"
	"github.com/gardener/gardener/pkg/utils"
	"github.com/metal-stack/gardener-extension-audit/pkg/apis/audit/v1alpha1"
	"github.com/metal-stack/gardener-extension-audit/pkg/fluentbitconfig"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Splunk struct {
	backend *v1alpha1.AuditBackendSplunk
	secret  *corev1.Secret
}

func NewSplunk(backend *v1alpha1.AuditBackendSplunk, secret *corev1.Secret) (Splunk, error) {
	err := validateCustomData(backend)
	if err != nil {
		return Splunk{}, err
	}

	_, ok := secret.Data[v1alpha1.SplunkSecretTokenKey]
	if !ok {
		return Splunk{}, fmt.Errorf("referenced splunk secret does not contain contents under key %q", v1alpha1.SplunkSecretTokenKey)
	}

	return Splunk{
		backend: backend,
		secret:  secret,
	}, nil
}

var validCustomDataExpression = regexp.MustCompile("^[a-zA-Z0-9._-]+$")

// validateCustomData makes sure that all key/value pairs contain only letters,
// numbers, '_' or '.'. Empty keys or values are also not allowed.
func validateCustomData(splunk *v1alpha1.AuditBackendSplunk) error {
	customData := splunk.CustomData

	isValidSplunkCustomDataString := func(s string) bool {
		return validCustomDataExpression.MatchString(s)
	}

	for key, value := range customData {
		if !isValidSplunkCustomDataString(key) {
			return fmt.Errorf("%q is not a valid customData key for splunk", key)
		}
		if !isValidSplunkCustomDataString(value) {
			return fmt.Errorf("%q is not a valid customData value for splunk", value)
		}
	}

	return nil
}

const (
	caFilePath = "/backends/splunk/certs/ca.crt"
)

func (s Splunk) FluentBitConfig(cluster *extensions.Cluster) fluentbitconfig.Config {
	splunkConfig := map[string]string{
		"match":                    "audit",
		"name":                     "splunk",
		"retry_limit":              "no_limits", // let fluent-bit never discard any data
		"storage.total_limit_size": pointer.SafeDeref(s.backend.FilesystemBufferSize),
		"host":                     s.backend.Host,
		"port":                     s.backend.Port,
		"splunk_token":             "${SPLUNK_HEC_TOKEN}",
		"splunk_send_raw":          "off",
		"event_sourcetype":         "kube:apiserver:auditlog",
		"event_index":              s.backend.Index,
		"event_host":               cluster.ObjectMeta.Name,
	}

	_, ok := s.secret.Data[v1alpha1.SplunkSecretCaFileKey]
	if ok {
		splunkConfig["tls.ca_file"] = caFilePath
	}

	if s.backend.TlsEnabled {
		splunkConfig["tls"] = "on"
		splunkConfig["tls.verify"] = "on"
		splunkConfig["tls.verify_hostname"] = "on"
		if s.backend.TlsHost != "" {
			splunkConfig["tls.vhost"] = s.backend.TlsHost
		}
	}

	filters := []fluentbitconfig.Filter{}
	if len(s.backend.CustomData) > 0 {
		splunkConfigFilter := make(map[string]string, len(s.backend.CustomData)+2)
		splunkConfigFilter["name"] = "modify"
		splunkConfigFilter["match"] = "*"
		for key, value := range s.backend.CustomData {
			splunkConfigFilter["add "+key] = value
		}
		filters = append(filters, splunkConfigFilter)
	}
	fluentbitBackendSplunk := fluentbitconfig.Config{
		Output: []fluentbitconfig.Output{splunkConfig},
		Filter: filters,
	}
	return fluentbitBackendSplunk
}

func (s Splunk) PatchAuditWebhook(sts *appsv1.StatefulSet) {
	sts.Spec.Template.Spec.Containers[0].Env = append(sts.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
		Name: "SPLUNK_HEC_TOKEN",
		ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: s.secret.Name,
				},
				Key: v1alpha1.SplunkSecretTokenKey,
			},
		},
	})

	_, ok := s.secret.Data[v1alpha1.SplunkSecretCaFileKey]
	if ok {
		sts.Spec.Template.Spec.Volumes = append(sts.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: "splunk-secret",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: s.secret.Name,
					Items: []corev1.KeyToPath{
						{
							Key:  v1alpha1.SplunkSecretCaFileKey,
							Path: "ca.crt",
						},
					},
				},
			},
		})

		sts.Spec.Template.Spec.Containers[0].VolumeMounts = append(sts.Spec.Template.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{
			Name:      "splunk-secret",
			MountPath: path.Dir(caFilePath),
		})
	}

	sts.Spec.Template.ObjectMeta.Annotations["checksum/splunk-secret"] = utils.ComputeSecretChecksum(s.secret.Data)
}

func (s Splunk) AdditionalSeedObjects(*extensions.Cluster) []client.Object {
	return []client.Object{}
}

func (s Splunk) AdditionalShootObjects(*extensions.Cluster) []client.Object {
	return []client.Object{}
}
