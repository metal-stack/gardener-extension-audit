package backend

import (
	"fmt"
	"path"

	"github.com/gardener/gardener/pkg/extensions"
	"github.com/metal-stack/gardener-extension-audit/pkg/apis/audit/v1alpha1"
	"github.com/metal-stack/gardener-extension-audit/pkg/fluentbitconfig"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	s3SecretAccessKeyIDKey     = "access_key_id"
	s3SecretSecretAccessKeyKey = "secret_access_key"
)

type S3 struct {
	backend *v1alpha1.AuditBackendS3
	secret  *corev1.Secret
}

func NewS3(backend *v1alpha1.AuditBackendS3, secret *corev1.Secret) (S3, error) {
	if _, ok := secret.Data[s3SecretAccessKeyIDKey]; !ok {
		return S3{}, fmt.Errorf("referenced S3 secret does not contain %q", s3SecretAccessKeyIDKey)
	}

	if _, ok := secret.Data[s3SecretSecretAccessKeyKey]; !ok {
		return S3{}, fmt.Errorf("referenced S3 secret does not contain %q", s3SecretSecretAccessKeyKey)
	}

	return S3{
		backend: backend,
		secret:  secret,
	}, nil
}

func (s S3) FluentBitConfig(cluster *extensions.Cluster) fluentbitconfig.Config {
	s3Config := map[string]string{
		"match":                    "audit",
		"name":                     "s3",
		"retry_limit":              "no_limits", // Let FluentBit never discard any data
		"storage.total_limit_size": pointer.SafeDeref(s.backend.FilesystemBufferSize),
		"bucket":                   s.backend.Bucket,
		"region":                   s.backend.Region,
		"json_date_key":            "timestamp",
		"total_file_size":          "50M",
		"upload_timeout":           "10m",
		"use_put_object":           "On",
		"s3_key_format":            "/audit-logs/%Y/%m/%d/%H/%M/%S",
		"access_key_id":            "${AWS_ACCESS_KEY_ID}",
		"secret_access_key":        "${AWS_SECRET_ACCESS_KEY}",
	}

	if s.backend.Prefix != "" {
		s3Config["s3_key_format"] = path.Join(s.backend.Prefix, s3Config["s3_key_format"])
	}

	if s.backend.Endpoint != "" {
		s3Config["endpoint"] = s.backend.Endpoint
	}

	if s.backend.TlsEnabled {
		s3Config["tls"] = "on"
		s3Config["tls.verify"] = "on"
	}

	return fluentbitconfig.Config{
		Output: []fluentbitconfig.Output{s3Config},
	}
}

func (s S3) PatchAuditWebhook(sts *appsv1.StatefulSet) {
	container := &sts.Spec.Template.Spec.Containers[0]
	container.Env = append(container.Env,
		corev1.EnvVar{
			Name: "AWS_ACCESS_KEY_ID",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: s.secret.Name,
					},
					Key: s3SecretAccessKeyIDKey,
				},
			},
		},
		corev1.EnvVar{
			Name: "AWS_SECRET_ACCESS_KEY",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: s.secret.Name,
					},
					Key: s3SecretSecretAccessKeyKey,
				},
			},
		},
	)
}

func (s S3) AdditionalShootObjects(*extensions.Cluster) []client.Object {
	// No objects needed in the shoot cluster
	return []client.Object{}
}

func (s S3) AdditionalSeedObjects(cluster *extensions.Cluster) []client.Object {
	// Create a secret in the seed cluster containing the credentials
	s3Secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: cluster.ObjectMeta.Name,
		},
		Data: map[string][]byte{
			"access_key_id":     s.secret.Data[s3SecretAccessKeyIDKey],
			"secret_access_key": s.secret.Data[s3SecretSecretAccessKeyKey],
		},
	}

	return []client.Object{s3Secret}
}
