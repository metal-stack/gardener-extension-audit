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

func (s S3) FluentBitConfig(*extensions.Cluster) fluentbitconfig.Config {
	s3Config := map[string]string{
		"match":                "audit",
		"name":                 "s3",
		"retry_limit":          "no_limits", // Let FluentBit only discard data if store_dir_limit_size is reached
		"store_dir_limit_size": pointer.SafeDeref(s.backend.FilesystemBufferSize),
		"bucket":               s.backend.Bucket,
		"region":               s.backend.Region,
		"json_date_key":        "timestamp",
		"use_put_object":       "On",
	}

	if s.backend.S3KeyFormat != nil {
		s3Config["s3_key_format"] = *s.backend.S3KeyFormat
	}

	if s.backend.Prefix != nil {
		s3Config["s3_key_format"] = path.Join(*s.backend.Prefix, s3Config["s3_key_format"])
	}

	if s.backend.Endpoint != nil {
		s3Config["endpoint"] = *s.backend.Endpoint
	}

	if s.backend.UploadTimeout != nil {
		s3Config["upload_timeout"] = *s.backend.UploadTimeout
	}

	if s.backend.TotalFileSize != nil {
		s3Config["total_file_size"] = *s.backend.TotalFileSize
	}

	if s.backend.TlsEnabled != nil && *s.backend.TlsEnabled {
		s3Config["tls"] = "On"
	}

	if s.backend.UseCompression != nil && *s.backend.UseCompression {
		s3Config["compression"] = "gzip"

	}

	return fluentbitconfig.Config{
		Output: []fluentbitconfig.Output{s3Config},
	}
}

func (s S3) PatchAuditWebhook(sts *appsv1.StatefulSet) {
	// Add AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY ENV, this ENVs are used to authenticate on the s3 object storage.
	sts.Spec.Template.Spec.Containers[0].Env = append(sts.Spec.Template.Spec.Containers[0].Env,
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
	return []client.Object{}
}

func (s S3) AdditionalSeedObjects(_ *extensions.Cluster) []client.Object {
	return []client.Object{}
}
