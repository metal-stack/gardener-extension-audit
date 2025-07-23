package backend

import (
	"github.com/gardener/gardener/pkg/extensions"
	"github.com/metal-stack/gardener-extension-audit/pkg/apis/audit/v1alpha1"
	"github.com/metal-stack/gardener-extension-audit/pkg/fluentbitconfig"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"testing"
)

func Test_S3FluentBitConfig(t *testing.T) {
	validSecretData := map[string][]byte{
		s3SecretAccessKeyIDKey:     []byte("key"),
		s3SecretSecretAccessKeyKey: []byte("secret"),
	}
	tt := []struct {
		desc            string
		backend         v1alpha1.AuditBackendS3
		secretData      map[string][]byte
		assertionError  func(*testing.T, error)
		assertionConfig func(*testing.T, fluentbitconfig.Config)
	}{
		{
			desc: "secret missing",
			backend: v1alpha1.AuditBackendS3{
				Enabled: true,
				Bucket:  "bucket",
				Region:  "region",
			},
			secretData: map[string][]byte{},
			assertionError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.ErrorContains(t, err, "secret")
			},
		},
		{
			desc: "missing bucket",
			backend: v1alpha1.AuditBackendS3{
				Enabled: true,
				Region:  "region",
			},
			secretData: validSecretData,
			assertionError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.ErrorContains(t, err, "bucket")
			},
		},
		{
			desc: "missing region",
			backend: v1alpha1.AuditBackendS3{
				Enabled: true,
				Bucket:  "bucket",
			},
			secretData: validSecretData,
			assertionError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.ErrorContains(t, err, "region")
			},
		},
		{
			desc: "prefix dose not start with /",
			backend: v1alpha1.AuditBackendS3{
				Enabled: true,
				Bucket:  "bucket",
				Region:  "region",
				Prefix:  pointer.Pointer("audit"),
			},
			secretData: validSecretData,
			assertionError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.ErrorContains(t, err, "prefix")
			},
		},

		{
			desc: "prefix dose not start with /",
			backend: v1alpha1.AuditBackendS3{
				Enabled:     true,
				Bucket:      "bucket",
				Region:      "region",
				S3KeyFormat: pointer.Pointer("audit"),
			},
			secretData: validSecretData,
			assertionError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.ErrorContains(t, err, "s3KeyFormat")
			},
		},
		{
			desc: "valid secret",
			backend: v1alpha1.AuditBackendS3{
				Enabled: true,
				Bucket:  "bucket",
				Region:  "region",
			},
			secretData: validSecretData,
			assertionError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			assertionConfig: func(t *testing.T, c fluentbitconfig.Config) {},
		},
		{
			desc: "with default config",
			backend: v1alpha1.AuditBackendS3{
				Enabled: true,
				Bucket:  "bucket",
				Region:  "region",
			},
			secretData: validSecretData,
			assertionError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			assertionConfig: func(t *testing.T, c fluentbitconfig.Config) {
				assert.Len(t, c.Output, 1)
				o := c.Output[0]
				assert.Equal(t, o["match"], "audit")
				assert.Equal(t, o["name"], "s3")
				assert.Equal(t, o["retry_limit"], "no_limits")
				assert.Equal(t, o["store_dir_limit_size"], "900M")
				assert.Equal(t, o["bucket"], "bucket")
				assert.Equal(t, o["region"], "region")
				assert.Equal(t, o["json_date_key"], "timestamp")
				assert.Equal(t, o["use_put_object"], "On")
				assert.Equal(t, o["s3_key_format"], "/audit-logs/%Y/%m/%d/%H/%M/%S/$UUID")
				assert.Equal(t, o["upload_timeout"], "10m")
				assert.Equal(t, o["total_file_size"], "100M")
				assert.Equal(t, o["tls"], "On")
			},
		},

		{
			desc: "with changes config config",
			backend: v1alpha1.AuditBackendS3{
				Enabled:              true,
				Bucket:               "bucket",
				Region:               "region",
				FilesystemBufferSize: pointer.Pointer("1G"),
				S3KeyFormat:          pointer.Pointer("/%Y/%m/%d/$UUID"),
				Prefix:               pointer.Pointer("/logs"),
				UploadTimeout:        pointer.Pointer("2m"),
				TotalFileSize:        pointer.Pointer("99M"),
				TlsEnabled:           pointer.Pointer(false),
				UseCompression:       pointer.Pointer(true),
			},
			secretData: validSecretData,
			assertionError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			assertionConfig: func(t *testing.T, c fluentbitconfig.Config) {
				assert.Len(t, c.Output, 1)
				o := c.Output[0]
				assert.Equal(t, o["store_dir_limit_size"], "1G")
				assert.Equal(t, o["json_date_key"], "timestamp")
				assert.Equal(t, o["use_put_object"], "On")
				assert.Equal(t, o["s3_key_format"], "/logs/%Y/%m/%d/$UUID")
				assert.Equal(t, o["upload_timeout"], "2m")
				assert.Equal(t, o["total_file_size"], "99M")
				assert.Equal(t, o["compression"], "gzip")
				assert.NotEqual(t, o["tls"], "On")
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			backends := &v1alpha1.AuditBackends{
				S3: &tc.backend,
			}
			v1alpha1.DefaultBackends(backends)
			s3, err := NewS3(backends.S3, &corev1.Secret{
				Data: tc.secretData,
			})
			tc.assertionError(t, err)
			if err == nil {
				config := s3.FluentBitConfig(&extensions.Cluster{})
				tc.assertionConfig(t, config)
			}
		})
	}
}
