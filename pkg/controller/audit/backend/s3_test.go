package backend

import (
	"testing"

	"github.com/gardener/gardener/pkg/extensions"
	"github.com/metal-stack/gardener-extension-audit/pkg/apis/audit/v1alpha1"
	"github.com/metal-stack/gardener-extension-audit/pkg/fluentbitconfig"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
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
				require.Error(t, err)
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
				require.Error(t, err)
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
				require.Error(t, err)
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
				require.Error(t, err)
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
				require.Error(t, err)
				assert.ErrorContains(t, err, "s3KeyFormat")
			},
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
				assert.Equal(t, "audit", o["match"])
				assert.Equal(t, "s3", o["name"])
				assert.Equal(t, "no_limits", o["retry_limit"])
				assert.Equal(t, "900M", o["store_dir_limit_size"])
				assert.Equal(t, "bucket", o["bucket"])
				assert.Equal(t, "region", o["region"])
				assert.Equal(t, "timestamp", o["json_date_key"])
				assert.Equal(t, "On", o["use_put_object"])
				assert.Equal(t, "/audit-logs/%Y/%m/%d/%H/%M/%S/$UUID", o["s3_key_format"])
				assert.Equal(t, "10m", o["upload_timeout"])
				assert.Equal(t, "100M", o["total_file_size"])
				assert.Equal(t, "On", o["tls"])
			},
		},

		{
			desc: "with changes config",
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
				assert.Equal(t, "1G", o["store_dir_limit_size"])
				assert.Equal(t, "timestamp", o["json_date_key"])
				assert.Equal(t, "On", o["use_put_object"])
				assert.Equal(t, "/logs/%Y/%m/%d/$UUID", o["s3_key_format"])
				assert.Equal(t, "2m", o["upload_timeout"])
				assert.Equal(t, "99M", o["total_file_size"])
				assert.Equal(t, "gzip", o["compression"])
				assert.NotEqual(t, "On", o["tls"])
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
