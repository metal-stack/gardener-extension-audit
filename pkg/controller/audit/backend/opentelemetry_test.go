package backend

import (
	"testing"

	"github.com/gardener/gardener/pkg/extensions"
	"github.com/metal-stack/gardener-extension-audit/pkg/apis/audit/v1alpha1"
	"github.com/metal-stack/gardener-extension-audit/pkg/fluentbitconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
)

func Test_OpenTelemetryFluentBitConfig(t *testing.T) {
	validSecretData := map[string][]byte{
		v1alpha1.OpenTelemetrySecretTokenKey: []byte("token"),
	}

	tt := []struct {
		desc            string
		backend         v1alpha1.AuditBackendOpenTelemetry
		secretData      map[string][]byte
		assertionError  func(*testing.T, error)
		assertionConfig func(*testing.T, fluentbitconfig.Config)
	}{
		{
			desc: "secret missing",
			backend: v1alpha1.AuditBackendOpenTelemetry{
				Enabled: true,
			},
			secretData: map[string][]byte{},
			assertionError: func(t *testing.T, err error) {
				require.Error(t, err)
				assert.ErrorContains(t, err, "secret")
			},
		},
		{
			desc: "host missing",
			backend: v1alpha1.AuditBackendOpenTelemetry{
				Enabled: true,
				Port:    "443",
			},
			secretData: validSecretData,
			assertionError: func(t *testing.T, err error) {
				require.Error(t, err)
				assert.ErrorContains(t, err, "host")
			},
		},
		{
			desc: "port missing",
			backend: v1alpha1.AuditBackendOpenTelemetry{
				Enabled: true,
				Host:    "example.com",
			},
			secretData: validSecretData,
			assertionError: func(t *testing.T, err error) {
				require.Error(t, err)
				assert.ErrorContains(t, err, "port")
			},
		},
		{
			desc: "with default config",
			backend: v1alpha1.AuditBackendOpenTelemetry{
				Enabled: true,
				Host:    "example.com",
				Port:    "443",
			},
			secretData: validSecretData,
			assertionConfig: func(t *testing.T, c fluentbitconfig.Config) {
				assert.Len(t, c.Output, 1)
				o := c.Output[0]
				assert.Equal(t, "audit", o["match"])
				assert.Equal(t, "opentelemetry", o["name"])
				assert.Equal(t, "no_limits", o["retry_limit"])
				assert.Equal(t, "900M", o["storage.total_limit_size"])
				assert.Equal(t, "example.com", o["host"])
				assert.Equal(t, "443", o["port"])
				assert.Equal(t, []string{"Authorization Bearer ${OTLP_BEARER_TOKEN}"}, o["header"])
				assert.Equal(t, "$body", o["logs_body_key"])
				assert.Equal(t, "on", o["tls"])
				assert.Equal(t, "on", o["tls.verify"])
				assert.Equal(t, "on", o["tls.verify_hostname"])

				filters := o["processors"].(map[string]any)["logs"].([]map[string]string)
				assert.Len(t, filters, 2)
				assert.Equal(t, "lua", filters[0]["name"])
				assert.Equal(t, "split_json_logs", filters[0]["call"])
				assert.Contains(t, filters[0]["code"], "new_records")
				assert.Equal(t, "opentelemetry_envelope", filters[1]["name"])
			},
		},
		{
			desc: "with changed config",
			backend: v1alpha1.AuditBackendOpenTelemetry{
				Enabled:              true,
				Host:                 "example.com",
				Port:                 "443",
				FilesystemBufferSize: ptr.To("1G"),
				TlsEnabled:           ptr.To(false),
				Attributes: map[string]string{
					"example": "entry",
				},
				AuditIDAttribute: "my.audit.id",
				BatchSize:        ptr.To(42),
			},
			secretData: validSecretData,
			assertionConfig: func(t *testing.T, c fluentbitconfig.Config) {
				assert.Len(t, c.Output, 1)
				o := c.Output[0]
				assert.Equal(t, "1G", o["storage.total_limit_size"])
				assert.NotEqual(t, "on", o["tls"])
				assert.Equal(t, "42", o["batch_size"])

				filters := o["processors"].(map[string]any)["logs"].([]map[string]string)
				assert.Len(t, filters, 3)
				assert.Equal(t, "lua", filters[0]["name"])
				assert.Contains(t, filters[0]["code"], "my.audit.id")
				assert.Equal(t, "opentelemetry_envelope", filters[1]["name"])
				assert.Equal(t, "content_modifier", filters[2]["name"])
				assert.Equal(t, "attributes", filters[2]["context"])
				assert.Equal(t, "upsert", filters[2]["action"])
				assert.Equal(t, "example", filters[2]["key"])
				assert.Equal(t, "entry", filters[2]["value"])
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			backends := &v1alpha1.AuditBackends{
				OpenTelemetry: &tc.backend,
			}
			v1alpha1.DefaultBackends(backends)
			opentelemetry, err := NewOpenTelemetry(backends.OpenTelemetry, &corev1.Secret{
				Data: tc.secretData,
			})
			if tc.assertionError != nil {
				tc.assertionError(t, err)
			} else {
				assert.NoError(t, err)
			}
			if err == nil {
				config := opentelemetry.FluentBitConfig(&extensions.Cluster{})
				tc.assertionConfig(t, config)
			}
		})
	}
}

func Test_OpenTelemetryValidateAttributes(t *testing.T) {
	tt := []struct {
		desc    string
		auditID string
		values  map[string]string
		valid   bool
	}{
		{
			desc:   "nil attributes",
			values: nil,
			valid:  true,
		},
		{
			desc:   "empty attributes",
			values: map[string]string{},
			valid:  true,
		},
		{
			desc: "single valid key/value pair with all allowed punctuation",
			values: map[string]string{
				"key-1.KEY_1": "something$",
			},
			valid: true,
		},
		{
			desc: "invalid key",
			values: map[string]string{
				"key1!": "value1",
			},
			valid: false,
		},
		{
			desc: "empty key",
			values: map[string]string{
				"": "value",
			},
			valid: false,
		},
		{
			desc: "multiple valid key/value pairs",
			values: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			valid: true,
		},
		{
			desc: "multiple key/value pairs with one invalid pair",
			values: map[string]string{
				"key1":  "value1",
				"key2":  "value2",
				"key2!": "value2",
			},
			valid: false,
		},
		{
			desc:    "invalid auditIDAttribute",
			auditID: "invalid!",
			valid:   false,
		},
		{
			desc:    "valid auditIDAttribute",
			auditID: "valid",
			valid:   true,
		},
	}
	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			backend := &v1alpha1.AuditBackendOpenTelemetry{
				Attributes:       tc.values,
				AuditIDAttribute: tc.auditID,
			}
			actual := validateOpenTelemetryAttributes(backend)
			if tc.valid {
				assert.NoError(t, actual)
			} else {
				assert.Error(t, actual)
			}
		})
	}
}
