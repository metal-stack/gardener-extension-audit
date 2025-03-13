package backend

import (
	"testing"

	"github.com/gardener/gardener/pkg/extensions"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"

	"github.com/metal-stack/gardener-extension-audit/pkg/apis/audit/v1alpha1"
	"github.com/metal-stack/gardener-extension-audit/pkg/fluentbitconfig"
)

func Test_SplunkFluentBitConfig(t *testing.T) {
	tt := []struct {
		desc       string
		customData map[string]string
		assertion  func(*testing.T, fluentbitconfig.Config)
	}{
		{
			desc: "multiple custom data",
			customData: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			assertion: func(t *testing.T, c fluentbitconfig.Config) {
				assert.Len(t, c.Filter, 1)
				f := c.Filter[0]
				assert.Contains(t, f, "add key1")
				assert.Contains(t, f, "add key2")
			},
		},
		{
			desc:       "empty custom data",
			customData: map[string]string{},
			assertion: func(t *testing.T, c fluentbitconfig.Config) {
				assert.Len(t, c.Filter, 0)
			},
		},
		{
			desc:       "nil custom data",
			customData: nil,
			assertion: func(t *testing.T, c fluentbitconfig.Config) {
				assert.Len(t, c.Filter, 0)
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			// prepare test inputs
			backend := &v1alpha1.AuditBackendSplunk{
				Enabled:    true,
				CustomData: tc.customData,
			}
			splunk := Splunk{
				backend: backend,
				secret: &corev1.Secret{
					Data: map[string][]byte{},
				},
			}
			config := splunk.FluentBitConfig(&extensions.Cluster{})

			tc.assertion(t, config)
		})
	}
}

func Test_SplunkValidateCustomData(t *testing.T) {
	tt := []struct {
		desc   string
		values map[string]string
		valid  bool
	}{
		{
			desc:   "nil customData",
			values: nil,
			valid:  true,
		},
		{
			desc:   "empty customData",
			values: map[string]string{},
			valid:  true,
		},
		{
			desc: "single valid key/value pair with all allowed punctuation",
			values: map[string]string{
				"key-1.KEY_1": "value-1.VALUE_1",
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
			desc: "invalid value",
			values: map[string]string{
				"key1": "value1!",
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
			desc: "empty value",
			values: map[string]string{
				"value": "",
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
	}
	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			backend := &v1alpha1.AuditBackendSplunk{
				CustomData: tc.values,
			}
			actual := validateCustomData(backend)
			if tc.valid {
				assert.NoError(t, actual)
			} else {
				assert.Error(t, actual)
			}
		})
	}
}
