package audit

import (
	"testing"

	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/extensions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/metal-stack/gardener-extension-audit/pkg/apis/audit/v1alpha1"
)

func TestSeedObjects_SplunkConfigCustomData(t *testing.T) {
	tt := []struct {
		desc       string
		customData map[string]string
		assertion  func(*testing.T, string)
	}{
		{
			desc: "multiple custom data",
			customData: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			assertion: func(t *testing.T, c string) {
				assert.Contains(t, c, "[FILTER]")
				assert.Contains(t, c, "add key1 value1")
				assert.Contains(t, c, "add key2 value2")
			},
		},
		{
			desc:       "empty custom data",
			customData: map[string]string{},
			assertion: func(t *testing.T, c string) {
				assert.NotContains(t, c, "[FILTER]")
			},
		},
		{
			desc:       "nil custom data",
			customData: nil,
			assertion: func(t *testing.T, c string) {
				assert.NotContains(t, c, "[FILTER]")
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			// setup empty inputs
			var (
				auditConfig *v1alpha1.AuditConfig = &v1alpha1.AuditConfig{
					Backends: &v1alpha1.AuditBackends{
						Log: &v1alpha1.AuditBackendLog{},
					},
					Persistence: v1alpha1.AuditPersistence{
						Size: &resource.Quantity{},
					},
				}
				secrets map[string]*corev1.Secret = map[string]*corev1.Secret{}
				cluster *extensions.Cluster       = &extensions.Cluster{
					Shoot: &v1beta1.Shoot{},
				}
				splunkSecretFromResources *corev1.Secret = &corev1.Secret{}
				shootAccessSecretName     string
				namespace                 string
			)
			// prepare test inputs
			auditConfig.Backends.Splunk = &v1alpha1.AuditBackendSplunk{
				Enabled:    true,
				CustomData: tc.customData,
			}
			objects, err := seedObjects(auditConfig, secrets, cluster, splunkSecretFromResources, shootAccessSecretName, namespace)
			require.NoError(t, err)

			// inspect output
			require.Greaterf(t, len(objects), 3, "returend objects slice is to small")

			fluentbitConfigMap, ok := objects[2].(*corev1.ConfigMap)
			require.Truef(t, ok, "fluentbitConfigMap is of the wrong type %T", objects[0])

			fluentbitConfig := fluentbitConfigMap.Data["splunk.backend.conf"]

			tc.assertion(t, fluentbitConfig)
		})
	}
}

func TestValidateSplunkCustomData(t *testing.T) {
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
			auditConfig := &v1alpha1.AuditConfig{
				Backends: &v1alpha1.AuditBackends{
					Splunk: &v1alpha1.AuditBackendSplunk{
						CustomData: tc.values,
					},
				},
			}
			actual := validateSplunkCustomData(auditConfig)
			if tc.valid {
				assert.NoError(t, actual)
			} else {
				assert.Error(t, actual)
			}
		})
	}
}
