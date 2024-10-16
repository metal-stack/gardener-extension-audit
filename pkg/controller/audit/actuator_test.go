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

func TestSeedObjects_SplunkConfig_MultipleEventFields(t *testing.T) {
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
		Enabled: true,
		CustomData: map[string]string{
			"key1": "value1",
			"key2": "value2",
		},
	}
	objects, err := seedObjects(auditConfig, secrets, cluster, splunkSecretFromResources, shootAccessSecretName, namespace)
	require.NoError(t, err)

	// inspect output
	require.Greaterf(t, len(objects), 3, "returend objects slice is to small")

	fluentbitConfigMap, ok := objects[2].(*corev1.ConfigMap)
	require.Truef(t, ok, "fluentbitConfigMap is of the wrong type %T", objects[0])

	fluentbitConfig := fluentbitConfigMap.Data["splunk.backend.conf"]
	require.NotEmpty(t, fluentbitConfig, "fluentbitConfig is empty")

	assert.Contains(t, fluentbitConfig, "[FILTER]")
	assert.Contains(t, fluentbitConfig, "add key1 value1")
	assert.Contains(t, fluentbitConfig, "add key2 value2")
}
