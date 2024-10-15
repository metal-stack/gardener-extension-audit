package audit

import (
	"strings"
	"testing"

	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/extensions"
	"github.com/metal-stack/gardener-extension-audit/pkg/apis/audit/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
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
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	// inspect output
	if len(objects) < 3 {
		t.Error("returend objects slice is to small")
		t.FailNow()
	}
	fluentbitConfigMap, ok := objects[2].(*corev1.ConfigMap)
	if !ok {
		t.Errorf("fluentbitConfigMap is of the wrong type %T", objects[0])
		t.FailNow()
	}
	fluentbitConfig := fluentbitConfigMap.Data["splunk.backend.conf"]
	if fluentbitConfig == "" {
		t.Error("fluentbitConfig is empty")
		t.FailNow()
	}
	if !(strings.Contains(fluentbitConfig, "[FILTER]") && strings.Contains(fluentbitConfig, "add key1 value1") && strings.Contains(fluentbitConfig, "add key2 value2")) {
		t.Errorf("fluentbitConfig does not contain the expected custom data entries:\n%v", fluentbitConfig)
		t.FailNow()
	}
}
