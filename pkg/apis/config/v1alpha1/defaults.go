package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"
)

func addDefaultingFuncs(scheme *runtime.Scheme) error {
	return RegisterDefaults(scheme)
}

// SetDefaults_ControllerConfiguration sets defaults for the ControllerConfiguration.
func SetDefaults_ControllerConfiguration(obj *ControllerConfiguration) {
	if obj.AllowCustomBackends == nil {
		obj.AllowCustomBackends = new(false)
	}
}
