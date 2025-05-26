package config

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	healthcheckconfigv1alpha1 "github.com/gardener/gardener/extensions/pkg/apis/config/v1alpha1"
	"github.com/metal-stack/gardener-extension-audit/pkg/apis/audit/v1alpha1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ControllerConfiguration defines the configuration for the audit controller.
type ControllerConfiguration struct {
	metav1.TypeMeta

	// DefaultBackends can be used to configure provider-default backends that are not explicitly disabled from the user.
	DefaultBackends *v1alpha1.AuditBackends

	// HealthCheckConfig is the config for the health check controller
	HealthCheckConfig *healthcheckconfigv1alpha1.HealthCheckConfig
}
