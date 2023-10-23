package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	healthcheckconfigv1alpha1 "github.com/gardener/gardener/extensions/pkg/apis/config/v1alpha1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ControllerConfiguration defines the configuration for the audit controller.
type ControllerConfiguration struct {
	metav1.TypeMeta `json:",inline"`

	// // ClusterAudit is the configuration for cluster auditing.
	// ClusterAudit ClusterAudit `json:"clusterAudit"`

	// // AuditToSplunk is the configuration for forwarding audit (and firewall) logs to Splunk.
	// AuditToSplunk AuditToSplunk `json:"auditToSplunk"`

	// HealthCheckConfig is the config for the health check controller
	// +optional
	HealthCheckConfig *healthcheckconfigv1alpha1.HealthCheckConfig `json:"healthCheckConfig,omitempty"`
}

// // ClusterAudit is the configuration for cluster auditing.
// type ClusterAudit struct {
// 	// Enabled enables collecting of the kube-apiserver audit log.
// 	Enabled bool `json:"enabled"`
// }

// // AuditToSplunk is the configuration for forwarding audit (and firewall) logs to Splunk.
// type AuditToSplunk struct {
// 	// Enabled enables forwarding of the kube-apiserver auditlogto splunk.
// 	Enabled bool `json:"enabled"`
// 	// This defines the default splunk endpoint unless otherwise specified by the cluster user
// 	HECToken   string `json:"hecToken"`
// 	Index      string `json:"index"`
// 	HECHost    string `json:"hecHost"`
// 	HECPort    int    `json:"hecPort"`
// 	TLSEnabled bool   `json:"tlsEnabled"`
// 	HECCAFile  string `json:"hecCAFile"`
// }
