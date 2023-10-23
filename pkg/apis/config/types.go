package config

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	healthcheckconfig "github.com/gardener/gardener/extensions/pkg/apis/config"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ControllerConfiguration defines the configuration for the audit controller.
type ControllerConfiguration struct {
	metav1.TypeMeta

	// // ClusterAudit is the configuration for cluster auditing.
	// ClusterAudit ClusterAudit

	// // AuditToSplunk is the configuration for forwarding audit (and firewall) logs to Splunk.
	// AuditToSplunk AuditToSplunk

	// HealthCheckConfig is the config for the health check controller
	HealthCheckConfig *healthcheckconfig.HealthCheckConfig
}

// // ClusterAudit is the configuration for cluster auditing.
// type ClusterAudit struct {
// 	// Enabled enables collecting of the kube-apiserver auditlog.
// 	Enabled bool
// }

// // AuditToSplunk is the configuration for forwarding audit (and firewall) logs to Splunk.
// type AuditToSplunk struct {
// 	// Enabled enables forwarding of the kube-apiserver auditlog to splunk.
// 	Enabled bool
// 	// This defines the default splunk endpoint unless otherwise specified by the cluster user
// 	HECToken   string
// 	Index      string
// 	HECHost    string
// 	HECPort    int
// 	TLSEnabled bool
// 	HECCAFile  string
// }
