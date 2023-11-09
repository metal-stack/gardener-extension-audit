package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	SeedAuditResourceName  = "extension-audit"
	ShootAuditResourceName = "extension-audit-shoot"

	ShootAudittailerNamespace = "audit"

	AuditWebhookModeBatch          AuditWebhookMode = "batch"
	AuditWebhookModeBlocking       AuditWebhookMode = "blocking"
	AuditWebhookModeBlockingStrict AuditWebhookMode = "blocking-strict"
)

type (
	AuditWebhookMode string
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AuditConfig configuration resource
type AuditConfig struct {
	metav1.TypeMeta `json:",inline"`

	// Persistence contains options about the persistent volume used for buffering the audit data
	// on the filesystem.
	Persistence *AuditPersistence `json:"persistence,omitempty"`

	// WebhookMode allows to select which auditing mode - batching or blocking - should be used.
	WebhookMode AuditWebhookMode `json:"webhookMode,omitempty"`

	// AuditPolicy contains the audit policy to be used for the cluster, as unencoded string.
	// If none is supplied, a default auditpolicy is used.
	AuditPolicy *string `json:"auditPolicy,omitempty"`

	// Backends contains the settings for the various backends.
	Backends *AuditBackends `json:"backends,omitempty"`
}

type AuditPersistence struct {
	// Size is the size of the PVC to be used for each replica of the statefulset.
	Size *string `json:"size,omitempty"`

	// StorageClassName is the name of the storage class to be used for the PVC. If empty, the default
	// storage class is used.
	StorageClassName *string `json:"storageClassName,omitempty"`
}

type AuditBackends struct {
	// Log outputs the log data on stdout of the webhook pod. It is mainly intended for debugging / testing purposes.
	Log *AuditBackendLog `json:"log,omitempty"`

	// ClusterForwarding will forward the audit data to a pod in the shoot where they are printed to stdout and can be
	// picked up by the log collecting solution of the cluster operator's choice.
	ClusterForwarding *AuditBackendClusterForwarding `json:"clusterForwarding,omitempty"`

	// Splunk will forward the audit data to a splunk HEC endpoint.
	Splunk *AuditBackendSplunk `json:"splunk,omitempty"`

	// Possible backends that would be helpful as well:
	// - Forward
	// - Loki
	// - Elasticsearch
	// - Forward
	// - Kafka
}

type AuditBackendLog struct {
	// Enabled allows to turn this backend on.
	Enabled bool `json:"enabled"`
}

type AuditBackendClusterForwarding struct {
	// Enabled allows to turn this backend on.
	Enabled bool `json:"enabled"`

	// FilesystemBufferSize is the maximum disk space for the fluent-bit file sytem buffer.
	FilesystemBufferSize string `json:"bufferSize,omitempty"`
}
type AuditBackendSplunk struct {
	// Enabled allows to turn this backend on.
	Enabled bool `json:"enabled"`

	// FilesystemBufferSize is the maximum disk space for the fluent-bit file sytem buffer.
	FilesystemBufferSize string `json:"bufferSize,omitempty"`

	// Index is the splunk index that should be used.
	Index string `json:"index"`

	// Host ist the hostname of the splunk HEC endpoint.
	Host string `json:"host"`

	// Port ist the port on which the HEC endpoint is listening.
	Port string `json:"port"`

	// Token is the splunk HEC token necessary to send log data to this Host/Index.
	Token string `json:"hecToken"`

	// CaFile contains, in an unencoded string, the CA (bundle) of the CA that signed the HEC endpoint's server certificate.
	CaFile string `json:"caFile"`

	// TlsEnabled determines whether TLS should be used to communicate to the HEC endpoint.
	TlsEnabled bool `json:"tls"`
}
