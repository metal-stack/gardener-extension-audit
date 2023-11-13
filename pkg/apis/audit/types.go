package audit

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
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
	metav1.TypeMeta

	// Persistence contains options about the persistent volume used for buffering the audit data
	// on the filesystem.
	Persistence *AuditPersistence

	// WebhookMode allows to select which auditing mode - batching or blocking - should be used.
	WebhookMode AuditWebhookMode

	// Backends contains the settings for the various backends.
	Backends *AuditBackends
}

type AuditPersistence struct {
	// Size is the size of the PVC to be used for each replica of the statefulset.
	Size *string

	// StorageClassName is the name of the storage class to be used for the PVC. If empty, the default
	// storage class is used.
	StorageClassName *string
}

type AuditBackends struct {
	// Log outputs the log data on stdout of the webhook pod. It is mainly intended for debugging / testing purposes.
	Log *AuditBackendLog

	// ClusterForwarding will forward the audit data to a pod in the shoot where they are printed to stdout and can be
	// picked up by the log collecting solution of the cluster operator's choice.
	ClusterForwarding *AuditBackendClusterForwarding

	// Splunk will forward the audit data to a splunk HEC endpoint.
	Splunk *AuditBackendSplunk
}

type AuditBackendLog struct {
	// Enabled allows to turn this backend on.
	Enabled bool
}

type AuditBackendClusterForwarding struct {
	// Enabled allows to turn this backend on.
	Enabled bool

	// FilesystemBufferSize is the maximum disk space for the fluent-bit file sytem buffer.
	FilesystemBufferSize string
}

type AuditBackendSplunk struct {
	// Enabled allows to turn this backend on.
	Enabled bool

	// FilesystemBufferSize is the maximum disk space for the fluent-bit file sytem buffer.
	FilesystemBufferSize string

	// Index is the splunk index that should be used.
	Index string

	// Host ist the hostname of the splunk HEC endpoint.
	Host string

	// Port ist the port on which the HEC endpoint is listening.
	Port string

	// SecretResourceName is a reference under Shoot.spec.resources to the secret used to authenticate against the splunk backend.
	//
	// The referenced secret may contain the following keys:
	//
	// - token: Required, hec token to authenticate against this host/index
	// - ca: Optional, the CA (bundle) that signed the HEC endpoint's server certificate as an unencoded string.
	SecretResourceName string

	// TlsEnabled determines whether TLS should be used to communicate to the HEC endpoint.
	TlsEnabled bool
}
