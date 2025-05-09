package v1alpha1

import (
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	SeedAuditResourceName  = "extension-audit"
	ShootAuditResourceName = "extension-audit-shoot"

	ShootAudittailerNamespace = "audit"

	AuditWebhookModeBatch          AuditWebhookMode = "batch"
	AuditWebhookModeBlocking       AuditWebhookMode = "blocking"
	AuditWebhookModeBlockingStrict AuditWebhookMode = "blocking-strict"

	SplunkSecretTokenKey  = "token"
	SplunkSecretCaFileKey = "ca"
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
	Persistence AuditPersistence `json:"persistence"`

	// Replicas are the amount of replicas used for the buffering audit pods.
	// +optional
	Replicas *int32 `json:"replicas,omitempty"`

	// WebhookMode allows to select which auditing mode - batching or blocking - should be used.
	WebhookMode AuditWebhookMode `json:"webhookMode"`

	// Backends contains the settings for the various backends.
	// +optional
	Backends *AuditBackends `json:"backends,omitempty"`
}

type AuditPersistence struct {
	// Size is the size of the PVC to be used for each replica of the statefulset.
	// +optional
	Size *resource.Quantity `json:"size,omitempty"`

	// StorageClassName is the name of the storage class to be used for the PVC. If empty, the default
	// storage class is used.
	// +optional
	StorageClassName *string `json:"storageClassName,omitempty"`
}

type AuditBackends struct {
	// Log outputs the log data on stdout of the webhook pod. It is mainly intended for debugging / testing purposes.
	// +optional
	Log *AuditBackendLog `json:"log,omitempty"`

	// ClusterForwarding will forward the audit data to a pod in the shoot where they are printed to stdout and can be
	// picked up by the log collecting solution of the cluster operator's choice.
	// +optional
	ClusterForwarding *AuditBackendClusterForwarding `json:"clusterForwarding,omitempty"`

	// Splunk will forward the audit data to a splunk HEC endpoint.
	// +optional
	Splunk *AuditBackendSplunk `json:"splunk,omitempty"`

	// S3 will store audit logs in an S3 bucket.
	// +optional
	S3 *AuditBackendS3 `json:"s3,omitempty"`

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

	// FilesystemBufferSize is the maximum disk space for the fluent-bit file system buffer.
	FilesystemBufferSize *string `json:"bufferSize,omitempty"`
}
type AuditBackendSplunk struct {
	// Enabled allows to turn this backend on.
	Enabled bool `json:"enabled"`

	// FilesystemBufferSize is the maximum disk space for the fluent-bit file system buffer.
	FilesystemBufferSize *string `json:"bufferSize,omitempty"`

	// Index is the splunk index that should be used.
	Index string `json:"index"`

	// Host is the hostname or IP of the splunk HEC endpoint.
	Host string `json:"host"`

	// Port is the port on which the HEC endpoint is listening.
	Port string `json:"port"`

	// SecretResourceName is a reference under Shoot.spec.resources to the secret used to authenticate against the splunk backend.
	//
	// The referenced secret may contain the following keys:
	//
	// - token: Required, hec token to authenticate against this host/index
	// - ca: Optional, the CA (bundle) that signed the HEC endpoint's server certificate as an unencoded string.
	SecretResourceName string `json:"secretResourceName"`

	// TlsEnabled determines whether TLS should be used to communicate to the HEC endpoint.
	TlsEnabled bool `json:"tls"`

	// TlsHost is the hostname that fluent-bit should request through SNI when connecting to a site that serves different hostnames under one IP.
	TlsHost string `json:"tlshost,omitempty"`

	// CustomData contains a map of custom key/value pairs. The custom data is added to each audit log entry using fluentbit's modify filter.
	// The keys and the values may only contain letters, numbers, '_' or '.'. Empty keys or values are also not accepted.
	CustomData map[string]string `json:"customData,omitempty"`
}

type AuditBackendS3 struct {
	// Enabled allows to turn this backend on.
	Enabled bool `json:"enabled"`

	// FilesystemBufferSize is the maximum disk space for the fluent-bit file system buffer.
	FilesystemBufferSize *string `json:"bufferSize,omitempty"`

	// Bucket is the S3 bucket name where audit logs will be stored.
	Bucket string `json:"bucket"`

	// Region is the AWS region where the bucket is located.
	Region string `json:"region"`

	// Prefix is the prefix (folder path) where audit logs will be stored in the bucket.
	// +optional
	Prefix string `json:"prefix,omitempty"`

	// SecretResourceName is a reference under Shoot.spec.resources to the secret used to authenticate against AWS.
	// The referenced secret must contain:
	// - access_key_id: Required, AWS access key ID
	// - secret_access_key: Required, AWS secret access key
	SecretResourceName string `json:"secretResourceName"`

	// Endpoint is the custom S3 endpoint URL (optional, for S3-compatible storage).
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// TlsEnabled determines whether TLS should be used to communicate with S3.
	// +optional
	TlsEnabled bool `json:"tlsEnabled,omitempty"`
}
