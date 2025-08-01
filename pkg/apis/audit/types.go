package audit

import (
	"k8s.io/apimachinery/pkg/api/resource"
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
	Persistence AuditPersistence

	// Replicas are the amount of replicas used for the buffering audit pods.
	Replicas *int32

	// WebhookMode allows to select which auditing mode - batching or blocking - should be used.
	WebhookMode AuditWebhookMode

	// Backends contains the settings for the various backends.
	Backends *AuditBackends
}

type AuditPersistence struct {
	// Size is the size of the PVC to be used for each replica of the statefulset.
	Size *resource.Quantity

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

	// S3 will store audit logs in an S3 bucket.
	S3 *AuditBackendS3
}

type AuditBackendLog struct {
	// Enabled allows to turn this backend on.
	Enabled bool
}

type AuditBackendClusterForwarding struct {
	// Enabled allows to turn this backend on.
	Enabled bool

	// FilesystemBufferSize is the maximum disk space for the fluent-bit file system buffer.
	// +optional
	FilesystemBufferSize *string
}

type AuditBackendSplunk struct {
	// Enabled allows to turn this backend on.
	Enabled bool

	// FilesystemBufferSize is the maximum disk space for the fluent-bit file system buffer.
	// +optional
	FilesystemBufferSize *string

	// Index is the splunk index that should be used.
	Index string

	// Host is the hostname or IP of the splunk HEC endpoint.
	Host string

	// Port is the port on which the HEC endpoint is listening.
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

	// TlsHost is the hostname that fluent-bit should request through SNI when connecting to a site that serves different hostnames under one IP.
	TlsHost string

	// CustomData contains a map of custom key value pairs. The custom data is added to each audit log entry using fluentbit's modify filter.
	CustomData map[string]string
}

type AuditBackendS3 struct {
	// Enabled allows to turn this backend on.
	Enabled bool

	// FilesystemBufferSize is the maximum disk space for the fluent-bit file system buffer.
	// +optional
	FilesystemBufferSize *string

	// Bucket is the S3 bucket name where audit logs will be stored.
	Bucket string

	// Region is the AWS region where the bucket is located.
	Region string

	// Prefix is the prefix (folder path) where audit logs will be stored in the bucket. Defaults to "/audit-logs".
	// +optional
	Prefix *string

	// S3KeyFormat is the folder structure in which the audit logs will be stored in the bucket. Defaults to "/%Y/%m/%d/%H/%M/%S/$UUID".
	// +optional
	S3KeyFormat *string

	// SecretResourceName is a reference under Shoot.spec.resources to the secret used to authenticate against AWS.
	// The referenced secret must contain:
	// - access_key_id: Required, AWS access key ID
	// - secret_access_key: Required, AWS secret access key
	SecretResourceName string

	// Endpoint is the custom S3 endpoint URL (optional, for S3-compatible storage).
	// +optional
	Endpoint *string

	// TlsEnabled determines whether TLS should be used to communicate with S3.
	// +optional
	TlsEnabled *bool

	// TotalFileSize specify file size in S3. Minimum size is 1M, maximum size is 1G. Defaults to 100M.
	// +optional
	TotalFileSize *string

	// UploadTimeout specify the amount of time in which the logs are uploaded and creates a new file in S3. Defaults to 10m.
	// +optional
	UploadTimeout *string

	// UseCompression enables gzip compression for the S3 objects.
	// +optional
	UseCompression *bool
}
