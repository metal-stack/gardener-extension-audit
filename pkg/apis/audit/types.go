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

	Persistence *AuditPersistence

	WebhookMode AuditWebhookMode

	AuditPolicy *string

	Backends *AuditBackends
}

type AuditPersistence struct {
	Size             *string
	StorageClassName *string
}

type AuditBackends struct {
	Log               *AuditBackendLog
	ClusterForwarding *AuditClusterForwarding
}

type AuditBackendLog struct {
	Enabled bool
}

type AuditClusterForwarding struct {
	Enabled bool
}
