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

	Persistence *AuditPersistence `json:"persistence,omitempty"`

	WebhookMode AuditWebhookMode `json:"webhookMode,omitempty"`

	AuditPolicy *string `json:"auditPolicy,omitempty"`

	Backends *AuditBackends `json:"backends,omitempty"`
}

type AuditPersistence struct {
	Size             *string `json:"size,omitempty"`
	StorageClassName *string `json:"storageClassName,omitempty"`
}

type AuditBackends struct {
	Log               *AuditBackendLog               `json:"log,omitempty"`
	ClusterForwarding *AuditBackendClusterForwarding `json:"clusterForwarding,omitempty"`
	Splunk            *AuditBackendSplunk            `json:"splunk,omitempty"`

	// Possible backends that would be helpful as well:
	// - Forward
	// - Loki
	// - Elasticsearch
	// - Forward
	// - Kafka
}

type AuditBackendLog struct {
	Enabled bool `json:"enabled"`
}

type AuditBackendClusterForwarding struct {
	Enabled bool `json:"enabled"`
}
type AuditBackendSplunk struct {
	Enabled bool `json:"enabled"`

	Index      string `json:"index"`
	Host       string `json:"host"`
	Port       string `json:"port"`
	Token      string `json:"hecToken"`
	CaFile     string `json:"caFile"`
	TlsEnabled bool   `json:"tls"`
}
