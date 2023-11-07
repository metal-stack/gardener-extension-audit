package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	SeedAuditResourceName  = "extension-audit"
	ShootAuditResourceName = "extension-audit-shoot"

	ShootAudittailerNamespace = "audit"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AuditConfig configuration resource
type AuditConfig struct {
	metav1.TypeMeta `json:",inline"`

	Persistence *AuditPersistence `json:"persistence,omitempty"`

	AuditPolicy *string `json:"auditPolicy,omitempty"`

	Backends *AuditBackends `json:"backends,omitempty"`
}

type AuditPersistence struct {
	Size             *string `json:"size,omitempty"`
	StorageClassName *string `json:"storageClassName,omitempty"`
}

type AuditBackends struct {
	Log               *AuditBackendLog        `json:"log,omitempty"`
	ClusterForwarding *AuditClusterForwarding `json:"clusterForwarding,omitempty"`
}

type AuditBackendLog struct {
	Enabled bool `json:"enabled"`
}

type AuditClusterForwarding struct {
	Enabled bool `json:"enabled"`
}

// persistentVolumeSize: 10Gi
// auditPolicy: |
//   apiVersion: audit.k8s.io/v1
//   kind: Policy
//   omitStages:
// 	- "RequestReceived"
//   rules:
// 	- level: RequestResponse
// 	  resources:
// 	  - group: ""
// 		resources: ["pods"]
// 	- level: Metadata
// 	  resources:
// 	  - group: ""
// 		resources: ["pods/log", "pods/status"]
// backends:
//   log: # just logs the audit traces in the audit-forwarder
// 	enabled: true
//   cluster-forward: # forwards logs to an audittailer in the shoot cluster as soon as the pod runs
// 	enabled: true
//   splunk:
// 	enabled: true
// 	config:
// 	  hecToken: <token>
// 	  index: <index>
// 	  hecHost: https://<host>
// 	  hecPort: <port>
// 	  tlsEnabled: true
// 	  hecCAFile: <ca-cert>
// ClusterAudit enables the deployment of a non-null audit policy to the apiserver and the forwarding
// of the audit events into the cluster where they appear as container log of an audittailer pod, where they
// can be picked up by any of the available Kubernetes logging solutions.
// +optional
// ClusterAudit *bool
// AuditToSplunk enables the forwarding of the apiserver auditlog to a defined splunk instance in addition to
// forwarding it into the cluster. Needs the clusterAudit featureGate to be active.
// +optional
// AuditToSplunk *bool

// ClusterAudit enables the deployment of a non-null audit policy to the apiserver and the forwarding
// of the audit events into the cluster where they appear as container log of an audittailer pod, where they
// can be picked up by any of the available Kubernetes logging solutions.
// +optional
// ClusterAudit *bool `json:"clusterAudit,omitempty"`
// AuditToSplunk enables the forwarding of the apiserver auditlog to a defined splunk instance in addition to
// forwarding it into the cluster. Needs the clusterAudit featureGate to be active.
// +optional
// AuditToSplunk *bool `json:"auditToSplunk,omitempty"`
