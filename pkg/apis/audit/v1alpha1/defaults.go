package v1alpha1

import (
	"github.com/metal-stack/metal-lib/pkg/pointer"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
)

func addDefaultingFuncs(scheme *runtime.Scheme) error {
	return RegisterDefaults(scheme)
}

// SetDefaults_AuditPersistence sets the defaults for the AuditPersistence configuration
func SetDefaults_AuditPersistence(persistence *AuditPersistence) {
	if persistence.Size == nil {
		defaultCacheSize := resource.MustParse("1Gi")
		persistence.Size = &defaultCacheSize
	}
}

// SetDefaults_AuditConfig sets the defaults for the AuditConfig configuration
func SetDefaults_AuditConfig(a *AuditConfig) {
	if a.Replicas == nil {
		a.Replicas = pointer.Pointer(int32(2))
	}

	DefaultBackends(a.Backends)
}

func DefaultBackends(backends *AuditBackends) {
	if backends == nil {
		return
	}

	defaultBackendClusterForwarding(backends.ClusterForwarding)
	defaultBackendSplunk(backends.Splunk)
}

func defaultBackendClusterForwarding(backend *AuditBackendClusterForwarding) {
	if backend == nil {
		return
	}

	if backend.FilesystemBufferSize == nil {
		backend.FilesystemBufferSize = pointer.Pointer("900M")
	}
}

func defaultBackendSplunk(backend *AuditBackendSplunk) {
	if backend == nil {
		return
	}

	if backend.FilesystemBufferSize == nil {
		backend.FilesystemBufferSize = pointer.Pointer("900M")
	}
}
