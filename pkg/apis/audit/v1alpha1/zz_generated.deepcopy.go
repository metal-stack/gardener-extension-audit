//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
2023 Copyright metal-stack.
*/

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AuditBackendClusterForwarding) DeepCopyInto(out *AuditBackendClusterForwarding) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AuditBackendClusterForwarding.
func (in *AuditBackendClusterForwarding) DeepCopy() *AuditBackendClusterForwarding {
	if in == nil {
		return nil
	}
	out := new(AuditBackendClusterForwarding)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AuditBackendLog) DeepCopyInto(out *AuditBackendLog) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AuditBackendLog.
func (in *AuditBackendLog) DeepCopy() *AuditBackendLog {
	if in == nil {
		return nil
	}
	out := new(AuditBackendLog)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AuditBackendSplunk) DeepCopyInto(out *AuditBackendSplunk) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AuditBackendSplunk.
func (in *AuditBackendSplunk) DeepCopy() *AuditBackendSplunk {
	if in == nil {
		return nil
	}
	out := new(AuditBackendSplunk)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AuditBackends) DeepCopyInto(out *AuditBackends) {
	*out = *in
	if in.Log != nil {
		in, out := &in.Log, &out.Log
		*out = new(AuditBackendLog)
		**out = **in
	}
	if in.ClusterForwarding != nil {
		in, out := &in.ClusterForwarding, &out.ClusterForwarding
		*out = new(AuditBackendClusterForwarding)
		**out = **in
	}
	if in.Splunk != nil {
		in, out := &in.Splunk, &out.Splunk
		*out = new(AuditBackendSplunk)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AuditBackends.
func (in *AuditBackends) DeepCopy() *AuditBackends {
	if in == nil {
		return nil
	}
	out := new(AuditBackends)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AuditConfig) DeepCopyInto(out *AuditConfig) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.Persistence.DeepCopyInto(&out.Persistence)
	if in.Replicas != nil {
		in, out := &in.Replicas, &out.Replicas
		*out = new(int32)
		**out = **in
	}
	if in.Backends != nil {
		in, out := &in.Backends, &out.Backends
		*out = new(AuditBackends)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AuditConfig.
func (in *AuditConfig) DeepCopy() *AuditConfig {
	if in == nil {
		return nil
	}
	out := new(AuditConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AuditConfig) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AuditPersistence) DeepCopyInto(out *AuditPersistence) {
	*out = *in
	if in.Size != nil {
		in, out := &in.Size, &out.Size
		x := (*in).DeepCopy()
		*out = &x
	}
	if in.StorageClassName != nil {
		in, out := &in.StorageClassName, &out.StorageClassName
		*out = new(string)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AuditPersistence.
func (in *AuditPersistence) DeepCopy() *AuditPersistence {
	if in == nil {
		return nil
	}
	out := new(AuditPersistence)
	in.DeepCopyInto(out)
	return out
}
