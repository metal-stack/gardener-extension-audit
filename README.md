# gardener-extension-audit

Provides a Gardener extension for sending managing kube-apiserver audit logs for a shoot cluster.

The extension spins up a fluentbit-based audit sink in the seed's shoot namespace prior to starting the shoot's API server. Therefore, it is required to run this extension with the reconcile lifecycle policy `BeforeKubeAPIServer`. This sink has the ability to buffer audit logs to a persistent volume and send them to the supported backends.

## Specifying An Audit Policy

A custom audit policy can be natively configured by Gardener in the shoot spec's API server configuration under `.spec.kubernetes.kubeAPIServer.auditConfig.auditPolicy.configMapRef`.

## Supported Backends

- Log (just logs to the container, only for developers)
- Cluster Forwarding (forwards audit logs into a pod in the shoot cluster, should not be used for production purposes)
- Splunk
