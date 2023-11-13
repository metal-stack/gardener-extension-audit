# gardener-extension-audit

Provides a Gardener extension for managing kube-apiserver audit logs for a shoot cluster.

The extension spins up a fluentbit-based audit sink in the seed's shoot namespace prior to starting the shoot's API server. Therefore, it is required to run this extension with the reconcile lifecycle policy `BeforeKubeAPIServer`.

This sink has the ability to buffer audit logs to a persistent volume and send them to the supported backends.

## Specifying An Audit Policy

A custom audit policy can be natively configured by Gardener in the shoot spec's API server configuration under `.spec.kubernetes.kubeAPIServer.auditConfig.auditPolicy.configMapRef.name`.

## Supported Backends

- Log (just logs to the container, only for devel-purposes)
- Cluster Forwarding (forwards audit logs into a pod in the shoot cluster, should not be used for production purposes)
- Splunk

## Development

This extension can be developed in the gardener-local devel environment.

1. Start up the local devel environment
1. The extension's docker image can be pushed into Kind using `make push-to-gardener-local`
1. Install the extension `kubectl apply -k example/`
1. Parametrize the `example/shoot.yaml` and apply with `kubectl -f example/shoot.yaml`
