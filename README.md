# gardener-extension-audit

Provides a Gardener extension for managing kube-apiserver audit logs for a shoot cluster.

The extension spins up a fluent-bit-based audit sink in the seed's shoot namespace prior to starting the shoot's API server. Therefore, it is required to run this extension with the reconcile lifecycle policy `BeforeKubeAPIServer`. Also the deletion has to happen `BeforeKubeAPIServer` as otherwise the managed resources of this extension block the shoot deletion flow.

This sink has the ability to buffer audit logs to a persistent volume and send them to the supported backends.

## Specifying An Audit Policy

A custom audit policy can be natively configured by Gardener in the shoot spec's API server configuration under `.spec.kubernetes.kubeAPIServer.auditConfig.auditPolicy.configMapRef.name`.

## Supported Backends

- Splunk
- S3
- Log (just logs to the container, only for devel-purposes)
- Cluster Forwarding (forwards audit logs into a pod in the shoot cluster)

> [!IMPORTANT]
> The Cluster Forwarding backend is mainly intended for showcasing and not for production purposes. It is known not to work with Gardener HA Control Planes and also there were issues reported when using it in combination with the Cilium CNI configured kubeproxyless with Native-Routing (audit entries do not arrive at the `audittailer` pod).

## Development

This extension can be developed in the gardener-local devel environment.

1. Start up the local devel environment
1. The extension's docker image can be pushed into Kind using `make push-to-gardener-local`
1. Install the extension `kubectl apply -k example/`
1. Parametrize the `example/shoot.yaml` and apply with `kubectl -f example/shoot.yaml`
