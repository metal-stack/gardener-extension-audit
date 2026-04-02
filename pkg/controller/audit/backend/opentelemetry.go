package backend

import (
	"fmt"
	"regexp"

	"github.com/gardener/gardener/pkg/extensions"
	"github.com/gardener/gardener/pkg/utils"
	"github.com/metal-stack/gardener-extension-audit/pkg/apis/audit/v1alpha1"
	"github.com/metal-stack/gardener-extension-audit/pkg/fluentbitconfig"
	"github.com/metal-stack/metal-lib/pkg/pointer"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type OpenTelemetry struct {
	backend *v1alpha1.AuditBackendOpenTelemetry
	secret  *corev1.Secret
}

func NewOpenTelemetry(backend *v1alpha1.AuditBackendOpenTelemetry, secret *corev1.Secret) (OpenTelemetry, error) {
	err := validateOpenTelemetryAttributes(backend)
	if err != nil {
		return OpenTelemetry{}, err
	}

	_, ok := secret.Data[v1alpha1.OpenTelemetrySecretTokenKey]
	if !ok {
		return OpenTelemetry{}, fmt.Errorf("referenced bearer token secret does not contain contents under key %q", v1alpha1.OpenTelemetrySecretTokenKey)
	}

	if backend.Host == "" {
		return OpenTelemetry{}, fmt.Errorf("backend must contain a host")
	}
	if backend.Port == "" {
		return OpenTelemetry{}, fmt.Errorf("backend must contain a port")
	}

	return OpenTelemetry{
		backend: backend,
		secret:  secret,
	}, nil
}

var validOpenTelemetryAttributeExpression = regexp.MustCompile("^[a-zA-Z0-9._-]+$")

// validateOpenTelemetryAttributes makes sure that all key/value pairs contain only letters,
// numbers, '_' or '.'. Empty keys or values are also not allowed. The AuditIDAttribute must
// also conform to these restrictions.
func validateOpenTelemetryAttributes(backend *v1alpha1.AuditBackendOpenTelemetry) error {
	isValidOpenTelemetryAttributeString := func(s string) bool {
		return validOpenTelemetryAttributeExpression.MatchString(s)
	}

	for key := range backend.Attributes {
		if !isValidOpenTelemetryAttributeString(key) {
			return fmt.Errorf("%q is not a valid attribute key for OpenTelemetry", key)
		}
	}

	if backend.AuditIDAttribute != "" && !isValidOpenTelemetryAttributeString(backend.AuditIDAttribute) {
		return fmt.Errorf("%q is not a valid auditIDAttribute name", backend.AuditIDAttribute)
	}

	return nil
}

func (s OpenTelemetry) FluentBitConfig(cluster *extensions.Cluster) fluentbitconfig.Config {
	openTelemetryConfig := map[string]any{
		"match":                    "audit",
		"name":                     "opentelemetry",
		"retry_limit":              "no_limits", // let fluent-bit never discard any data
		"storage.total_limit_size": pointer.SafeDeref(s.backend.FilesystemBufferSize),
		"host":                     s.backend.Host,
		"port":                     s.backend.Port,
		"header":                   []string{"Authorization Bearer ${OTLP_BEARER_TOKEN}"},
		// use body field in log entry as body for the otlp log entry
		"logs_body_key": "$body",
	}

	if s.backend.TlsEnabled != nil && *s.backend.TlsEnabled {
		openTelemetryConfig["tls"] = "on"
		openTelemetryConfig["tls.verify"] = "on"
		openTelemetryConfig["tls.verify_hostname"] = "on"
		if s.backend.TlsHost != "" {
			openTelemetryConfig["tls.vhost"] = s.backend.TlsHost
		}
	}

	if s.backend.BatchSize != nil {
		openTelemetryConfig["batch_size"] = fmt.Sprintf("%v", *s.backend.BatchSize)
	}

	var auditIDCopyCode string
	if s.backend.AuditIDAttribute != "" {
		auditIDCopyCode = fmt.Sprintf(`meta["%v"] = entry["auditID"]`, s.backend.AuditIDAttribute)
	}

	// Audit logs sent by Kubernetes are already batched, but OTLP also supports batching. Thus, split the
	// k8s audit log batch and add the entries individually as log messages.
	code := fmt.Sprintf(`function split_json_logs(tag, timestamp, group, metadata, record)
	local new_records = {}
	local new_metadatas = {}
	local array = record["items"]
	
	if type(array) == "table" then
		for i, entry in ipairs(array) do
			table.insert(new_records, {body=entry, SeverityText="INFO"})
			local meta = {}
			%v
			table.insert(new_metadatas, meta)
		end
		return 1, timestamp, new_metadatas, new_records
	end
	
	return 0, 0, 0, 0
end`, auditIDCopyCode)

	filters := []map[string]string{
		{
			"name": "lua",
			"call": "split_json_logs",
			"code": code,
		},
		{
			"name": "opentelemetry_envelope",
		},
	}

	if len(s.backend.Attributes) > 0 {
		for key, value := range s.backend.Attributes {
			filters = append(filters, map[string]string{
				"name":    "content_modifier",
				"context": "attributes",
				"action":  "upsert",
				"key":     key,
				"value":   value,
			})
		}
	}

	openTelemetryConfig["processors"] = map[string]any{
		"logs": filters,
	}

	fluentbitBackendOpenTelemetry := fluentbitconfig.Config{
		Output: []fluentbitconfig.Output{openTelemetryConfig},
	}
	return fluentbitBackendOpenTelemetry
}

func (s OpenTelemetry) PatchAuditWebhook(sts *appsv1.StatefulSet) {
	sts.Spec.Template.Spec.Containers[0].Env = append(sts.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
		Name: "OTLP_BEARER_TOKEN",
		ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: s.secret.Name,
				},
				Key: v1alpha1.OpenTelemetrySecretTokenKey,
			},
		},
	})

	sts.Spec.Template.ObjectMeta.Annotations["checksum/opentelemetry-secret"] = utils.ComputeSecretChecksum(s.secret.Data)
}

func (s OpenTelemetry) AdditionalSeedObjects(*extensions.Cluster) []client.Object {
	return []client.Object{}
}

func (s OpenTelemetry) AdditionalShootObjects(*extensions.Cluster) []client.Object {
	return []client.Object{}
}
