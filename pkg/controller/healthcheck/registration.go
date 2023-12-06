package healthcheck

import (
	"time"

	extensionsconfig "github.com/gardener/gardener/extensions/pkg/apis/config"
	"github.com/gardener/gardener/extensions/pkg/controller/healthcheck"
	"github.com/gardener/gardener/extensions/pkg/controller/healthcheck/general"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/metal-stack/gardener-extension-audit/pkg/apis/audit/v1alpha1"
	"github.com/metal-stack/gardener-extension-audit/pkg/controller/audit"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var (
	defaultSyncPeriod = 60 * time.Second
	// DefaultAddOptions contains configuration for the health check controller.
	DefaultAddOptions = healthcheck.DefaultAddArgs{
		HealthCheckConfig: extensionsconfig.HealthCheckConfig{SyncPeriod: metav1.Duration{Duration: defaultSyncPeriod}},
	}
)

// RegisterHealthChecks registers health checks for each extension resource
// HealthChecks are grouped by extension (e.g worker), extension.type (e.g aws) and  Health Check Type (e.g SystemComponentsHealthy)
func RegisterHealthChecks(mgr manager.Manager, opts healthcheck.DefaultAddArgs) error {
	return healthcheck.DefaultRegistration(
		audit.Type,
		extensionsv1alpha1.SchemeGroupVersion.WithKind(extensionsv1alpha1.ExtensionResource),
		func() client.ObjectList { return &extensionsv1alpha1.ExtensionList{} },
		func() extensionsv1alpha1.Object { return &extensionsv1alpha1.Extension{} },
		mgr,
		opts,
		nil,
		[]healthcheck.ConditionTypeToHealthCheck{
			{
				ConditionType: string(gardencorev1beta1.ShootSystemComponentsHealthy),
				HealthCheck:   general.CheckManagedResource(v1alpha1.ShootAuditResourceName),
			},
			{
				ConditionType: string(gardencorev1beta1.ShootSystemComponentsHealthy),
				HealthCheck:   general.CheckManagedResource(v1alpha1.SeedAuditResourceName),
			},
			{
				ConditionType: string(gardencorev1beta1.ShootSystemComponentsHealthy),
				HealthCheck:   backendHealth(opts.HealthCheckConfig.SyncPeriod.Duration),
			},
		},
		sets.Set[gardencorev1beta1.ConditionType]{},
	)
}

// AddToManager adds a controller with the default Options.
func AddToManager(mgr manager.Manager) error {
	return RegisterHealthChecks(mgr, DefaultAddOptions)
}
