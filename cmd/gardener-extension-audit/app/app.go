package app

import (
	"context"
	"fmt"
	"os"

	"github.com/metal-stack/gardener-extension-audit/pkg/apis/audit/install"
	"github.com/metal-stack/gardener-extension-audit/pkg/controller/audit"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	heartbeatcontroller "github.com/gardener/gardener/extensions/pkg/controller/heartbeat"
	"github.com/gardener/gardener/extensions/pkg/util"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	gardenerhealthz "github.com/gardener/gardener/pkg/healthz"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/spf13/cobra"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	componentbaseconfig "k8s.io/component-base/config"
)

var log = logf.Log.WithName("gardener-extension-audit")

// NewControllerManagerCommand creates a new command that is used to start the controller.
func NewControllerManagerCommand(ctx context.Context) *cobra.Command {
	options := NewOptions()

	cmd := &cobra.Command{
		Use:           "gardener-extension-audit",
		Short:         "provides cluster audit for shoot clusters.",
		SilenceErrors: true,

		RunE: func(cmd *cobra.Command, args []string) error {
			if err := options.optionAggregator.Complete(); err != nil {
				return fmt.Errorf("error completing options: %w", err)
			}
			if err := options.heartbeatOptions.Validate(); err != nil {
				return err
			}

			cmd.SilenceUsage = true
			return options.run(ctx)
		},
	}

	options.optionAggregator.AddFlags(cmd.Flags())

	return cmd
}

func (o *Options) run(ctx context.Context) error {
	util.ApplyClientConnectionConfigurationToRESTConfig(&componentbaseconfig.ClientConnectionConfiguration{
		QPS:   100.0,
		Burst: 130,
	}, o.restOptions.Completed().Config)

	mgrOpts := o.managerOptions.Completed().Options()

	mgrOpts.Cache = cache.Options{
		ByObject: map[client.Object]cache.ByObject{
			&corev1.Secret{}:    {},
			&corev1.ConfigMap{}: {},
		},
		// &corev1.Secret{},    // applied for ManagedResources
		// &corev1.ConfigMap{}, // applied for monitoring config
	}

	// Operators can enable the source cluster option via SOURCE_CLUSTER environment variable.
	// In-cluster config will be used if no SOURCE_KUBECONFIG is specified.
	//
	// The source cluster is for instance used by Gardener's certificate controller, to maintain certificate
	// secrets in a different cluster ('runtime-garden') than the cluster where the webhook configurations
	// are maintained ('virtual-garden').
	var sourceClusterConfig *rest.Config
	if sourceClusterEnabled := os.Getenv("SOURCE_CLUSTER"); sourceClusterEnabled != "" {
		log.Info("Configuring source cluster option")
		var err error
		sourceClusterConfig, err = clientcmd.BuildConfigFromFlags("", os.Getenv("SOURCE_KUBECONFIG"))
		if err != nil {
			return err
		}
		mgrOpts.LeaderElectionConfig = sourceClusterConfig
	} else {
		// Restrict the cache for secrets to the configured namespace to avoid the need for cluster-wide list/watch permissions.
		mgrOpts.Cache = cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				&corev1.Secret{}: {Namespaces: map[string]cache.Config{o.webhookOptions.Server.Completed().Namespace: {}}},
			},
		}
	}

	mgr, err := manager.New(o.restOptions.Completed().Config, mgrOpts)
	if err != nil {
		return fmt.Errorf("could not instantiate controller-manager: %w", err)
	}

	if err := extensionscontroller.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("could not update manager scheme: %w", err)
	}

	if err := install.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("could not update manager scheme: %w", err)
	}

	ctrlConfig := o.auditOptions.Completed()
	ctrlConfig.Apply(&audit.DefaultAddOptions.Config)
	o.controllerOptions.Completed().Apply(&audit.DefaultAddOptions.ControllerOptions)
	o.reconcileOptions.Completed().Apply(&audit.DefaultAddOptions.IgnoreOperationAnnotation)
	o.heartbeatOptions.Completed().Apply(&heartbeatcontroller.DefaultAddOptions)

	var sourceCluster cluster.Cluster
	if sourceClusterConfig != nil {
		sourceCluster, err = cluster.New(sourceClusterConfig, func(opts *cluster.Options) {
			opts.Logger = log
			opts.Cache.DefaultNamespaces = map[string]cache.Config{v1beta1constants.GardenNamespace: {}}
		})
		if err != nil {
			return err
		}

		if err := mgr.AddReadyzCheck("source-informer-sync", gardenerhealthz.NewCacheSyncHealthz(sourceCluster.GetCache())); err != nil {
			return err
		}

		if err = mgr.Add(sourceCluster); err != nil {
			return err
		}
	}

	if err := o.controllerSwitches.Completed().AddToManager(ctx, mgr); err != nil {
		return fmt.Errorf("could not add controllers to manager: %w", err)
	}

	if _, err := o.webhookOptions.Completed().AddToManager(ctx, mgr, sourceCluster); err != nil {
		return fmt.Errorf("could not add the mutating webhook to manager: %w", err)
	}

	if err := mgr.AddReadyzCheck("informer-sync", gardenerhealthz.NewCacheSyncHealthz(mgr.GetCache())); err != nil {
		return fmt.Errorf("could not add ready check for informers: %w", err)
	}

	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("could not add health check to manager: %w", err)
	}

	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("error running manager: %w", err)
	}

	return nil
}
