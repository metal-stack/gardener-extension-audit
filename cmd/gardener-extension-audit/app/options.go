package app

import (
	"os"

	controllercmd "github.com/gardener/gardener/extensions/pkg/controller/cmd"
	heartbeatcmd "github.com/gardener/gardener/extensions/pkg/controller/heartbeat/cmd"
	webhookcmd "github.com/gardener/gardener/extensions/pkg/webhook/cmd"
	auditcmd "github.com/metal-stack/gardener-extension-audit/pkg/cmd"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

// ExtensionName is the name of the extension.
const ExtensionName = "extension-audit"

// Options holds configuration passed to the registry service controller.
type Options struct {
	generalOptions     *controllercmd.GeneralOptions
	auditOptions       *auditcmd.AuthOptions
	restOptions        *controllercmd.RESTOptions
	managerOptions     *controllercmd.ManagerOptions
	controllerOptions  *controllercmd.ControllerOptions
	heartbeatOptions   *heartbeatcmd.Options
	healthOptions      *controllercmd.ControllerOptions
	controllerSwitches *controllercmd.SwitchOptions
	webhookOptions     *webhookcmd.AddToManagerOptions
	reconcileOptions   *controllercmd.ReconcilerOptions
	optionAggregator   controllercmd.OptionAggregator
}

// NewOptions creates a new Options instance.
func NewOptions() *Options {
	// options for the webhook server
	webhookServerOptions := &webhookcmd.ServerOptions{
		Namespace: os.Getenv("WEBHOOK_CONFIG_NAMESPACE"),
	}

	webhookSwitches := auditcmd.WebhookSwitchOptions()
	webhookOptions := webhookcmd.NewAddToManagerOptions(
		"audit",
		"",
		nil,
		webhookServerOptions,
		webhookSwitches,
	)

	options := &Options{
		generalOptions: &controllercmd.GeneralOptions{},
		auditOptions:   &auditcmd.AuthOptions{},
		restOptions:    &controllercmd.RESTOptions{},
		managerOptions: &controllercmd.ManagerOptions{
			// These are default values.
			LeaderElection:             true,
			LeaderElectionID:           controllercmd.LeaderElectionNameID(ExtensionName),
			LeaderElectionResourceLock: resourcelock.LeasesResourceLock,
			LeaderElectionNamespace:    os.Getenv("LEADER_ELECTION_NAMESPACE"),
			MetricsBindAddress:         ":8080",
			HealthBindAddress:          ":8081",
		},
		controllerOptions: &controllercmd.ControllerOptions{
			// This is a default value.
			MaxConcurrentReconciles: 5,
		},
		heartbeatOptions: &heartbeatcmd.Options{
			// This is a default value.
			ExtensionName:        ExtensionName,
			RenewIntervalSeconds: 30,
			Namespace:            os.Getenv("LEADER_ELECTION_NAMESPACE"),
		},
		healthOptions: &controllercmd.ControllerOptions{
			// This is a default value.
			MaxConcurrentReconciles: 5,
		},
		controllerSwitches: auditcmd.ControllerSwitchOptions(),
		reconcileOptions:   &controllercmd.ReconcilerOptions{},
		webhookOptions:     webhookOptions,
	}

	options.optionAggregator = controllercmd.NewOptionAggregator(
		options.generalOptions,
		options.restOptions,
		options.managerOptions,
		options.controllerOptions,
		options.auditOptions,
		controllercmd.PrefixOption("heartbeat-", options.heartbeatOptions),
		controllercmd.PrefixOption("healthcheck-", options.healthOptions),
		options.controllerSwitches,
		options.reconcileOptions,
		options.webhookOptions,
	)

	return options
}
