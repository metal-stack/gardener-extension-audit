package cmd

import (
	controllercmd "github.com/gardener/gardener/extensions/pkg/controller/cmd"
	webhookcmd "github.com/gardener/gardener/extensions/pkg/webhook/cmd"
	"github.com/metal-stack/gardener-extension-audit/pkg/controller"
	"github.com/metal-stack/gardener-extension-audit/pkg/webhook/kapiserver"
)

// ControllerSwitchOptions are the controllercmd.SwitchOptions for the provider controllers.
func ControllerSwitchOptions() *controllercmd.SwitchOptions {
	return controllercmd.NewSwitchOptions(
		controllercmd.Switch(controller.ControllerName, controller.AddToManager),
	)
}

// WebhookSwitchOptions are the webhookcmd.SwitchOptions for the provider webhooks.
func WebhookSwitchOptions() *webhookcmd.SwitchOptions {
	return webhookcmd.NewSwitchOptions(
		webhookcmd.Switch("audit-webhook", kapiserver.New),
	)
}
