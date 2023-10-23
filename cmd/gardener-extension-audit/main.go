package main

import (
	"os"

	"github.com/gardener/gardener/pkg/logger"
	"github.com/metal-stack/gardener-extension-audit/cmd/gardener-extension-audit/app"

	runtimelog "sigs.k8s.io/controller-runtime/pkg/log"
)

func main() {
	runtimelog.SetLogger(logger.MustNewZapLogger(logger.InfoLevel, logger.FormatJSON))
	cmd := app.NewControllerManagerCommand()

	if err := cmd.Execute(); err != nil {
		runtimelog.Log.Error(err, "error executing the main controller command")
		os.Exit(1)
	}
}
