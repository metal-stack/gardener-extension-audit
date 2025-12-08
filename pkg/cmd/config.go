package cmd

import (
	"errors"
	"os"

	healthcheckconfigv1alpha1 "github.com/gardener/gardener/extensions/pkg/apis/config/v1alpha1"
	configapi "github.com/metal-stack/gardener-extension-audit/pkg/apis/config"
	"github.com/metal-stack/gardener-extension-audit/pkg/apis/config/v1alpha1"

	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

var (
	scheme  *runtime.Scheme
	decoder runtime.Decoder
)

func init() {
	scheme = runtime.NewScheme()
	utilruntime.Must(configapi.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))

	decoder = serializer.NewCodecFactory(scheme).UniversalDecoder()
}

// AuditOptions holds options related to the audit service.
type AuditOptions struct {
	ConfigLocation string
	config         *AuditServiceConfig
}

// AddFlags implements Flagger.AddFlags.
func (o *AuditOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.ConfigLocation, "config", "", "Path to audit configuration")
}

// Complete implements Completer.Complete.
func (o *AuditOptions) Complete() error {
	if o.ConfigLocation == "" {
		return errors.New("config location is not set")
	}
	data, err := os.ReadFile(o.ConfigLocation)
	if err != nil {
		return err
	}

	config := configapi.ControllerConfiguration{}
	_, _, err = decoder.Decode(data, nil, &config)
	if err != nil {
		return err
	}

	// if errs := validation.ValidateConfiguration(&config); len(errs) > 0 {
	// 	return errs.ToAggregate()
	// }

	o.config = &AuditServiceConfig{
		config: config,
	}

	return nil
}

// Completed returns the decoded AuditServiceConfig instance. Only call this if `Complete` was successful.
func (o *AuditOptions) Completed() *AuditServiceConfig {
	return o.config
}

// AuditServiceConfig contains configuration information about the audit service.
type AuditServiceConfig struct {
	config configapi.ControllerConfiguration
}

// Apply applies the AuditOptions to the passed ControllerOptions instance.
func (c *AuditServiceConfig) Apply(config *configapi.ControllerConfiguration) {
	*config = c.config
}

// ApplyHealthCheckConfig applies the HealthCheckConfig.
func (c *AuditServiceConfig) ApplyHealthCheckConfig(config *healthcheckconfigv1alpha1.HealthCheckConfig) {
	if c.config.HealthCheckConfig != nil {
		*config = *c.config.HealthCheckConfig
	}
}
