package fluentbitconfig

import (
	"strings"

	"gopkg.in/yaml.v3"
)

type (
	Config struct {
		Service  Service
		Input    []Input
		Filter   []Filter
		Output   []Output
		Includes []Include
	}

	Service map[string]string
	Input   map[string]string
	// some filter attributes must be passed as a list such that "string" is not sufficient
	Filter  map[string]any
	Output  map[string]string
	Include string
)

type yamlConfig struct {
	Service  Service `yaml:"service,omitempty"`
	Pipeline struct {
		Input  []Input  `yaml:"inputs,omitempty"`
		Filter []Filter `yaml:"filters,omitempty"`
		Output []Output `yaml:"outputs,omitempty"`
	} `yaml:"pipeline"`
	Includes []Include `yaml:"includes,omitempty"`
}

func (c Config) Generate() string {
	yc := yamlConfig{
		Service:  c.Service,
		Includes: c.Includes,
	}
	yc.Pipeline.Input = c.Input
	yc.Pipeline.Filter = c.Filter
	yc.Pipeline.Output = c.Output

	out, err := yaml.Marshal(yc)
	if err != nil {
		// as this function is tested, this should never happen...
		panic(err)
	}

	return strings.TrimSpace(string(out))
}
