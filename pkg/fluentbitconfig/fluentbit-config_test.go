package fluentbitconfig

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestConfig_Generate(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		want   string
	}{
		{
			name: "full config",
			config: &Config{
				Service: map[string]string{
					"flush":     "1",
					"log_level": "info",
				},
				Input: []Input{
					map[string]string{
						"name": "http",
					},
				},
				Filter: []Filter{
					{
						"name":  "modify",
						"match": "*",
						"add":   "cluster devcluster",
					},
				},
				Output: []Output{
					map[string]string{
						"name":  "    stdout  ",
						"match": "*",
					},
					map[string]string{
						"name": "null",
					},
				},
				Includes: []Include{
					"data/*.conf",
				},
			},
			want: `[SERVICE]
    flush 1
    log_level info

[INPUT]
    name http

[FILTER]
    add cluster devcluster
    match *
    name modify

[OUTPUT]
    match *
    name stdout
[OUTPUT]
    name null

@INCLUDE data/*.conf`,
		},
		{
			name: "only output section",
			config: &Config{
				Output: []Output{
					map[string]string{
						"name":  "stdout",
						"match": "*",
					},
				},
			},
			want: `[OUTPUT]
    match *
    name stdout`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.Generate()
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Logf("Got:\n\n%s\n", got)
				t.Errorf("diff: %s", diff)
			}
		})
	}
}
