package fluentbitconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
						"add":   []string{"cluster devcluster"},
					},
				},
				Output: []Output{
					map[string]any{
						"name":  "    stdout  ",
						"match": "*",
					},
					map[string]any{
						"name": "null",
					},
				},
				Includes: []Include{
					"data/*.yaml",
				},
			},
			want: `service:
    flush: "1"
    log_level: info
pipeline:
    inputs:
        - name: http
    filters:
        - add:
            - cluster devcluster
          match: '*'
          name: modify
    outputs:
        - match: '*'
          name: '    stdout  '
        - name: "null"
includes:
    - data/*.yaml`,
		},
		{
			name: "only output section",
			config: &Config{
				Output: []Output{
					map[string]any{
						"name":  "stdout",
						"match": "*",
					},
				},
			},
			want: `pipeline:
    outputs:
        - match: '*'
          name: stdout`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.Generate()
			assert.Equal(t, tt.want, got)
		})
	}
}
