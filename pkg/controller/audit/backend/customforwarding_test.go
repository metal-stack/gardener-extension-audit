package backend

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_parseFluentBitOutput(t *testing.T) {
	tt := []struct {
		desc           string
		input          string
		expected       map[string]string
		assertionError func(*testing.T, error)
	}{
		{
			desc: "valid output config",
			input: `[OUTPUT]
				Name  s3
				Match *
				bucket my-bucket
				region us-west-2`,
			expected: map[string]string{
				"Name":   "s3",
				"Match":  "*",
				"bucket": "my-bucket",
				"region": "us-west-2",
			},
			assertionError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			desc: "missing OUTPUT section",
			input: `Name  s3
				Match *
				bucket my-bucket
				region us-west-2`,
			expected: nil,
			assertionError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.ErrorContains(t, err, "missing [OUTPUT] section")
			},
		},
		{
			desc: "empty configuration",
			input: ``,
			expected: nil,
			assertionError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.ErrorContains(t, err, "empty configuration")
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			config, err := parseFluentBitOutput(tc.input)
			tc.assertionError(t, err)
			if err == nil {
				assert.Equal(t, tc.expected, config)
			}
		})
	}

}
