package backend

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

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
			desc: "valid output config s3",
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
			desc: "valid output config loki",
			input: `[OUTPUT]
			    name   loki
			    match  *
			    labels job=fluentbit, $sub['stream']`,
			expected: map[string]string{
				"name":   "loki",
				"match":  "*",
				"labels": "job=fluentbit, $sub['stream']",
			},
			assertionError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			desc: "valid output config with comments",
			input: `[OUTPUT]
			    # this is a comment in a new line
			    name   loki
			    match  * # this is a comment inline
			    labels job=fluentbit, $sub['stream']`,
			expected: map[string]string{
				"#":      "this is a comment in a new line",
				"name":   "loki",
				"match":  "* # this is a comment inline",
				"labels": "job=fluentbit, $sub['stream']",
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
			desc:     "empty configuration",
			input:    ``,
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

func Test_isValidCertificate(t *testing.T) {
	// Generate a valid test certificate
	validCert := generateTestCertificate(t)
	validCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: validCert.Raw,
	})

	tt := []struct {
		desc     string
		input    []byte
		expected bool
	}{
		{
			desc:     "valid certificate",
			input:    validCertPEM,
			expected: true,
		},
		{
			desc:     "invalid PEM format",
			input:    []byte("not a valid PEM"),
			expected: false,
		},
		{
			desc: "wrong PEM type",
			input: pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: []byte("some data"),
			}),
			expected: false,
		},
		{
			desc: "corrupted certificate data",
			input: pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: []byte("corrupted data"),
			}),
			expected: false,
		},
		{
			desc:     "empty input",
			input:    []byte{},
			expected: false,
		},
		{
			desc: "shell script attempt",
			input: pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: []byte("#!/bin/bash\nrm -rf /"),
			}),
			expected: false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			result := isValidCertificate(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func Test_isValidPrivateKey(t *testing.T) {
	// Generate valid test keys
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	rsaKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	})

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	ecKeyBytes, err := x509.MarshalECPrivateKey(ecKey)
	assert.NoError(t, err)
	ecKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: ecKeyBytes,
	})

	pkcs8KeyBytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	assert.NoError(t, err)
	pkcs8KeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8KeyBytes,
	})

	tt := []struct {
		desc     string
		input    []byte
		expected bool
	}{
		{
			desc:     "valid RSA private key",
			input:    rsaKeyPEM,
			expected: true,
		},
		{
			desc:     "valid EC private key",
			input:    ecKeyPEM,
			expected: true,
		},
		{
			desc:     "valid PKCS8 private key",
			input:    pkcs8KeyPEM,
			expected: true,
		},
		{
			desc:     "invalid PEM format",
			input:    []byte("not a valid PEM"),
			expected: false,
		},
		{
			desc: "wrong PEM type",
			input: pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: []byte("some data"),
			}),
			expected: false,
		},
		{
			desc: "corrupted key data",
			input: pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: []byte("corrupted data"),
			}),
			expected: false,
		},
		{
			desc:     "empty input",
			input:    []byte{},
			expected: false,
		},
		{
			desc: "shell script attempt",
			input: pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: []byte("#!/bin/bash\nrm -rf /"),
			}),
			expected: false,
		},
		{
			desc: "unknown key type",
			input: pem.EncodeToMemory(&pem.Block{
				Type:  "UNKNOWN KEY",
				Bytes: []byte("some data"),
			}),
			expected: false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			result := isValidPrivateKey(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// generateTestCertificate creates a valid self-signed certificate for testing
func generateTestCertificate(t *testing.T) *x509.Certificate {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	assert.NoError(t, err)

	cert, err := x509.ParseCertificate(certBytes)
	assert.NoError(t, err)

	return cert
}
