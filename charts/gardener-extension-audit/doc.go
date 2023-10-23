//go:generate sh -c "../../vendor/github.com/gardener/gardener/hack/generate-controller-registration.sh audit . $(cat ../../VERSION) ../../example/controller-registration.yaml Extension:audit"

// Package chart enables go:generate support for generating the correct controller registration.
package chart
