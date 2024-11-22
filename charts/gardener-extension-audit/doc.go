//go:generate sh -c "bash $GARDENER_HACK_DIR/generate-controller-registration.sh audit . $(cat ../../VERSION) ../../example/controller-registration.yaml Extension:audit"

// Package chart enables go:generate support for generating the correct controller registration.
package chart
