package healthcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gardener/gardener/extensions/pkg/controller/healthcheck"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/types"
)

type BackendHealthChecker struct {
	logger     logr.Logger
	httpClient *http.Client
	retries    map[string]int
}

func backendHealth() healthcheck.HealthCheck {
	return &BackendHealthChecker{
		httpClient: http.DefaultClient,
		retries:    map[string]int{},
	}
}

func (h *BackendHealthChecker) SetLoggerSuffix(provider, extension string) {
	h.logger = h.logger.WithName(fmt.Sprintf("%s-%s-healthcheck-backend", provider, extension))
}

func (h *BackendHealthChecker) DeepCopy() healthcheck.HealthCheck {
	copy := *h
	return &copy
}

func (h *BackendHealthChecker) Check(ctx context.Context, request types.NamespacedName) (*healthcheck.SingleCheckResult, error) {
	err := h.check(ctx, request.Namespace)
	if err != nil {
		return &healthcheck.SingleCheckResult{ // nolint:nilerr
			Status: gardencorev1beta1.ConditionFalse,
			Detail: err.Error(),
		}, nil
	}

	return &healthcheck.SingleCheckResult{
		Status: gardencorev1beta1.ConditionTrue,
	}, nil
}

func (h *BackendHealthChecker) check(ctx context.Context, namespace string) error {
	if err := h.checkHealthEndpoint(ctx, namespace); err != nil {
		return err
	}

	if err := h.checkRetries(ctx, namespace); err != nil {
		return err
	}

	return nil
}

func (h *BackendHealthChecker) checkHealthEndpoint(ctx context.Context, namespace string) error {
	url := fmt.Sprintf("http://audit-webhook-backend.%s.svc.cluster.local:2020/api/v1/health", namespace)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("unable to create http request: %w", err)
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("unable to do http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	return fmt.Errorf("backend is unhealthy since errors or failures have occurred in the last minute time frame")
}

func (h *BackendHealthChecker) checkRetries(ctx context.Context, namespace string) error {
	// as retries are set to no_limits, fluent-bit does not count unreachable backends as errors or retry_errors
	// therefore, we need to check if there were any retries during the last health check

	type metrics struct {
		Output map[string]struct {
			Retries        int `json:"retries"`
			RetriedRecords int `json:"retried_records"`
		} `json:"output"`
	}

	url := fmt.Sprintf("http://audit-webhook-backend.%s.svc.cluster.local:2020/api/v1/metrics", namespace)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("unable to create http request: %w", err)
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("unable to do http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("metrics endpoint return code was %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read http body: %w", err)
	}

	var m metrics

	err = json.Unmarshal(body, &m)
	if err != nil {
		return fmt.Errorf("unable to unmarshal metrics: %w", err)
	}

	sum := 0
	for _, output := range m.Output {
		sum += output.Retries
	}

	lastCount, ok := h.retries[namespace]
	if !ok {
		h.retries[namespace] = sum
		return nil
	}

	diff := sum - lastCount

	h.retries[namespace] = sum

	if diff > 0 {
		return fmt.Errorf("backend is unhealthy since retries have occurred in the last minute time frame")
	}

	return nil
}
