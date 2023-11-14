package healthcheck

import (
	"context"
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
}

func backendHealth() healthcheck.HealthCheck {
	return &BackendHealthChecker{
		httpClient: http.DefaultClient,
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read http body: %w", err)
	}

	return fmt.Errorf("backend is unhealthy since errors or failued have occurred in the last minute time frame: %s", string(body))
}
