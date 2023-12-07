package healthcheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gardener/gardener/extensions/pkg/controller/healthcheck"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/types"
)

// retryMap contains outputRetries using the namespace as a key
type retryMap map[string]outputRetries

// outputRetries contains retries per output plugin
type outputRetries map[string]int

type BackendHealthChecker struct {
	logger     logr.Logger
	httpClient *http.Client
	retries    retryMap
	mutex      sync.Mutex
	backoff    map[string]time.Time
	syncPeriod time.Duration
	seedClient client.Client
}

func backendHealth(syncPeriod time.Duration) healthcheck.HealthCheck {
	return &BackendHealthChecker{
		httpClient: http.DefaultClient,
		retries:    retryMap{},
		backoff:    map[string]time.Time{},
		syncPeriod: syncPeriod,
	}
}

// InjectSeedClient injects the seed client
func (h *BackendHealthChecker) InjectSeedClient(seedClient client.Client) {
	h.seedClient = seedClient
}

func (h *BackendHealthChecker) SetLoggerSuffix(provider, extension string) {
	h.logger = h.logger.WithName(fmt.Sprintf("%s-%s-healthcheck-backend", provider, extension))
}

func (h *BackendHealthChecker) DeepCopy() healthcheck.HealthCheck {
	return &BackendHealthChecker{
		logger:     h.logger,
		httpClient: h.httpClient,
		retries:    h.retries,
		mutex:      sync.Mutex{},
		backoff:    h.backoff,
		syncPeriod: h.syncPeriod,
		seedClient: h.seedClient,
	}
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

	endpointSliceList := &discoveryv1.EndpointSliceList{}
	err := h.seedClient.List(ctx, endpointSliceList, client.MatchingLabels{
		"kubernetes.io/service-name": "audit-webhook-backend",
	}, client.InNamespace(namespace))
	if err != nil {
		return err
	}

	if len(endpointSliceList.Items) == 0 {
		return fmt.Errorf("no endpoints found for audit backend service")
	}

	h.mutex.Lock()
	defer h.mutex.Unlock()

	defer func() {
		h.backoff[namespace] = time.Now()
	}()

	lastCheck, ok := h.backoff[namespace]
	if ok {
		if time.Since(lastCheck) < h.syncPeriod-1*time.Second {
			// we only need a check once every sync period, otherwise retries might be too low such that health flickers
			return nil
		}
	}

	type metrics struct {
		Output map[string]struct {
			Retries        int `json:"retries"`
			RetriedRecords int `json:"retried_records"`
		} `json:"output"`
	}

	var (
		ms        []metrics
		addresses []string
	)

	for _, endpoints := range endpointSliceList.Items {
		for _, endpoint := range endpoints.Endpoints {
			addresses = append(addresses, endpoint.Addresses...)
		}
	}

	for _, address := range addresses {
		url := fmt.Sprintf("http://%s:2020/api/v1/metrics", address)

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

		ms = append(ms, m)
	}

	plugins, ok := h.retries[namespace]
	if !ok {
		plugins = outputRetries{}
	}

	var (
		errs []error
		sums = outputRetries{}
	)

	for _, m := range ms {
		m := m

		for name, output := range m.Output {
			output := output

			sums[name] += output.Retries
		}
	}

	for name, sum := range sums {
		lastCount, ok := plugins[name]
		if !ok {
			plugins[name] = sum
			continue
		}

		diff := sum - lastCount

		plugins[name] = sum

		if diff > 0 {
			errs = append(errs, fmt.Errorf("%d retries (%d in total) have occurred in the last minute time frame for output %q", diff, sum, name))
		}
	}

	h.retries[namespace] = plugins

	return errors.Join(errs...)
}
