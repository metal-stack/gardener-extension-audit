package healthcheck

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var (
	body1 = `{
		"output": {
		  "splunk.0": {
			"retries": 10
		  },
		  "null.1": {
			"retries": 0
		  }
		}
	  } `
	body2 = `{
		"output": {
		  "splunk.0": {
			"retries": 20
		  },
		  "null.1": {
			"retries": 0
		  }
		}
	  } `
)

type RoundTripFunc func(req *http.Request) *http.Response

func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func TestBackendHealthChecker_checkRetries(t *testing.T) {
	h := &BackendHealthChecker{
		httpClient: newFakeClient(http.StatusOK, body1),
		retries:    retryMap{},
		backoff:    map[string]time.Time{},
		seedClient: fake.NewClientBuilder().WithLists(&discoveryv1.EndpointSliceList{
			Items: []discoveryv1.EndpointSlice{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "shoot-a",
						Labels: map[string]string{
							"kubernetes.io/service-name": "audit-webhook-backend",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{"1.2.3.4"},
						},
						{
							Addresses: []string{"1.2.3.5"},
						},
					},
				},
			},
		}).Build(),
	}

	err := h.checkRetries(context.Background(), "shoot-a")
	require.NoError(t, err)

	require.Equal(t, retryMap{
		"shoot-a": {
			"splunk.0": 2 * 10, // two backends with 10 retries
			"null.1":   0,
		},
	}, h.retries)

	err = h.checkRetries(context.Background(), "shoot-a")
	require.NoError(t, err)

	require.Equal(t, retryMap{
		"shoot-a": {
			"splunk.0": 2 * 10, // no changes in retries
			"null.1":   0,
		},
	}, h.retries)

	h.httpClient = newFakeClient(http.StatusOK, body2)

	err = h.checkRetries(context.Background(), "shoot-a")
	require.ErrorContains(t, err, `20 retries (40 in total) have occurred in the last minute time frame for output "splunk.0"`)

	require.Equal(t, retryMap{
		"shoot-a": {
			"splunk.0": 2 * 20,
			"null.1":   0,
		},
	}, h.retries)
}

func newFakeClient(code int, respBody string) *http.Client {
	return &http.Client{Transport: RoundTripFunc(func(req *http.Request) *http.Response {
		return &http.Response{
			StatusCode: code,
			Body:       io.NopCloser(strings.NewReader(respBody)),
		}
	})}
}
