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
		"input": {
		  "http.0": {
			"records": 3586,
			"bytes": 2007828608
		  },
		  "storage_backlog.1": {
			"records": 0,
			"bytes": 0
		  }
		},
		"filter": {},
		"output": {
		  "splunk.0": {
			"proc_records": 0,
			"proc_bytes": 0,
			"errors": 0,
			"retries": 9226,
			"retries_failed": 0,
			"dropped_records": 0,
			"retried_records": 13026
		  },
		  "null.1": {
			"proc_records": 182,
			"proc_bytes": 91946175,
			"errors": 0,
			"retries": 0,
			"retries_failed": 0,
			"dropped_records": 0,
			"retried_records": 0
		  }
		}
	  } `

	body2 = `{
		"input": {
		  "http.0": {
			"records": 3586,
			"bytes": 2007828608
		  },
		  "storage_backlog.1": {
			"records": 0,
			"bytes": 0
		  }
		},
		"filter": {},
		"output": {
		  "splunk.0": {
			"proc_records": 0,
			"proc_bytes": 0,
			"errors": 0,
			"retries": 9230,
			"retries_failed": 0,
			"dropped_records": 0,
			"retried_records": 13026
		  },
		  "null.1": {
			"proc_records": 182,
			"proc_bytes": 91946175,
			"errors": 0,
			"retries": 0,
			"retries_failed": 0,
			"dropped_records": 0,
			"retried_records": 0
		  }
		}
	  }`
)

type RoundTripFunc func(req *http.Request) *http.Response

func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func TestBackendHealthChecker_checkRetries(t *testing.T) {
	h := &BackendHealthChecker{
		httpClient: newFakeClient(http.StatusOK, body1),
		retries:    map[string]map[string]int{},
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
					},
				},
			},
		}).Build(),
	}

	err := h.checkRetries(context.Background(), "shoot-a")
	require.NoError(t, err)

	require.Equal(t, map[string]map[string]int{
		"shoot-a": {
			"splunk.0": 9226,
			"null.1":   0,
		},
	}, h.retries)

	err = h.checkRetries(context.Background(), "shoot-a")
	require.NoError(t, err)

	require.Equal(t, map[string]map[string]int{
		"shoot-a": {
			"splunk.0": 9226,
			"null.1":   0,
		},
	}, h.retries)

	h.httpClient = newFakeClient(http.StatusOK, body2)

	err = h.checkRetries(context.Background(), "shoot-a")
	require.ErrorContains(t, err, `4 retries (9230 in total) have occurred in the last minute time frame for output "splunk.0"`)

	require.Equal(t, map[string]map[string]int{
		"shoot-a": {
			"splunk.0": 9230,
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
