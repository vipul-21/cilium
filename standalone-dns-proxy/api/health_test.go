// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/go-openapi/runtime"

	"github.com/cilium/cilium/api/v1/standalone-dns-proxy/server/restapi/sdp"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/safeio"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestHealthHandlerK8sEnabled(t *testing.T) {
	defer testutils.GoleakVerifyNone(t)

	tt := []struct {
		name           string
		isHealthyFunc  func() bool
		expectedStatus int
		expectedBody   string
	}{
		{
			name: "healthy",
			isHealthyFunc: func() bool {
				return true
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "ok",
		},
		{
			name: "unhealthy",
			isHealthyFunc: func() bool {
				return false
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "not ok",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()

			hive := hive.New(

				HealthHandlerCell(
					tc.isHealthyFunc,
				),

				// transform GetHealthzHandler in a http.HandlerFunc to use
				// the http package testing facilities
				cell.Provide(func(h sdp.GetHealthzHandler) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						res := h.Handle(sdp.GetHealthzParams{})
						res.WriteResponse(w, runtime.TextProducer())
					}
				}),

				cell.Invoke(func(hf http.HandlerFunc) {
					req := httptest.NewRequest(http.MethodGet, "http://localhost/healthz", nil)
					hf.ServeHTTP(rr, req)
				}),
			)

			tlog := hivetest.Logger(t)
			if err := hive.Start(tlog, t.Context()); err != nil {
				t.Fatalf("failed to start: %s", err)
			}

			if rr.Result().StatusCode != tc.expectedStatus {
				t.Fatalf("expected http status code %d, got %d", tc.expectedStatus, rr.Result().StatusCode)
			}

			body, err := safeio.ReadAllLimit(rr.Result().Body, safeio.KB)
			if err != nil {
				t.Fatalf("error while reading response body: %s", err)
			}
			rr.Result().Body.Close()

			if string(body) != tc.expectedBody {
				t.Fatalf("expected response body %q, got: %q", tc.expectedBody, string(body))
			}

			if err := hive.Stop(tlog, t.Context()); err != nil {
				t.Fatalf("failed to stop: %s", err)
			}
		})
	}
}
