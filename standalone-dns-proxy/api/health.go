// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/standalone-dns-proxy/server/restapi/sdp"
)

type isHealthyFunc func() bool

// HealthHandlerCell provides the health check handler for the standalone DNS proxy API.
// It is used for the liveness/readiness probe.
func HealthHandlerCell(
	isHealthy isHealthyFunc,
) cell.Cell {
	return cell.Module(
		"health-handler",
		"Standalone DNS proxy health HTTP handler",

		cell.Provide(func(logger *slog.Logger) sdp.GetHealthzHandler {
			return &healthHandler{
				isHealthy: isHealthy,
				logger:    logger,
			}
		}),
	)
}

type healthHandler struct {
	isHealthy isHealthyFunc
	logger    *slog.Logger
}

func (h *healthHandler) Handle(params sdp.GetHealthzParams) middleware.Responder {
	if h.isHealthy() {
		return sdp.NewGetHealthzOK().WithPayload("ok")
	}
	h.logger.Warn("Health check failed")
	return sdp.NewGetHealthzInternalServerError().WithPayload("not ok")
}
