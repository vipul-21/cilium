// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/cilium/hive/cell"
	"github.com/go-openapi/loads"
	"github.com/go-openapi/runtime"

	sdpApi "github.com/cilium/cilium/api/v1/standalone-dns-proxy/server"
	"github.com/cilium/cilium/api/v1/standalone-dns-proxy/server/restapi"
	"github.com/cilium/cilium/api/v1/standalone-dns-proxy/server/restapi/sdp"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// params contains all the dependencies for the api server.
type params struct {
	cell.In

	Cfg Config

	HealthHandler sdp.GetHealthzHandler

	Logger     *slog.Logger
	Lifecycle  cell.Lifecycle
	Shutdowner hive.Shutdowner
}

type Server struct {
	*sdpApi.Server

	logger     *slog.Logger
	shutdowner hive.Shutdowner

	socketPath string
	listener   net.Listener
	server     *http.Server

	healthHandler sdp.GetHealthzHandler
}

func newServer(
	p params,
) (*Server, error) {
	server := &Server{
		logger:        p.Logger,
		shutdowner:    p.Shutdowner,
		socketPath:    p.Cfg.StandaloneDNSProxyAPISocketPath,
		healthHandler: p.HealthHandler,
	}
	p.Lifecycle.Append(server)

	return server, nil
}

func (s *Server) Start(ctx cell.HookContext) error {
	spec, err := loads.Analyzed(sdpApi.SwaggerJSON, "")
	if err != nil {
		return err
	}

	restAPI := restapi.NewStandaloneDNSProxyAPI(spec)
	restAPI.Logger = s.logger.Debug
	restAPI.SdpGetHealthzHandler = s.healthHandler

	srv := sdpApi.NewServer(restAPI)
	srv.EnabledListeners = []string{"http"}
	srv.ConfigureAPI()
	s.Server = srv

	mux := http.NewServeMux()

	// Index handler is the handler for Open-API router.
	mux.Handle("/", s.Server.GetHandler())

	// Create a custom handler for /healthz.
	mux.HandleFunc("/healthz", func(rw http.ResponseWriter, _ *http.Request) {
		resp := s.healthHandler.Handle(sdp.GetHealthzParams{})
		resp.WriteResponse(rw, runtime.TextProducer())
	})

	// Ensure the directory exists
	if err := os.MkdirAll(filepath.Dir(s.socketPath), 0755); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Remove existing socket file if it exists
	if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing socket: %w", err)
	}

	// Create Unix domain socket listener
	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("unable to listen on %s: %w", s.socketPath, err)
	}
	s.listener = ln

	// Set socket permissions to allow local access
	if err := os.Chmod(s.socketPath, 0660); err != nil {
		ln.Close()
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	s.logger.Info("API server listening on Unix domain socket", logfields.Path, s.socketPath)

	s.server = &http.Server{
		Handler: mux,
	}

	go func() {
		if err := s.server.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("HTTP server stopped with error", logfields.Error, err)
			s.shutdowner.Shutdown()
		}
	}()

	return nil
}

func (s *Server) Stop(ctx cell.HookContext) error {
	if s.server != nil {
		if err := s.server.Shutdown(ctx); err != nil {
			return err
		}
	}

	// Clean up socket file
	if s.socketPath != "" {
		if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
			s.logger.Warn("Failed to remove socket file", logfields.Path, s.socketPath, logfields.Error, err)
		}
	}

	return nil
}
