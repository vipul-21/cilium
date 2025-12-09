// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"syscall"

	"github.com/cilium/hive/cell"
	"github.com/go-openapi/loads"
	"github.com/go-openapi/runtime"
	"golang.org/x/sys/unix"

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

	address  string
	httpSrvs []httpServer

	healthHandler sdp.GetHealthzHandler
}

type httpServer struct {
	address  string
	listener net.Listener
	server   *http.Server
}

func newServer(
	p params,
) (*Server, error) {
	server := &Server{
		logger:        p.Logger,
		shutdowner:    p.Shutdowner,
		address:       p.Cfg.StandaloneDNSProxyAPIServeAddr,
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

	if s.address == "" {
		s.httpSrvs = make([]httpServer, 2)
		s.httpSrvs[0].address = "127.0.0.1:0"
		s.httpSrvs[1].address = "[::1]:0"
	} else {
		s.httpSrvs = make([]httpServer, 1)
		s.httpSrvs[0].address = s.address
	}

	var errs []error
	for i := range s.httpSrvs {
		lc := net.ListenConfig{Control: setsockoptReuseAddrAndPort}
		ln, err := lc.Listen(ctx, "tcp", s.httpSrvs[i].address)
		if err != nil {
			errs = append(errs, fmt.Errorf("unable to listen on %s: %w", s.httpSrvs[i].address, err))
			continue
		}
		s.httpSrvs[i].listener = ln

		s.logger.Debug("Listening on", logfields.Address, ln.Addr().String())

		s.httpSrvs[i].server = &http.Server{
			Addr:    s.httpSrvs[i].address,
			Handler: mux,
		}
	}

	// if no server can be started, we stop the cell
	if (len(s.httpSrvs) == 1 && s.httpSrvs[0].server == nil) ||
		(len(s.httpSrvs) == 2 && s.httpSrvs[0].server == nil && s.httpSrvs[1].server == nil) {
		s.shutdowner.Shutdown()
		return errors.Join(errs...)
	}

	// otherwise just log any possible error and continue
	for _, err := range errs {
		s.logger.Error("Failed to start server", logfields.Error, err)
	}

	for _, srv := range s.httpSrvs {
		if srv.server == nil {
			continue
		}
		go func(srv httpServer) {
			if err := srv.server.Serve(srv.listener); !errors.Is(err, http.ErrServerClosed) {
				s.logger.Error("HTTP server stopped with error", logfields.Error, err)
				s.shutdowner.Shutdown()
			}
		}(srv)
	}

	return nil
}

func (s *Server) Stop(ctx cell.HookContext) error {
	for _, srv := range s.httpSrvs {
		if srv.server == nil {
			continue
		}
		if err := srv.server.Shutdown(ctx); err != nil {
			return err
		}
	}
	return nil
}

// setsockoptReuseAddrAndPort sets the SO_REUSEADDR and SO_REUSEPORT socket options on c's
// underlying socket in order to improve the chance to re-bind to the same address and port
// upon restart.
func setsockoptReuseAddrAndPort(network, address string, c syscall.RawConn) error {
	var soerr error
	if err := c.Control(func(su uintptr) {
		s := int(su)
		// Allow reuse of recently-used addresses. This socket option is
		// set by default on listeners in Go's net package, see
		// net setDefaultListenerSockopts
		if err := unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			soerr = fmt.Errorf("failed to setsockopt(SO_REUSEADDR): %w", err)
			return
		}

		// Allow reuse of recently-used ports. This gives the standalone dnsproxy a
		// better chance to re-bind upon restarts.
		soerr = unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	}); err != nil {
		return err
	}
	return soerr
}
