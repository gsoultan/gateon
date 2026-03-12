package entrypoint

import (
	"context"
	"crypto/tls"
	"net/http"
	"sync"

	"github.com/gateon/gateon/internal/logger"
	"github.com/gateon/gateon/internal/syncutil"
	gtls "github.com/gateon/gateon/internal/tls"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"github.com/rs/cors"
)

// Runner is the strategy interface for starting one kind of entrypoint.
type Runner interface {
	Run(ctx context.Context, ep *gateonv1.EntryPoint, deps *Deps, wg *syncutil.WaitGroup)
}

// ShutdownRegistry collects shutdown functions for graceful exit.
type ShutdownRegistry struct {
	mu    sync.Mutex
	funcs []func(context.Context) error
}

// Register adds a shutdown function (e.g. server.Shutdown).
func (r *ShutdownRegistry) Register(fn func(context.Context) error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.funcs = append(r.funcs, fn)
}

// ShutdownAll runs all registered shutdown functions with the given context.
func (r *ShutdownRegistry) ShutdownAll(ctx context.Context) {
	r.mu.Lock()
	list := make([]func(context.Context) error, len(r.funcs))
	copy(list, r.funcs)
	r.mu.Unlock()
	for _, fn := range list {
		if err := fn(ctx); err != nil {
			logger.L.Debug().Err(err).Msg("shutdown callback error")
		}
	}
}

// Deps holds dependencies needed to run entrypoints.
type Deps struct {
	Port             string
	BaseHandler      http.Handler
	Wrapped          *grpcweb.WrappedGrpcServer
	CORS             *cors.Cors
	TLSConfig       *tls.Config
	TLSManager      *gtls.Manager
	Limiter         interface {
		Handler(keyFunc func(*http.Request) string) func(http.Handler) http.Handler
	}
	ShutdownRegistry *ShutdownRegistry
}

func runnerFor(epType gateonv1.EntryPoint_Type) Runner {
	switch epType {
	case gateonv1.EntryPoint_HTTP, gateonv1.EntryPoint_HTTP2, gateonv1.EntryPoint_GRPC, gateonv1.EntryPoint_HTTP3:
		return &httpRunner{}
	case gateonv1.EntryPoint_TCP:
		return &tcpRunner{}
	case gateonv1.EntryPoint_UDP:
		return &udpRunner{}
	default:
		return nil
	}
}
