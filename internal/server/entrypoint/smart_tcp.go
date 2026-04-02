package entrypoint

import (
	"cmp"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// peekedConn wraps a connection and returns buffered data first.
type peekedConn struct {
	net.Conn
	r io.Reader
}

func newPeekedConn(conn net.Conn, peeked []byte) *peekedConn {
	r := io.MultiReader(
		&bufFix{b: peeked},
		conn,
	)
	return &peekedConn{Conn: conn, r: r}
}

func (p *peekedConn) Read(b []byte) (int, error) {
	return p.r.Read(b)
}

type bufFix struct {
	b []byte
	i int
}

func (b *bufFix) Read(p []byte) (int, error) {
	if b.i >= len(b.b) {
		return 0, io.EOF
	}
	n := copy(p, b.b[b.i:])
	b.i += n
	return n, nil
}

// oneShotListener returns a single connection on Accept, then blocks.
type oneShotListener struct {
	conn net.Conn
	done chan struct{}
}

func newOneShotListener(conn net.Conn) *oneShotListener {
	return &oneShotListener{conn: conn, done: make(chan struct{})}
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		// Block forever after first Accept
		select {}
	default:
		close(l.done)
		return l.conn, nil
	}
}

func (l *oneShotListener) Close() error {
	return nil
}

func (l *oneShotListener) Addr() net.Addr {
	if l.conn != nil {
		return l.conn.LocalAddr()
	}
	return nil
}

// buildPlainHTTPHandler builds the HTTP handler chain for an entrypoint (plaintext).
func buildPlainHTTPHandler(ep *gateonv1.EntryPoint, deps *Deps) http.Handler {
	var epHandler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isGRPC := (r.ProtoMajor == 2 || r.ProtoMajor == 3) && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc")
		isGRPCWeb := deps.Wrapped.IsGrpcWebRequest(r) || deps.Wrapped.IsAcceptableGrpcCorsRequest(r) || deps.Wrapped.IsGrpcWebSocketRequest(r)
		if isGRPC || isGRPCWeb {
			deps.Wrapped.ServeHTTP(w, r)
			return
		}
		deps.BaseHandler.ServeHTTP(w, r)
	})
	isMgmt := IsManagementAddress(ep.Address, deps)
	epLabel := cmp.Or(ep.Name, ep.Id)
	epHandler = injectEntryPointID(ep.Id, epLabel, isMgmt, epHandler)
	chain := []middleware.Middleware{
		middleware.RequestID(),
		middleware.Recovery(),
		middleware.Metrics("gateon-" + epLabel),
	}
	if ep.AccessLogEnabled {
		chain = append(chain, middleware.AccessLog("gateon-"+epLabel))
	}
	return middleware.Chain(chain...)(deps.CORS.Handler(deps.Limiter.Handler(middleware.PerIP)(epHandler)))
}

// serveConnAsHTTP serves a single connection as HTTP (plaintext).
// peeked contains the bytes already read during inspection; they are replayed first.
func serveConnAsHTTP(conn net.Conn, peeked []byte, ep *gateonv1.EntryPoint, deps *Deps) {
	handler := deps.TLSManager.HTTPChallengeHandler(buildPlainHTTPHandler(ep, deps))
	readTimeout := time.Duration(ep.ReadTimeoutMs) * time.Millisecond
	writeTimeout := time.Duration(ep.WriteTimeoutMs) * time.Millisecond
	if readTimeout == 0 {
		readTimeout = 15 * time.Second
	}
	if writeTimeout == 0 {
		writeTimeout = 15 * time.Second
	}
	server := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		Handler:           handler,
	}
	listener := newOneShotListener(newPeekedConn(conn, peeked))
	_ = server.Serve(listener)
}
