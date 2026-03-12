package middleware

import (
	"encoding/base64"
	"io"
	"net/http"
	"strings"

	"github.com/improbable-eng/grpc-web/go/grpcweb"
)

// GRPCWeb returns a middleware that converts gRPC-Web requests to standard gRPC requests.
// This allows backends that only support standard gRPC (over HTTP/2) to handle requests
// coming from web browsers.
func GRPCWeb() Middleware {
	// We create a wrapper with nil server to use its detection methods.
	// This avoids the type mismatch with http.HandlerFunc and allows us to use
	// the library's detection logic while we handle the header mapping for the proxy.
	detector := grpcweb.WrapServer(nil)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if detector.IsGrpcWebRequest(r) || detector.IsAcceptableGrpcCorsRequest(r) {
				contentType := r.Header.Get("Content-Type")

				// Handle base64 decoding for text-based gRPC-Web requests
				if strings.HasPrefix(contentType, "application/grpc-web-text") {
					r.Body = io.NopCloser(base64.NewDecoder(base64.StdEncoding, r.Body))
				}

				if strings.HasPrefix(contentType, "application/grpc-web") {
					// Translate gRPC-Web content type to standard gRPC
					newType := contentType
					newType = strings.Replace(newType, "application/grpc-web-text", "application/grpc", 1)
					newType = strings.Replace(newType, "application/grpc-web", "application/grpc", 1)
					r.Header.Set("Content-Type", newType)
				}

				// gRPC requires HTTP/2. We upgrade the request metadata
				// so the proxy knows to treat it as a gRPC call.
				if r.ProtoMajor < 2 {
					r.ProtoMajor = 2
					r.ProtoMinor = 0
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
