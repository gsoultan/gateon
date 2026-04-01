package middleware

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/improbable-eng/grpc-web/go/grpcweb"
)

// grpcWebTrailerFlag is the gRPC frame flag indicating a trailer frame.
const grpcWebTrailerFlag byte = 0x80

// GRPCWeb returns a middleware that converts gRPC-Web requests to standard gRPC requests
// and translates responses back to gRPC-Web format. This allows backends that only support
// standard gRPC (over HTTP/2) to handle requests from web browsers.
//
// Request side: translates Content-Type from application/grpc-web to application/grpc,
// base64-decodes body for grpc-web-text, and upgrades protocol version.
//
// Response side: translates Content-Type back to application/grpc-web, and appends
// HTTP trailers as a gRPC trailer frame in the response body (required because
// HTTP/1.1 browsers cannot read HTTP/2 trailers).
func GRPCWeb() Middleware {
	// We create a wrapper with nil server to use its detection methods.
	// This avoids the type mismatch with http.HandlerFunc and allows us to use
	// the library's detection logic while we handle the header mapping for the proxy.
	detector := grpcweb.WrapServer(nil)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !detector.IsGrpcWebRequest(r) && !detector.IsAcceptableGrpcCorsRequest(r) {
				next.ServeHTTP(w, r)
				return
			}

			contentType := r.Header.Get("Content-Type")
			isTextFormat := strings.HasPrefix(contentType, "application/grpc-web-text")

			// Determine the original grpc-web content type for the response
			originalWebCT := "application/grpc-web"
			if isTextFormat {
				originalWebCT = "application/grpc-web-text"
			}
			// Preserve any suffix (e.g. +proto)
			if idx := strings.IndexByte(contentType, '+'); idx >= 0 {
				originalWebCT += contentType[idx:]
			}

			// Handle base64 decoding for text-based gRPC-Web requests
			if isTextFormat {
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

			gwrw := &grpcWebResponseWriter{
				ResponseWriter: w,
				isTextFormat:   isTextFormat,
				originalWebCT:  originalWebCT,
			}
			next.ServeHTTP(gwrw, r)
			gwrw.finalize()
		})
	}
}

// grpcWebResponseWriter wraps an http.ResponseWriter to translate gRPC responses
// back to gRPC-Web format. It rewrites the Content-Type header and appends
// HTTP trailers as a gRPC trailer frame in the response body.
type grpcWebResponseWriter struct {
	http.ResponseWriter
	isTextFormat  bool
	originalWebCT string
	wroteHeader   bool
	// b64Writer is used only for grpc-web-text to base64-encode the response.
	b64Writer io.WriteCloser
	finalized bool
}

// WriteHeader translates the Content-Type from application/grpc to the original
// gRPC-Web content type before writing the response header.
func (w *grpcWebResponseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true

	h := w.ResponseWriter.Header()

	// Translate Content-Type back to gRPC-Web
	ct := h.Get("Content-Type")
	if strings.HasPrefix(ct, "application/grpc") && !strings.HasPrefix(ct, "application/grpc-web") {
		h.Set("Content-Type", w.originalWebCT)
	}

	// Remove Content-Length since we will append trailer frames
	h.Del("Content-Length")

	// Announce trailers in the Trailer header so the client knows to expect them
	h.Del("Trailer")

	w.ResponseWriter.WriteHeader(code)
}

// Write ensures headers are sent and writes response data. For grpc-web-text
// format, the data is base64-encoded.
func (w *grpcWebResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.isTextFormat {
		if w.b64Writer == nil {
			w.b64Writer = base64.NewEncoder(base64.StdEncoding, w.ResponseWriter)
		}
		return w.b64Writer.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

// Flush flushes buffered data to the client.
func (w *grpcWebResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements the http.Hijacker interface.
func (w *grpcWebResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// finalize appends HTTP trailers as a gRPC trailer frame to the response body.
// In gRPC-Web, trailers are sent as a length-prefixed frame with flag 0x80.
func (w *grpcWebResponseWriter) finalize() {
	if w.finalized {
		return
	}
	w.finalized = true

	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	// Collect trailers from the underlying ResponseWriter
	trailers := w.ResponseWriter.Header()
	var buf bytes.Buffer
	for key, vals := range trailers {
		// HTTP trailers set via Header().Set() after WriteHeader are available
		// via the Trailers() method or via the "Trailer" prefix convention.
		// httputil.ReverseProxy copies backend trailers to the response using
		// the "Trailer:" prefix convention in Header map keys.
		lk := strings.ToLower(key)
		if !isGRPCTrailer(lk) {
			continue
		}
		for _, v := range vals {
			buf.WriteString(key)
			buf.WriteString(": ")
			buf.WriteString(v)
			buf.WriteString("\r\n")
		}
	}

	// Also check for trailers set with the http.TrailerPrefix convention
	for key, vals := range trailers {
		if !strings.HasPrefix(key, http.TrailerPrefix) {
			continue
		}
		realKey := strings.TrimPrefix(key, http.TrailerPrefix)
		for _, v := range vals {
			buf.WriteString(realKey)
			buf.WriteString(": ")
			buf.WriteString(v)
			buf.WriteString("\r\n")
		}
	}

	trailerData := buf.Bytes()
	if len(trailerData) == 0 {
		// If no trailers found, write an empty trailer frame
		// so the client knows the stream is complete
		trailerData = []byte{}
	}

	// Write gRPC trailer frame: flag(1) + length(4) + data
	frame := make([]byte, 5+len(trailerData))
	frame[0] = grpcWebTrailerFlag
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(trailerData)))
	copy(frame[5:], trailerData)

	if w.isTextFormat && w.b64Writer != nil {
		_, _ = w.b64Writer.Write(frame)
		_ = w.b64Writer.Close()
	} else if w.isTextFormat {
		enc := base64.NewEncoder(base64.StdEncoding, w.ResponseWriter)
		_, _ = enc.Write(frame)
		_ = enc.Close()
	} else {
		_, _ = w.ResponseWriter.Write(frame)
	}

	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// isGRPCTrailer returns true if the header key is a gRPC trailer.
func isGRPCTrailer(lowerKey string) bool {
	switch lowerKey {
	case "grpc-status", "grpc-message", "grpc-status-details-bin":
		return true
	}
	return false
}
