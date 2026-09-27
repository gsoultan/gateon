// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"errors"
	"io/fs"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/telemetry/tracearchive"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func registerTracesHandlers(mux *http.ServeMux, apiService *api.ApiService) {
	mux.HandleFunc("GET /v1/traces", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceDiagnostics) {
			return
		}
		// Bounded; see the diagnostics handlers for why the conversion, not the
		// input, is what produced a negative.
		limit := boundedInt32(r.URL.Query().Get("limit"), maxPageSize)
		if limit <= 0 {
			limit = 100
		}
		summary := r.URL.Query().Get("summary") == "true"

		resp, err := apiService.ListTraces(r.Context(), &gateonv1.ListTracesRequest{
			Limit:   limit,
			Summary: summary,
		})
		if err != nil {
			// The store's error names the backing engine, its query and often a
			// filesystem path. It goes to the operator's log, not into a
			// response body rendered in a dashboard that also renders hostile
			// traffic.
			logger.L.LogError("failed to list traces", "error", err)
			http.Error(w, "Could not load traces", http.StatusInternalServerError)
			return
		}

		WriteProtoResponse(w, http.StatusOK, resp)
	})

	mux.HandleFunc("GET /v1/traces/detail", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceDiagnostics) {
			return
		}
		id := r.URL.Query().Get("id")
		ts := r.URL.Query().Get("timestamp")

		if id == "" || ts == "" {
			http.Error(w, "missing id or timestamp", http.StatusBadRequest)
			return
		}

		resp, err := apiService.GetTrace(r.Context(), &gateonv1.GetTraceRequest{
			Id:        id,
			Timestamp: ts,
		})
		if err != nil {
			logger.L.LogError("failed to load trace", "error", err, "trace_id", id)
			http.Error(w, "Trace not found", http.StatusNotFound)
			return
		}

		WriteProtoResponse(w, http.StatusOK, resp)
	})

	// An archived hour is a file, streamed from disk: a REST route rather than
	// an RPC because a unary response would hold the whole hour in memory. The
	// name is the only input, and only an exact segment name is accepted.
	mux.HandleFunc("GET /v1/traces/archives/{name}", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceDiagnostics) {
			return
		}
		serveTraceArchive(w, r, apiService)
	})
}

// downloadWriteTimeout is how long one write of a download may take. The
// management server sets no write timeout -- the event stream beside this
// route has to be able to stay open -- so without one a client that stops
// reading would hold its download slot, and the file, for as long as it liked.
const downloadWriteTimeout = 30 * time.Second

// serveTraceArchive sends an archived hour as stored, zstd-compressed, or with
// ?format=ndjson decompressed. Either way it is an attachment the browser is
// told not to sniff and not to keep: the file is traffic from strangers, and
// rendered inline as HTML it would run whatever they sent.
func serveTraceArchive(w http.ResponseWriter, r *http.Request, apiService *api.ApiService) {
	dl, err := apiService.OpenTraceArchive(r.PathValue("name"))
	if err != nil {
		traceArchiveOpenError(w, err)
		return
	}
	defer dl.Close()
	rc := http.NewResponseController(w)
	defer func() { _ = rc.SetWriteDeadline(time.Time{}) }()
	dw := deadlineWriter{ResponseWriter: w, rc: rc}
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "private, no-store")
	if r.URL.Query().Get("format") != "ndjson" {
		h.Set("Content-Type", "application/zstd")
		h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": dl.Name}))
		http.ServeContent(dw, r, dl.Name, dl.ModTime, dl.Content())
		return
	}
	h.Set("Content-Type", "application/x-ndjson")
	h.Set("Content-Disposition", mime.FormatMediaType("attachment",
		map[string]string{"filename": strings.TrimSuffix(dl.Name, ".zst")}))
	written, err := dl.WriteNDJSON(r.Context(), dw)
	if err == nil {
		return
	}
	logger.L.LogWarn("trace archive: download ended early", "error", err)
	if written == 0 {
		http.Error(w, "Could not read the archive file", http.StatusInternalServerError)
		return
	}
	// Part of the file has gone out as a chunked body. Returning now would end
	// it cleanly, and the client would keep a short file that looks whole.
	// Aborting drops the connection, which the client sees as the failure it is.
	panic(http.ErrAbortHandler)
}

func traceArchiveOpenError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, tracearchive.ErrNotASegment):
		http.Error(w, "Not a trace archive file name", http.StatusBadRequest)
	case errors.Is(err, fs.ErrNotExist):
		http.Error(w, "No archive for that hour", http.StatusNotFound)
	case errors.Is(err, tracearchive.ErrBusy):
		w.Header().Set("Retry-After", "30")
		http.Error(w, "Too many archive downloads at once; try again shortly", http.StatusServiceUnavailable)
	default:
		logger.L.LogError("trace archive: could not open a file for download", "error", err)
		http.Error(w, "Could not read the archive file", http.StatusInternalServerError)
	}
}

// deadlineWriter gives each write of a download a deadline of its own, so the
// download can take as long as it needs while the client keeps reading.
type deadlineWriter struct {
	http.ResponseWriter
	rc *http.ResponseController
}

func (d deadlineWriter) Write(p []byte) (int, error) {
	_ = d.rc.SetWriteDeadline(time.Now().Add(downloadWriteTimeout))
	return d.ResponseWriter.Write(p)
}
