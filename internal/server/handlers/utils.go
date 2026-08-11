// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/httputil"
	"google.golang.org/protobuf/proto"
)

// WriteHTTPError writes a JSON error response.
func WriteHTTPError(w http.ResponseWriter, statusCode int, message string) {
	if message == "" {
		message = http.StatusText(statusCode)
	}
	httputil.WriteJSONError(w, statusCode, message, "")
}

// WriteJSON writes v as JSON with Content-Type application/json.
func WriteJSON(w http.ResponseWriter, statusCode int, v any) {
	w.Header().Set("Content-Type", "application/json")
	data, err := json.Marshal(v)
	if err != nil {
		WriteHTTPError(w, http.StatusInternalServerError, "failed to encode response")
		return
	}
	w.WriteHeader(statusCode)
	_, _ = w.Write(data)
}

// MaxRequestBodySize is the default limit for DecodeRequestBody (1MB) to prevent large-body DoS.
const MaxRequestBodySize = 1024 * 1024

// DecodeRequestBody reads and unmarshals JSON or protobuf from the request body.
// Body size is limited to MaxRequestBodySize (1MB) to prevent DoS.
func DecodeRequestBody(r *http.Request, dst any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBodySize))
	if err != nil {
		return fmt.Errorf("read request body: %w", err)
	}
	if len(body) == 0 {
		return errors.New("request body is empty")
	}
	if msg, ok := dst.(proto.Message); ok {
		if err := protojsonUnmarshalOptions.Unmarshal(body, msg); err == nil {
			return nil
		}
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return errors.New("invalid json")
	}
	return nil
}

// Pagination bounds. Both values come straight off the query string, so both
// need a ceiling: pageSize is what a caller can turn into one enormous result
// set, and page is what they can turn into an enormous OFFSET.
const (
	maxPageNumber int32 = 1_000_000
	maxPageSize   int32 = 1_000
)

// ParsePagination extracts page, pageSize, and search from query params.
//
// Zero means "unset" and leaves the default to the caller.
func ParsePagination(r *http.Request) (page, pageSize int32, search string) {
	q := r.URL.Query()
	search = q.Get("search")
	page = boundedInt32(q.Get("page"), maxPageNumber)
	// Support both snake_case and camelCase for frontend compatibility
	pageSizeStr := q.Get("pageSize")
	if pageSizeStr == "" {
		pageSizeStr = q.Get("page_size")
	}
	pageSize = boundedInt32(pageSizeStr, maxPageSize)
	return page, pageSize, search
}

// boundedInt32 parses s as a non-negative int32 no larger than max.
//
// strconv.Atoi followed by an int32 conversion was silently wrong on a 64-bit
// build: Atoi returns an int, so "4294967297" parsed fine and the conversion
// truncated it to 1 — a caller could pick a page by overflowing into it, and a
// negative value sailed through as a negative page. ParseInt with a bitSize of
// 32 rejects the overflow at parse time instead of wrapping.
//
// Anything unparseable, negative or overflowing returns 0, which callers read
// as "unset" and replace with their own default. Values above max are clamped
// rather than rejected, so an over-eager page size degrades to the ceiling
// instead of failing the request.
func boundedInt32(s string, max int32) int32 {
	if s == "" {
		return 0
	}
	v, err := strconv.ParseInt(s, 10, 32)
	if err != nil || v < 0 {
		return 0
	}
	if v > int64(max) {
		return max
	}
	return int32(v)
}

// ParseRouteFilters extracts type, host, path, status from query params.
func ParseRouteFilters(r *http.Request) *config.RouteFilter {
	q := r.URL.Query()
	f := &config.RouteFilter{
		Type:   q.Get("type"),
		Host:   q.Get("host"),
		Path:   q.Get("path"),
		Status: q.Get("status"),
	}
	if f.Type == "" && f.Host == "" && f.Path == "" && f.Status == "" {
		return nil
	}
	return f
}

// SetSSEHeaders sets the required headers for Server-Sent Events (SSE).
// It sets standard SSE headers and security/performance best practices.
// It DOES NOT set Access-Control-Allow-Origin, as this should be handled by middleware.
func SetSSEHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Prevent browsers from MIME-sniffing the response away from text/event-stream
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Disable buffering in Nginx/other proxies for SSE
	w.Header().Set("X-Accel-Buffering", "no")
}
