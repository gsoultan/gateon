package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/gateon/gateon/internal/config"
	"google.golang.org/protobuf/proto"
)

// WriteHTTPError writes a plain text error response.
func WriteHTTPError(w http.ResponseWriter, statusCode int, message string) {
	if message == "" {
		message = http.StatusText(statusCode)
	}
	http.Error(w, message, statusCode)
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

// DecodeRequestBody reads and unmarshals JSON or protobuf from the request body.
func DecodeRequestBody(r *http.Request, dst any) error {
	body, err := io.ReadAll(r.Body)
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

// ParsePagination extracts page, pageSize, and search from query params.
func ParsePagination(r *http.Request) (page, pageSize int32, search string) {
	q := r.URL.Query()
	search = q.Get("search")
	if pageStr := q.Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil {
			page = int32(p)
		}
	}
	if pageSizeStr := q.Get("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil {
			pageSize = int32(ps)
		}
	}
	return page, pageSize, search
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
