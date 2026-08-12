// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"bytes"
	"io"
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// maxProtoRequestBody bounds a management-API request body. These are small
// control messages; without a cap, ReadAll would size the buffer from whatever
// the client chose to send.
const maxProtoRequestBody = 1 << 20 // 1 MiB

// DecodeProtoRequest fills msg from the request body, and reports whether the
// caller should continue. It writes the error response itself when it does not.
//
// protojson, not encoding/json. These are protobuf messages, and encoding/json
// matches incoming keys against the generated `json:"anomaly_type"` tag. The
// dashboard sends protojson's lowerCamel spelling, "anomalyType", which does
// not match — not even case-insensitively, because an underscore is not a
// capital T. The field silently stayed empty rather than erroring, which is the
// whole problem: ApplyRecommendation then switched on "" and answered
// "Automatic resolution for '' is not implemented yet" for every anomaly type,
// so the dashboard's "Apply automatic fix" never once did anything.
//
// protojson accepts both spellings, and it is what the rest of the API already
// uses. An empty body stays a zero-value request rather than an error, matching
// the previous behaviour for callers that send no payload.
func DecodeProtoRequest(w http.ResponseWriter, r *http.Request, msg proto.Message) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxProtoRequestBody))
	if err != nil {
		WriteHTTPError(w, http.StatusBadRequest, "could not read request body")
		return false
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return true
	}
	if err := protojsonUnmarshalOptions.Unmarshal(body, msg); err != nil {
		WriteHTTPError(w, http.StatusBadRequest, err.Error())
		return false
	}
	return true
}

var (
	protojsonOptions = protojson.MarshalOptions{
		EmitUnpopulated: true,
		UseProtoNames:   false,
		UseEnumNumbers:  true,
	}
	protojsonUnmarshalOptions = protojson.UnmarshalOptions{
		DiscardUnknown: true,
	}
)

// ProtojsonOptions returns the marshal options for JSON proto responses.
func ProtojsonOptions() protojson.MarshalOptions { return protojsonOptions }

// ProtojsonUnmarshalOptions returns the unmarshal options for JSON proto requests.
func ProtojsonUnmarshalOptions() protojson.UnmarshalOptions { return protojsonUnmarshalOptions }

// WriteProtoResponse writes a JSON-serialized protobuf message.
func WriteProtoResponse(w http.ResponseWriter, statusCode int, msg proto.Message) {
	w.Header().Set("Content-Type", "application/json")
	data, err := protojsonOptions.Marshal(msg)
	if err != nil {
		WriteHTTPError(w, http.StatusInternalServerError, "failed to encode response")
		return
	}
	w.WriteHeader(statusCode)
	_, _ = w.Write(data)
}
