package handlers

import (
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var (
	protojsonOptions = protojson.MarshalOptions{
		EmitUnpopulated: true,
		UseProtoNames:   true,
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
