package handlers

import (
	"encoding/json"
	"net/http"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func registerAIHandlers(mux *http.ServeMux, d *Deps) {
	mux.HandleFunc("POST /AnalyzeConfig", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req gateonv1.AnalyzeConfigRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			// Allow empty body
		}

		resp, err := d.AIService.AnalyzeConfig(r.Context(), &req)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		// Ensure Insights is never nil for the frontend
		if resp.Insights == nil {
			resp.Insights = []*gateonv1.AIInsight{}
		}

		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
}
