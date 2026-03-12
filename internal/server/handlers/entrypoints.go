package handlers

import (
	"net/http"
	"strings"

	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
	"github.com/google/uuid"
)

func registerEntryPointHandlers(mux *http.ServeMux, d *Deps) {
	mux.HandleFunc("GET /v1/entrypoints", func(w http.ResponseWriter, r *http.Request) {
		page, pageSize, search := ParsePagination(r)
		eps, total := d.EpReg.ListPaginated(page, pageSize, search)
		WriteProtoResponse(w, http.StatusOK, &gateonv1.ListEntryPointsResponse{
			EntryPoints: eps, TotalCount: total, Page: page, PageSize: pageSize,
		})
	})
	mux.HandleFunc("PUT /v1/entrypoints", func(w http.ResponseWriter, r *http.Request) {
		var ep gateonv1.EntryPoint
		if err := DecodeRequestBody(r, &ep); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		if ep.Address == "" {
			WriteHTTPError(w, http.StatusBadRequest, "missing address")
			return
		}
		if ep.Id == "" {
			ep.Id = uuid.NewString()
		}
		inferEntryPointType(&ep)
		if err := d.EpReg.Update(&ep); err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to save entrypoint")
			return
		}
		WriteProtoResponse(w, http.StatusOK, &ep)
	})
	mux.HandleFunc("DELETE /v1/entrypoints/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			WriteHTTPError(w, http.StatusBadRequest, "missing entrypoint id")
			return
		}
		if err := d.EpReg.Delete(id); err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to delete entrypoint")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func inferEntryPointType(ep *gateonv1.EntryPoint) {
	hasTCP, hasUDP := false, false
	for _, p := range ep.Protocols {
		if p == gateonv1.EntryPoint_TCP_PROTO {
			hasTCP = true
		}
		if p == gateonv1.EntryPoint_UDP_PROTO {
			hasUDP = true
		}
	}
	if !hasTCP && !hasUDP {
		hasTCP = true
		ep.Protocols = append(ep.Protocols, gateonv1.EntryPoint_TCP_PROTO)
	}
	addr := ep.Address
	isHTTPPort := strings.HasSuffix(addr, ":80") || strings.HasSuffix(addr, ":443") ||
		strings.HasSuffix(addr, ":8080") || strings.HasSuffix(addr, ":8443") || strings.Contains(addr, "http")
	tlsEnabled := ep.Tls != nil && ep.Tls.Enabled
	if hasTCP {
		if tlsEnabled || isHTTPPort {
			ep.Type = gateonv1.EntryPoint_HTTP
		} else {
			ep.Type = gateonv1.EntryPoint_TCP
		}
	} else if hasUDP {
		if tlsEnabled || isHTTPPort {
			ep.Type = gateonv1.EntryPoint_HTTP3
		} else {
			ep.Type = gateonv1.EntryPoint_UDP
		}
	}
	if hasTCP && hasUDP && (tlsEnabled || isHTTPPort) {
		ep.Type = gateonv1.EntryPoint_HTTP
	}
}
