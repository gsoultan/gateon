// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/audit"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/auth/admission"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/server/readiness"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// decodeGlobalConfig decodes body as protobuf JSON first, then plain JSON.
func decodeGlobalConfig(body []byte, conf *gateonv1.GlobalConfig) error {
	if err := ProtojsonUnmarshalOptions().Unmarshal(body, conf); err == nil {
		return nil
	}
	if err := json.Unmarshal(body, conf); err != nil {
		return errors.New("invalid json")
	}
	return nil
}

// sentByBrowser reports whether r was sent by a browser.
//
// Sec-Fetch-Mode is a forbidden request header: every current browser sets it
// on every request it sends -- a navigation, fetch(), XMLHttpRequest -- and page
// script can neither set nor remove it. So its presence means a browser sent
// the request and its absence means a program that is not one did, whatever the
// script behind a browser request would like the server to believe. A browser
// too old to send it is treated as an API client, which is what it was before.
func sentByBrowser(r *http.Request) bool {
	return r.Header.Get("Sec-Fetch-Mode") != ""
}

// TwoFactorChallengeInvalidCode is the error code POST /v1/auth/2fa/verify
// answers when the request does not carry a valid challenge from the password
// step (ADR 0039). The dashboard reads it to send the user back to sign in
// again; it is not a wrong code.
const TwoFactorChallengeInvalidCode = "two_factor_challenge_invalid"

// wrongCodeStatus is the status for a second factor that did not verify.
//
// During sign-in there is no session yet, and 401 says so. A caller enrolling
// their own account is signed in: the dashboard's apiFetch reads any 401 as
// "the session is over" and signs the user out, so a mistyped code in the
// enrolment dialog ended the session it was meant to protect. The session is
// fine; it is this code that was refused.
func wrongCodeStatus(isLoginStep bool) int {
	if isLoginStep {
		return http.StatusUnauthorized
	}
	return http.StatusForbidden
}

// writeSetup2FARefusal answers a self-service 2FA setup the service refused.
//
// A wrong password is 403, not 401, for the reason wrongCodeStatus gives: the
// caller is signed in, and it is the re-authentication that failed. Nothing
// the service produced is written, and neither is its error text, which for an
// unexpected failure could be a database error.
func writeSetup2FARefusal(w http.ResponseWriter, r *http.Request, err error) {
	if writeBusy(w, err) {
		return
	}
	switch {
	case errors.Is(err, auth.ErrAccountLocked):
		logger.SecurityEvent("auth_2fa_setup_locked", r, "account_locked")
		WriteHTTPError(w, http.StatusTooManyRequests, err.Error())
	case errors.Is(err, auth.ErrInvalidCredentials):
		logger.SecurityEvent("auth_2fa_setup_failure", r, "invalid_password")
		WriteHTTPError(w, http.StatusForbidden, "the current password is incorrect")
	case errors.Is(err, auth.ErrAccountDisabled):
		WriteHTTPError(w, http.StatusForbidden, err.Error())
	default:
		logger.L.LogError("2FA setup failed", "error", err)
		WriteHTTPError(w, http.StatusInternalServerError, "2FA setup could not be started")
	}
}

// writeBusy answers auth.ErrBusy -- every hash slot taken, refused before any
// hash (ADR 0053) -- as 429 with a Retry-After, and reports whether err was
// that. Not 401: nothing was checked, and the dashboard reads 401 on a step a
// signed-in user takes as the end of their session.
func writeBusy(w http.ResponseWriter, err error) bool {
	if !errors.Is(err, auth.ErrBusy) {
		return false
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(admission.BusyRetryAfter/time.Second)))
	WriteHTTPError(w, http.StatusTooManyRequests, err.Error())
	return true
}

// signInUnavailable is the answer to a sign-in the gateway could not judge.
const signInUnavailable = "sign-in is unavailable: the gateway could not read its user database; " +
	"try again shortly (the gateway's log has the reason)"

// writeSignInRefusal answers a failed POST /v1/login. A refusal of the
// credentials is 401 with its reason. Anything else is the gateway failing,
// not the caller: with the user database down every sign-in used to answer
// 401 with the driver's error, which read as a wrong password to the person
// signing in and named the database to anyone who asked. It is 503, which the
// dashboard shows as "not ready", and the error goes to the log.
func writeSignInRefusal(w http.ResponseWriter, err error) {
	if writeBusy(w, err) {
		return
	}
	if errors.Is(err, auth.ErrInvalidCredentials) || errors.Is(err, auth.ErrAccountLocked) ||
		errors.Is(err, auth.ErrAccountDisabled) {
		WriteHTTPError(w, http.StatusUnauthorized, err.Error())
		return
	}
	logger.L.LogError("sign-in failed: the user database could not be read", "error", err)
	WriteHTTPError(w, http.StatusServiceUnavailable, signInUnavailable)
}

// secondFactorUnreadable is the answer when an account's stored second factor
// does not decrypt under the session key in force.
const secondFactorUnreadable = "this account's two-factor secret cannot be read by this gateway: it was stored " +
	"under a different session key, which is what restoring the database with another global.json does. " +
	"An administrator can restore the matching global.json (or set GATEON_PREVIOUS_SESSION_KEY and restart), " +
	"or reset this account's two-factor authentication"

// writeSecondFactorFailure answers a 2FA verification that failed for a
// reason other than the code. It used to write the error itself, which for a
// database restored under another key was "failed to decrypt secret: cipher:
// message authentication failed" -- true, and no help to anyone.
func writeSecondFactorFailure(w http.ResponseWriter, id string, err error) {
	if errors.Is(err, auth.ErrSecretUndecryptable) {
		logger.L.LogError("a 2FA sign-in failed: the account's second factor does not decrypt under the "+
			"session key in global.json", "user_id", id)
		WriteHTTPError(w, http.StatusInternalServerError, secondFactorUnreadable)
		return
	}
	logger.L.LogError("2FA verification failed", "user_id", id, "error", err)
	WriteHTTPError(w, http.StatusInternalServerError,
		"two-factor verification could not be completed (the gateway's log has the reason)")
}

// writeServiceRefusal answers an error ApiService returned with the HTTP status
// its gRPC code stands for. The service's message is passed on only for the
// codes it writes messages for callers under -- a refusal, not a failure; an
// unexpected failure's text can be a database error, and is logged instead. A
// refused password is 403 and never 401, for the reason wrongCodeStatus gives.
func writeServiceRefusal(w http.ResponseWriter, err error) {
	st, _ := status.FromError(err)
	switch st.Code() {
	case codes.InvalidArgument:
		WriteHTTPError(w, http.StatusBadRequest, st.Message())
	case codes.PermissionDenied:
		WriteHTTPError(w, http.StatusForbidden, st.Message())
	case codes.ResourceExhausted:
		WriteHTTPError(w, http.StatusTooManyRequests, st.Message())
	case codes.AlreadyExists:
		WriteHTTPError(w, http.StatusConflict, st.Message())
	// A refusal each, not a failure; they read as 500 (ADR 0050's token and
	// audit-verification answers were the first to use them over REST).
	case codes.NotFound:
		WriteHTTPError(w, http.StatusNotFound, st.Message())
	case codes.FailedPrecondition:
		WriteHTTPError(w, http.StatusBadRequest, st.Message())
	case codes.Unavailable:
		WriteHTTPError(w, http.StatusServiceUnavailable, st.Message())
	default:
		logger.L.LogError("management request failed", "error", err)
		WriteHTTPError(w, http.StatusInternalServerError, "the request could not be completed")
	}
}

// registerGlobalHandlers registers global configuration and utility handlers.
func registerGlobalHandlers(mux *http.ServeMux, svc GlobalAndAuthAPI, d *Deps) {
	mux.HandleFunc("GET /v1/global", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceGlobal) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// A copy: the registry hands out its stored pointer, and the validation
		// stamped below belongs to this response. Stamped on the original it was
		// an unsynchronised write to the live config, and the next save
		// persisted it into global.json.
		gc, ok := proto.Clone(svc.GetGlobals().Get(r.Context())).(*gateonv1.GlobalConfig)
		if !ok || gc == nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to read global config")
			return
		}

		if gc.Tls != nil && len(gc.Tls.Certificates) > 0 {
			tm := svc.GetTLSManager()
			if tm != nil {
				for _, c := range gc.Tls.Certificates {
					if c.CertFile != "" && c.KeyFile != "" {
						v, err := tm.ValidateCertificateFiles(c.CertFile, c.KeyFile, c.CaFile)
						if err == nil {
							c.Validation = v
						}
					}
				}
			}
		}

		// No caller gets a stored credential back: a writer reads each as the
		// placeholder (or its reference) and sends it back to keep it, a
		// viewer reads "". The same view GetGlobalConfig serves over Connect
		// and gRPC. See ADR 0028.
		gc = api.GlobalConfigView(svc.GetGlobals(), gc, callerMayWrite(r, auth.ResourceGlobal))
		data, _ := ProtojsonOptions().Marshal(gc)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /v1/audit/logs", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceDiagnostics) {
			return
		}
		page, pageSize, search := ParsePagination(r)
		// Fall back to the legacy `limit` query param as the page size so older
		// clients keep working.
		if pageSize <= 0 {
			// Same bounding as ParsePagination: the legacy param is no less
			// attacker-controlled than the modern one, and Atoi + int32() here
			// let "4294967297" truncate into a small positive page size while
			// a value like 10_000_000 became one enormous query.
			pageSize = boundedInt32(r.URL.Query().Get("limit"), maxPageSize)
		}
		if pageSize <= 0 {
			pageSize = 100
		}
		logs, total, err := audit.GetLogsPaginated(r.Context(), int(page), int(pageSize), search)
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"logs":       logs,
			"totalCount": total,
			"page":       page,
			"pageSize":   pageSize,
		})
	})
	mux.HandleFunc("GET /v1/audit/logs/watch", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceDiagnostics) {
			return
		}
		SetSSEHeaders(w)

		ch := audit.Subscribe()
		if ch == nil {
			http.Error(w, "Audit manager not initialized", http.StatusInternalServerError)
			return
		}
		defer audit.Unsubscribe(ch)

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		for {
			select {
			case entry, ok := <-ch:
				if !ok {
					return
				}
				data, _ := json.Marshal(entry)
				_, _ = fmt.Fprintf(w, "data: %s\n\n", string(data))
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	})
	mux.HandleFunc("GET /v1/audit/archives", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceDiagnostics) {
			return
		}
		archives, err := audit.ListArchives()
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"archives": archives})
	})
	mux.HandleFunc("GET /v1/audit/archives/{filename}", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceDiagnostics) {
			return
		}
		filename := r.PathValue("filename")
		data, err := audit.GetArchive(filename)
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// #nosec G705 -- Gateon's own audit archive, served as application/json.
		// The management API applies SecurityHeaders(preset "recommended"), which
		// sets X-Content-Type-Options: nosniff, so it cannot be sniffed to HTML.
		_, _ = w.Write(data)
	})
	handleUpdateGlobal := func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceGlobal) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var conf gateonv1.GlobalConfig
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBodySize))
		if err != nil {
			WriteHTTPError(w, http.StatusBadRequest, "failed to read body")
			return
		}
		if err := decodeGlobalConfig(body, &conf); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		// Stored and applied by the code the API's UpdateGlobalConfig runs --
		// omitted sections kept, the audit key generated, TLS, alerting, IP
		// reputation, retention, eBPF and the WAF reconfigured, the change
		// audited. This handler used to store the body and apply a few of
		// those itself, so an ACME switch, a certificate or a client authority
		// saved from the dashboard did nothing until a restart.
		if _, err := svc.UpdateGlobalConfig(r.Context(), &gateonv1.UpdateGlobalConfigRequest{Config: &conf}); err != nil {
			// A refusal -- a kept secret that cannot be kept, or a setting
			// only an administrator may change (ADR 0040) -- names the field,
			// and the caller needs that to fix the request.
			switch status.Code(err) {
			case codes.InvalidArgument:
				WriteHTTPError(w, http.StatusBadRequest, status.Convert(err).Message())
				return
			case codes.PermissionDenied:
				WriteHTTPError(w, http.StatusForbidden, status.Convert(err).Message())
				return
			}
			logger.L.LogError("global config update failed", "error", err)
			WriteHTTPError(w, http.StatusInternalServerError, "failed to update global config")
			return
		}

		_ = json.NewEncoder(w).Encode(struct {
			Success bool `json:"success,omitzero"`
		}{Success: true})
	}
	mux.HandleFunc("POST /v1/global", handleUpdateGlobal)
	mux.HandleFunc("PUT /v1/global", handleUpdateGlobal)
	mux.HandleFunc("PUT /v1/config", func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = "/v1/global"
		mux.ServeHTTP(w, r)
	})
	mux.HandleFunc("GET /v1/me", func(w http.ResponseWriter, r *http.Request) {
		claims, ok := callerClaims(r)
		if !ok || claims == nil {
			WriteHTTPError(w, http.StatusUnauthorized, "not authenticated")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user": map[string]string{
				"id":       claims.ID,
				"username": claims.Username,
				"role":     claims.Role,
			},
		})
	})
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceDiagnostics) {
			return
		}
		res, err := svc.GetStatus(r.Context(), &gateonv1.GetStatusRequest{})
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		data, _ := ProtojsonOptions().Marshal(res)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /v1/status/watch", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceDiagnostics) {
			return
		}
		SetSSEHeaders(w)

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				res, err := svc.GetStatus(r.Context(), &gateonv1.GetStatusRequest{})
				if err != nil {
					return
				}
				data, _ := ProtojsonOptions().Marshal(res)
				_, _ = fmt.Fprintf(w, "data: %s\n\n", string(data))
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	})
	mux.HandleFunc("POST /v1/security/clamav/install", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceGlobal) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var req gateonv1.InstallClamavRequest
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBodySize))
		if err != nil {
			WriteHTTPError(w, http.StatusBadRequest, "failed to read body")
			return
		}
		if err := ProtojsonUnmarshalOptions().Unmarshal(body, &req); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}

		resp, err := svc.InstallClamav(r.Context(), &req)
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("POST /v1/security/clamav/uninstall", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceGlobal) {
			return
		}
		w.Header().Set("Content-Type", "application/json")

		// Decode the body. This used to pass a zero-valued request and never
		// read it, so SudoPassword was always empty: PreflightUninstall then
		// refused every local uninstall on a non-root host with "requires root
		// privileges; please provide sudo password" — the password the operator
		// had just typed into the dialog and which was thrown away here. The
		// install handler above has always decoded its body; only this one did
		// not, which is why installing worked and removing never could.
		//
		// An absent or empty body stays valid: Docker mode needs no password,
		// and a client with nothing to send should not have to send "{}".
		var req gateonv1.UninstallClamavRequest
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBodySize))
		if err != nil {
			WriteHTTPError(w, http.StatusBadRequest, "failed to read body")
			return
		}
		if len(bytes.TrimSpace(body)) > 0 {
			if err := ProtojsonUnmarshalOptions().Unmarshal(body, &req); err != nil {
				WriteHTTPError(w, http.StatusBadRequest, err.Error())
				return
			}
		}

		resp, err := svc.UninstallClamav(r.Context(), &req)
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("POST /v1/security/clamav/scan", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceGlobal) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		resp, err := svc.RunDeepScan(r.Context(), &gateonv1.RunDeepScanRequest{})
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	// Read-only counterpart to the POST above. It is a GET and needs only read
	// permission, because polling scan state must not require the authority to
	// start a scan — nor accidentally exercise it.
	mux.HandleFunc("GET /v1/security/clamav/scan-status", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceGlobal) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		resp, err := svc.GetClamavScanStatus(r.Context(), &gateonv1.GetClamavScanStatusRequest{})
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("POST /v1/waf/update", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceGlobal) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		resp, err := svc.TriggerWafUpdate(r.Context(), &gateonv1.TriggerWafUpdateRequest{})
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		data, err := ProtojsonOptions().Marshal(resp)
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to marshal response")
			return
		}
		if _, err := w.Write(data); err != nil {
			logger.L.LogError("failed to write response", "error", err)
		}
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	// /healthz answers "is the process alive"; /readyz answers "should this
	// instance receive traffic", and those are different questions. A static
	// 200 on /readyz means an orchestrator cannot tell a healthy gateway from
	// one whose telemetry never opened, so it routes production traffic to a
	// blind instance and completes the rollout past it.
	//
	// Beyond the telemetry store it reports every entrypoint listener that did
	// not bind and a configuration database that does not answer (ADR 0049):
	// a gateway whose :443 is held by another process, or whose user database
	// is down, is alive but must not be sent traffic.
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		var notReady []string
		if !telemetry.PathStatsStoreReady() {
			notReady = append(notReady, "telemetry store")
		}
		notReady = append(notReady, readiness.NotReady()...)
		if len(notReady) > 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready: " + strings.Join(notReady, "; ")))
			return
		}
		// Serving, but something is failing: a full trace disk drops traces,
		// an unreachable configuration database stops sign-in and writes. The
		// proxy still answers, so the instance stays in rotation (a 503 here
		// would make a degraded single-node gateway a down one) and the body
		// and the gauges say what is wrong.
		degraded := readiness.Degraded()
		if r := telemetry.TraceStoreNotReady(); r != "" {
			degraded = append(degraded, r)
		}
		w.WriteHeader(http.StatusOK)
		if len(degraded) > 0 {
			_, _ = w.Write([]byte("ready, degraded: " + strings.Join(degraded, "; ")))
			return
		}
		_, _ = w.Write([]byte("ready"))
	})
	mux.HandleFunc("GET /v1/setup/required", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp, err := svc.IsSetupRequired(r.Context(), &gateonv1.IsSetupRequiredRequest{})
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		data, err := ProtojsonOptions().Marshal(resp)
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to marshal response")
			return
		}
		if _, err := w.Write(data); err != nil {
			logger.L.LogError("failed to write response", "error", err)
		}
	})
	// Test DB connection endpoint for first-run wizard
	mux.HandleFunc("POST /v1/setup/test-db", func(w http.ResponseWriter, r *http.Request) {
		// Only allow test-db during setup.
		//
		// `err != nil ||` rather than `err == nil &&`: an error means the setup
		// state is unknown, and the old form treated unknown as permitted --
		// falling through to open a caller-supplied DSN. IsSetupRequired
		// returns a nil error on every path today, so this is latent rather
		// than live, which is exactly how the last two fail-open defects in
		// this codebase read right up until something on the path started
		// returning errors.
		setupReq, err := svc.IsSetupRequired(r.Context(), &gateonv1.IsSetupRequiredRequest{})
		if err != nil || !setupReq.Required {
			WriteHTTPError(w, http.StatusForbidden, "test-db is only allowed during initial setup")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		// The database half of the SetupRequest the wizard submits next, read
		// with protojson as Setup's own transports read it. This was
		// encoding/json into snake_case tags, which the wizard's "databaseUrl",
		// "databaseConfig" and "sqlitePath" do not match -- not even
		// case-insensitively -- so the body decoded empty and every test
		// answered "missing database configuration", whatever was filled in.
		var req gateonv1.SetupRequest
		if !DecodeProtoRequest(w, r, &req) {
			return
		}
		// The token Setup requires, before the probe dials anything: until
		// setup completes this is the one database connection a caller who has
		// not signed in can make the gateway open. See ADR 0021.
		if !d.SetupToken.Matches(req.GetSetupToken()) {
			WriteHTTPError(w, http.StatusForbidden, auth.ErrSetupTokenRequired.Error())
			return
		}
		// Probe confines a SQLite database before opening it: see db.ConfineSQLite.
		if err := db.Probe(req.GetDatabaseUrl(), req.GetDatabaseConfig(), config.DataDir()); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		_ = json.NewEncoder(w).Encode(struct {
			Success bool `json:"success"`
		}{Success: true})
	})
	mux.HandleFunc("POST /v1/setup", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Refuse before anything else once setup is done. This path skips
		// authentication for the life of the process, and Setup writes the
		// caller's authentication and audit databases to global config. The
		// handler used to do that write itself, ahead of Setup's own "already
		// completed" check, so on a configured gateway an unauthenticated
		// request could repoint both at a server it controls -- and the gateway
		// trusts that server's users on its next start. Setup now checks before
		// it writes; this refuses before the body is even read. An unknown
		// setup state is refused for the reason test-db gives.
		if setupReq, err := svc.IsSetupRequired(r.Context(), &gateonv1.IsSetupRequiredRequest{}); err != nil || !setupReq.Required {
			WriteHTTPError(w, http.StatusForbidden, "setup already completed")
			return
		}
		// Decoded whole and handed to Setup, which validates and saves the
		// databases for every transport. This handler kept its own copy of that
		// step, read through snake_case encoding/json tags, while the dashboard
		// called Setup over Connect, where the step did not exist: neither copy
		// ever saw the wizard's database. DecodeProtoRequest reads both
		// spellings, and bounds the read to 1 MiB, which matters on one of the
		// handful of paths that skip authentication entirely.
		var req gateonv1.SetupRequest
		if !DecodeProtoRequest(w, r, &req) {
			return
		}
		resp, err := svc.Setup(r.Context(), &req)
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		data, err := ProtojsonOptions().Marshal(resp)
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to marshal response")
			return
		}
		if _, err := w.Write(data); err != nil {
			logger.L.LogError("failed to write response", "error", err)
		}
	})
	mux.HandleFunc("POST /v1/auth/2fa/setup", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req gateonv1.Setup2FARequest
		if !DecodeProtoRequest(w, r, &req) {
			return
		}

		// Verify permission (self only -- see below).
		//
		// Both an absent caller and one whose claims cannot be read are refused.
		// The check below is the only thing standing between a request and
		// another account's second factor, so skipping it on an unreadable
		// credential is not an option.
		claims, ok := callerClaims(r)
		if !ok || claims == nil {
			WriteHTTPError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		{
			// 2FA setup is strictly self-service: the response contains the
			// TOTP secret, QR code, and recovery codes, which must only ever be
			// disclosed to the account owner. Even admins must not be able to
			// enable 2FA for another user, as that would hand them the second
			// factor and allow account takeover.
			if claims.ID != req.Id {
				WriteHTTPError(w, http.StatusForbidden, "2FA can only be set up for your own account")
				return
			}
		}
		// The session is not enough: see auth.Manager.Setup2FA. A missing
		// password is refused here without being counted, because it is not a
		// guess; a wrong one is counted by the service like a failed sign-in.
		if req.Password == "" {
			WriteHTTPError(w, http.StatusBadRequest, "your current password is required to set up 2FA")
			return
		}

		resp, err := svc.Setup2FA(r.Context(), &req)
		if err != nil {
			writeSetup2FARefusal(w, r, err)
			return
		}
		data, err := ProtojsonOptions().Marshal(resp)
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to marshal response")
			return
		}
		if _, err := w.Write(data); err != nil {
			logger.L.LogError("failed to write response", "error", err)
		}
	})
	mux.HandleFunc("POST /v1/auth/2fa/verify", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req gateonv1.Verify2FARequest
		if !DecodeProtoRequest(w, r, &req) {
			return
		}

		// Whether this is the second step of a login or an already-authenticated
		// user enabling 2FA. It decides whether a session cookie is issued, so a
		// claims value that cannot be read is refused rather than guessed: both
		// readings are wrong, and the permissive one mints a session.
		claims, ok := callerClaims(r)
		if !ok {
			WriteHTTPError(w, http.StatusForbidden, "insufficient permissions")
			return
		}
		// No claims means no session yet, which is the login step.
		isLoginStep := claims == nil
		// An authenticated caller may only complete their own enrolment. The
		// response carries a session token for whichever account req.Id names,
		// so verifying another user's code would hand the caller that user's
		// session.
		if !isLoginStep && claims.ID != req.Id {
			WriteHTTPError(w, http.StatusForbidden, "2FA can only be verified for your own account")
			return
		}

		resp, err := svc.Verify2FA(r.Context(), &req)
		if err != nil {
			if writeBusy(w, err) {
				return
			}
			switch {
			case errors.Is(err, auth.ErrInvalidChallenge):
				// No proof of the password step. 401 with a code the dashboard
				// keys on to send the user back to the password, never the text.
				logger.SecurityEvent("auth_2fa_challenge_refused", r, "invalid_challenge")
				httputil.WriteJSONError(w, http.StatusUnauthorized, err.Error(), TwoFactorChallengeInvalidCode)
			case errors.Is(err, auth.ErrAccountLocked):
				logger.SecurityEvent("auth_2fa_locked", r, "account_locked")
				audit.Log(r.Context(), req.Id, "2fa_locked", "auth", "Account locked during 2FA", request.ClientAddr(r))
				WriteHTTPError(w, http.StatusTooManyRequests, err.Error())
			case errors.Is(err, auth.ErrInvalidTwoFactorCode):
				logger.SecurityEvent("auth_2fa_failure", r, "invalid_2fa_code")
				audit.Log(r.Context(), req.Id, "2fa_failed", "auth", "Invalid 2FA code", request.ClientAddr(r))
				WriteHTTPError(w, wrongCodeStatus(isLoginStep), err.Error())
			default:
				writeSecondFactorFailure(w, req.Id, err)
			}
			return
		}

		if resp.Success && isLoginStep {
			// Set HttpOnly secure cookie for session (24h)
			middleware.SetSessionCookie(w, r, resp.Token, int(auth.TokenLifetime.Seconds()))
		}
		// The second step of a browser's sign-in gets the session only as the
		// cookie, as /v1/login does; see sentByBrowser.
		if isLoginStep && sentByBrowser(r) {
			resp.Token = ""
		}
		if !isLoginStep {
			// The caller is enrolling their own account and already holds a
			// session, in a cookie script cannot read. The service mints a token
			// on every successful verification, and it went back in the body:
			// script in the dashboard -- the stored-XSS case the cookie exists
			// for -- could call setup, derive a code from the secret it was
			// handed, call verify, and read a 24-hour bearer token out of the
			// answer. Enabling 2FA does not end the current session, so the
			// caller loses nothing.
			resp.Token = ""
		}

		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	// First-time 2FA enrollment during login, used when an administrator mandated
	// 2FA for an account that has not enrolled yet. It re-verifies the password (no
	// session exists at this point), so the TOTP secret is only disclosed to
	// someone who already passed the first factor. The client then completes
	// enrollment via POST /v1/auth/2fa/verify with the user id, the TOTP code and
	// the challenge the sign-in answered with.
	mux.HandleFunc("POST /v1/auth/2fa/enroll", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !auth.Available(d.AuthManager) {
			WriteHTTPError(w, http.StatusServiceUnavailable, "auth not initialized")
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		// Bounded like /v1/setup above: this path also skips authentication.
		if err := json.NewDecoder(io.LimitReader(r.Body, MaxRequestBodySize)).Decode(&req); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, "invalid json")
			return
		}
		secret, qr, recovery, id, err := d.AuthManager.EnrollPending2FA(req.Username, req.Password, request.ClientAddr(r))
		if err != nil {
			if writeBusy(w, err) {
				return
			}
			switch {
			case errors.Is(err, auth.ErrAccountLocked):
				WriteHTTPError(w, http.StatusTooManyRequests, err.Error())
			case errors.Is(err, auth.ErrAccountDisabled):
				WriteHTTPError(w, http.StatusForbidden, err.Error())
			case errors.Is(err, auth.ErrInvalidCredentials):
				logger.SecurityEvent("auth_2fa_enroll_failure", r, "invalid_credentials")
				WriteHTTPError(w, http.StatusUnauthorized, err.Error())
			default:
				WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			}
			return
		}
		// A proto message written with protojson, which the login page reads as
		// the generated type: both ends take the field names from auth.proto. They
		// were a map literal of qr_code_url and recovery_codes, which the page
		// never read -- an account made to enroll saw a broken QR image and was
		// never shown its recovery codes, only the secret to type in by hand.
		WriteProtoResponse(w, http.StatusOK, &gateonv1.Enroll2FAResponse{
			Id: id, Secret: secret, QrCodeUrl: qr, RecoveryCodes: recovery,
		})
	})
	mux.HandleFunc("POST /v1/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req gateonv1.LoginRequest
		if !DecodeProtoRequest(w, r, &req) {
			return
		}
		resp, err := svc.Login(r.Context(), &req)
		if err != nil {
			if errors.Is(err, auth.ErrInvalidCredentials) {
				logger.SecurityEvent("auth_failure", r, "invalid_credentials")
				audit.Log(r.Context(), req.Username, "login_failed", "auth", "Invalid credentials", request.ClientAddr(r))
			}
			writeSignInRefusal(w, err)
			return
		}

		audit.Log(r.Context(), req.Username, "login", "auth", "User logged in", request.ClientAddr(r))

		if !resp.TwoFactorRequired && !resp.TwoFactorSetupRequired {
			// Set HttpOnly secure cookie for session (24h) to reduce XSS exposure
			middleware.SetSessionCookie(w, r, resp.Token, int(auth.TokenLifetime.Seconds()))
		}
		// A browser gets the session only as that cookie. A token in the body
		// is a string any script in the page can read -- including script that
		// wrapped fetch before the sign-in form was submitted -- and carry off
		// as a bearer credential that outlives the tab; the cookie it cannot
		// read. API clients, which have no cookie jar to speak of, still read
		// the token from the body.
		if sentByBrowser(r) {
			resp.Token = ""
		}

		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /v1/users", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceUsers) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		page, pageSize, search := ParsePagination(r)
		resp, err := svc.ListUsers(r.Context(), &gateonv1.ListUsersRequest{
			Page: page, PageSize: pageSize, Search: search,
		})
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("PUT /v1/users", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceUsers) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var req gateonv1.User
		if !DecodeProtoRequest(w, r, &req) {
			return
		}
		if !auth.ValidRole(req.Role) {
			WriteHTTPError(w, http.StatusBadRequest, "invalid role: must be admin, operator, or viewer")
			return
		}
		resp, err := svc.UpdateUser(r.Context(), &gateonv1.UpdateUserRequest{User: &req})
		if err != nil {
			writeServiceRefusal(w, err)
			return
		}

		// Audit Log
		userID := auditUser(r)
		audit.Log(r.Context(), userID, "update", "user", "Updated user: "+req.Username, request.ClientAddr(r))

		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("POST /v1/users/password", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req gateonv1.ChangePasswordRequest
		if !DecodeProtoRequest(w, r, &req) {
			return
		}
		if req.Id == "" || req.Password == "" {
			WriteHTTPError(w, http.StatusBadRequest, "id and password are required")
			return
		}

		// Allow if admin OR if changing own password.
		//
		// A claims value that cannot be read is refused rather than skipped: it
		// establishes neither admin nor self, and continuing would change the
		// password of whatever user id the request names.
		claims, ok := callerClaims(r)
		if !ok {
			WriteHTTPError(w, http.StatusForbidden, "insufficient permissions")
			return
		}
		if claims != nil {
			isAdmin := auth.Allowed(r.Context(), claims.Role, auth.ActionWrite, auth.ResourceUsers)
			isSelf := claims.ID == req.Id
			if !isAdmin && !isSelf {
				WriteHTTPError(w, http.StatusForbidden, "insufficient permissions")
				return
			}
		}

		resp, err := svc.ChangePassword(r.Context(), &req)
		if err != nil {
			writeServiceRefusal(w, err)
			return
		}
		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	// Another account's second factor (ADR 0057). The rules -- administrators
	// only, never the caller's own account, sessions ended, audited -- are the
	// service's, so REST, Connect and gRPC give the same answer.
	mux.HandleFunc("POST /v1/users/{id}/2fa/reset", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceUsers) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		resp, err := svc.ResetUserTwoFactor(r.Context(), &gateonv1.ResetUserTwoFactorRequest{Id: r.PathValue("id")})
		if err != nil {
			writeServiceRefusal(w, err)
			return
		}
		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("DELETE /v1/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceUsers) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		id := r.PathValue("id")
		resp, err := svc.DeleteUser(r.Context(), &gateonv1.DeleteUserRequest{Id: id})
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}

		// Audit Log
		userID := auditUser(r)
		audit.Log(r.Context(), userID, "delete", "user", "Deleted user ID: "+id, request.ClientAddr(r))

		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("POST /v1/logout", handleLogout(d))
}

// handleLogout signs the caller out everywhere.
//
// It used to clear the cookie and nothing else, so the session token the
// cookie held kept working until it expired -- up to eight hours -- for anyone
// holding a copy of it. It now ends every session of the account
// (auth.Manager.EndSessions). The cookie is cleared either way: this browser is
// signed out even when the gateway cannot end the others, and says so.
func handleLogout(d *Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		middleware.ClearSessionCookie(w, r)
		w.Header().Set("Content-Type", "application/json")
		claims, _ := callerClaims(r)
		if claims != nil && auth.Available(d.AuthManager) {
			if err := d.AuthManager.EndSessions(claims.ID); err != nil {
				logger.L.LogError("sign-out could not end the account's sessions; "+
					"a copy of its session cookie still works until it expires",
					"error", err, "user", claims.ID)
				WriteHTTPError(w, http.StatusInternalServerError,
					"signed out on this device, but the account's other sessions could not be ended")
				return
			}
			audit.Log(r.Context(), claims.Username, "logout", "auth",
				"User signed out; every session of the account ended", request.ClientAddr(r))
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	}
}

// credentialAPI is what the scrape-credential and audit-verification
// handlers need of ApiService (ADR 0050).
type credentialAPI interface {
	ListApiTokens(ctx context.Context, req *gateonv1.ListApiTokensRequest) (*gateonv1.ListApiTokensResponse, error)
	CreateApiToken(ctx context.Context, req *gateonv1.CreateApiTokenRequest) (*gateonv1.CreateApiTokenResponse, error)
	RevokeApiToken(ctx context.Context, req *gateonv1.RevokeApiTokenRequest) (*gateonv1.RevokeApiTokenResponse, error)
	VerifyAuditChain(ctx context.Context, req *gateonv1.VerifyAuditChainRequest) (*gateonv1.VerifyAuditChainResponse, error)
}

// registerCredentialHandlers serves the REST twins of the scrape-credential
// RPCs and of VerifyAuditChain. Each checks the permission its RPC is mapped
// to, and ApiService then requires an administrator, as it does for users.
func registerCredentialHandlers(mux *http.ServeMux, svc credentialAPI) {
	mux.HandleFunc("GET /v1/api-tokens", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceUsers) {
			return
		}
		page, pageSize, _ := ParsePagination(r)
		resp, err := svc.ListApiTokens(r.Context(), &gateonv1.ListApiTokensRequest{Page: page, PageSize: pageSize})
		writeServiceAnswer(w, resp, err)
	})
	mux.HandleFunc("POST /v1/api-tokens", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceUsers) {
			return
		}
		var req gateonv1.CreateApiTokenRequest
		if !DecodeProtoRequest(w, r, &req) {
			return
		}
		resp, err := svc.CreateApiToken(r.Context(), &req)
		writeServiceAnswer(w, resp, err)
	})
	mux.HandleFunc("DELETE /v1/api-tokens/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceUsers) {
			return
		}
		resp, err := svc.RevokeApiToken(r.Context(), &gateonv1.RevokeApiTokenRequest{Id: r.PathValue("id")})
		writeServiceAnswer(w, resp, err)
	})
	mux.HandleFunc("GET /v1/audit/verify", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceDiagnostics) {
			return
		}
		q := r.URL.Query()
		resp, err := svc.VerifyAuditChain(r.Context(), &gateonv1.VerifyAuditChainRequest{
			From: q.Get("from"), To: q.Get("to"), AfterId: q.Get("afterId"),
			Limit: boundedInt32(q.Get("limit"), audit.MaxVerifyLimit),
		})
		writeServiceAnswer(w, resp, err)
	})
}

// writeServiceAnswer writes an ApiService answer as protojson, or its refusal
// with the status writeServiceRefusal gives it.
func writeServiceAnswer(w http.ResponseWriter, resp proto.Message, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		writeServiceRefusal(w, err)
		return
	}
	data, mErr := ProtojsonOptions().Marshal(resp)
	if mErr != nil {
		WriteHTTPError(w, http.StatusInternalServerError, "the answer could not be encoded")
		return
	}
	_, _ = w.Write(data)
}
