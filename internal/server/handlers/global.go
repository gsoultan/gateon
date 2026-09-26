// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/audit"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
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

// registerGlobalHandlers registers global configuration and utility handlers.
func registerGlobalHandlers(mux *http.ServeMux, svc GlobalAndAuthAPI, d *Deps) {
	mux.HandleFunc("GET /v1/global", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceGlobal) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		gc := svc.GetGlobals().Get(r.Context())

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

		// A caller who cannot write the global config gets it without its
		// credentials. RequirePermission admits viewers here so the dashboard
		// can render settings; it must not admit them to the PASETO key, the
		// audit signing key and every stored password and API token.
		if !callerMayWrite(r, auth.ResourceGlobal) {
			gc = api.RedactGlobalSecrets(gc)
		} else {
			// A writer sees a referenced secret as its reference, so saving
			// the page stores the reference back rather than the secret.
			gc = config.WithSecretReferences(svc.GetGlobals(), gc)
		}
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
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		var notReady []string
		if !telemetry.PathStatsStoreReady() {
			notReady = append(notReady, "telemetry store")
		}
		if len(notReady) > 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready: " + strings.Join(notReady, ", ")))
			return
		}
		w.WriteHeader(http.StatusOK)
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

		resp, err := svc.Setup2FA(r.Context(), &req)
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
			switch {
			case errors.Is(err, auth.ErrAccountLocked):
				logger.SecurityEvent("auth_2fa_locked", r, "account_locked")
				audit.Log(r.Context(), req.Id, "2fa_locked", "auth", "Account locked during 2FA", request.ClientAddr(r))
				WriteHTTPError(w, http.StatusTooManyRequests, err.Error())
			case errors.Is(err, auth.ErrInvalidTwoFactorCode):
				logger.SecurityEvent("auth_2fa_failure", r, "invalid_2fa_code")
				audit.Log(r.Context(), req.Id, "2fa_failed", "auth", "Invalid 2FA code", request.ClientAddr(r))
				WriteHTTPError(w, http.StatusUnauthorized, err.Error())
			default:
				WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			}
			return
		}

		if resp.Success && isLoginStep {
			// Set HttpOnly secure cookie for session (24h)
			middleware.SetSessionCookie(w, r, resp.Token, int(auth.TokenLifetime.Seconds()))
		}

		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	// First-time 2FA enrollment during login, used when an administrator mandated
	// 2FA for an account that has not enrolled yet. It re-verifies the password (no
	// session exists at this point), so the TOTP secret is only disclosed to
	// someone who already passed the first factor. The client then completes
	// enrollment via POST /v1/auth/2fa/verify with the user id and the TOTP code.
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
		secret, qr, recovery, id, err := d.AuthManager.EnrollPending2FA(req.Username, req.Password)
		if err != nil {
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
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":             id,
			"secret":         secret,
			"qr_code_url":    qr,
			"recovery_codes": recovery,
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
			WriteHTTPError(w, http.StatusUnauthorized, err.Error())
			return
		}

		audit.Log(r.Context(), req.Username, "login", "auth", "User logged in", request.ClientAddr(r))

		if !resp.TwoFactorRequired && !resp.TwoFactorSetupRequired {
			// Set HttpOnly secure cookie for session (24h) to reduce XSS exposure
			middleware.SetSessionCookie(w, r, resp.Token, int(auth.TokenLifetime.Seconds()))
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
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
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
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
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
	mux.HandleFunc("POST /v1/logout", func(w http.ResponseWriter, r *http.Request) {
		// Audit Log
		if claims, _ := callerClaims(r); claims != nil {
			audit.Log(r.Context(), claims.Username, "logout", "auth", "User logged out", request.ClientAddr(r))
		}
		middleware.ClearSessionCookie(w, r)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	})
}
