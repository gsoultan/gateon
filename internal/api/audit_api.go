// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gsoultan/gateon/internal/audit"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *ApiService) ListAuditLogs(ctx context.Context, req *gateonv1.ListAuditLogsRequest) (*gateonv1.ListAuditLogsResponse, error) {
	// Page-based pagination is preferred. The legacy `limit` field is honoured
	// as a page size when no explicit page_size is supplied.
	page := int(req.GetPage())
	pageSize := int(req.GetPageSize())
	if pageSize <= 0 {
		if limit := int(req.GetLimit()); limit > 0 {
			pageSize = limit
		} else {
			pageSize = 100
		}
	}

	logs, total, err := audit.GetLogsPaginated(ctx, page, pageSize, req.GetSearch())
	if err != nil {
		return nil, err
	}

	protoLogs := make([]*gateonv1.AuditLog, 0, len(logs))
	for _, l := range logs {
		protoLogs = append(protoLogs, &gateonv1.AuditLog{
			Id:        l.ID,
			UserId:    l.UserID,
			Action:    l.Action,
			Resource:  l.Resource,
			Details:   l.Details,
			Timestamp: l.Timestamp.Format(time.RFC3339),
			IpAddress: l.IPAddress,
			Signature: l.Signature,
		})
	}

	return &gateonv1.ListAuditLogsResponse{
		Logs:       protoLogs,
		TotalCount: int32(total),    //nosec G115
		Page:       int32(page),     //nosec G115
		PageSize:   int32(pageSize), //nosec G115
	}, nil
}

func (s *ApiService) ListAuditArchives(ctx context.Context, req *gateonv1.ListAuditArchivesRequest) (*gateonv1.ListAuditArchivesResponse, error) {
	archives, err := audit.ListArchives()
	if err != nil {
		return nil, err
	}
	return &gateonv1.ListAuditArchivesResponse{Archives: archives}, nil
}

func (s *ApiService) GetAuditArchive(ctx context.Context, req *gateonv1.GetAuditArchiveRequest) (*gateonv1.GetAuditArchiveResponse, error) {
	data, err := audit.GetArchive(req.GetFilename())
	if err != nil {
		return nil, err
	}

	var logs []audit.AuditEntry
	if err := json.Unmarshal(data, &logs); err != nil {
		return nil, err
	}

	protoLogs := make([]*gateonv1.AuditLog, 0, len(logs))
	for _, l := range logs {
		protoLogs = append(protoLogs, &gateonv1.AuditLog{
			Id:        l.ID,
			UserId:    l.UserID,
			Action:    l.Action,
			Resource:  l.Resource,
			Details:   l.Details,
			Timestamp: l.Timestamp.Format(time.RFC3339),
			IpAddress: l.IPAddress,
			Signature: l.Signature,
		})
	}

	return &gateonv1.GetAuditArchiveResponse{Logs: protoLogs}, nil
}

// VerifyAuditChain checks the audit log's HMAC chain over one bounded window
// and says whether it is intact or where it first breaks (ADR 0050).
// Administrators only: the answer says what was tampered with and when.
func (s *ApiService) VerifyAuditChain(ctx context.Context, req *gateonv1.VerifyAuditChainRequest) (*gateonv1.VerifyAuditChainResponse, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}
	vr, err := verifyRequestFrom(req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	res, err := audit.VerifyRange(ctx, vr)
	switch {
	case errors.Is(err, audit.ErrSigningOff):
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, audit.ErrUnknownCursor):
		return nil, status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, audit.ErrNotInitialized):
		return nil, status.Error(codes.Unavailable, err.Error())
	case err != nil:
		logger.L.LogError("audit chain verification failed", "error", err)
		return nil, status.Error(codes.Internal, "the audit log could not be read")
	}
	if res.Break != nil {
		s.logAudit(ctx, "verify_failed", "audit_chain", "Audit chain broken at entry "+res.Break.ID+": "+res.Break.Reason)
	}
	return verifyResponse(res), nil
}

// verifyRequestFrom parses req's RFC 3339 bounds.
func verifyRequestFrom(req *gateonv1.VerifyAuditChainRequest) (audit.VerifyRequest, error) {
	vr := audit.VerifyRequest{AfterID: req.GetAfterId(), Limit: int(req.GetLimit())}
	for _, b := range []struct {
		name, in string
		out      *time.Time
	}{{"from", req.GetFrom(), &vr.From}, {"to", req.GetTo(), &vr.To}} {
		if b.in == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, b.in)
		if err != nil {
			return vr, fmt.Errorf("%s must be an RFC 3339 time: %w", b.name, err)
		}
		*b.out = t
	}
	return vr, nil
}

func verifyResponse(res audit.VerifyResult) *gateonv1.VerifyAuditChainResponse {
	out := &gateonv1.VerifyAuditChainResponse{
		Intact:      res.Break == nil,
		Checked:     int32(res.Checked), //nolint:gosec // at most audit.MaxVerifyLimit
		NextAfterId: res.NextAfterID,
		Complete:    res.Complete,
	}
	if !res.Last.IsZero() {
		out.LastTimestamp = res.Last.UTC().Format(time.RFC3339Nano)
	}
	if res.Break != nil {
		out.FirstBreak = &gateonv1.AuditChainBreak{
			Id: res.Break.ID, Timestamp: res.BreakAt.UTC().Format(time.RFC3339Nano), Reason: res.Break.Reason,
		}
	}
	return out
}
