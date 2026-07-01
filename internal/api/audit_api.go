package api

import (
	"context"
	"encoding/json"
	"time"

	"github.com/gsoultan/gateon/internal/audit"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
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
		TotalCount: int32(total),
		Page:       int32(page),
		PageSize:   int32(pageSize),
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
