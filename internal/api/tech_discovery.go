package api

import (
	"context"
	"errors"

	"github.com/gsoultan/gateon/internal/discovery"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func (s *ApiService) DiscoverTech(ctx context.Context, req *gateonv1.DiscoverTechRequest) (*gateonv1.DiscoverTechResponse, error) {
	if req == nil {
		return nil, errors.New("request is required")
	}
	if req.Url == "" {
		return nil, errors.New("url is required")
	}

	detector := &discovery.TechDetector{}
	resp, err := detector.Discover(ctx, req.Url, req.TlsConfig)
	if err != nil {
		return nil, err
	}

	s.logAudit(ctx, "discover_tech", req.Url, "Identified tech: "+resp.Tech)

	return resp, nil
}
