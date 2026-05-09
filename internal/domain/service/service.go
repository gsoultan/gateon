package service

import (
	"context"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Service encapsulates service business logic: validation, ID generation, persistence, proxy invalidation.
type Service interface {
	ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.Service, int32)
	GetService(ctx context.Context, id string) (*gateonv1.Service, bool)
	SaveService(ctx context.Context, svc *gateonv1.Service) error
	DeleteService(ctx context.Context, id string) error
}
