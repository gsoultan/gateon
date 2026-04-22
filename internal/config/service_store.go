package config

import (
	"context"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// ServiceStore defines the contract for working with service configurations.
// It is implemented by ServiceRegistry.
type ServiceStore interface {
	List(ctx context.Context) []*gateonv1.Service
	ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.Service, int32)
	Get(ctx context.Context, id string) (*gateonv1.Service, bool)
	Update(ctx context.Context, s *gateonv1.Service) error
	Delete(ctx context.Context, id string) error
}
