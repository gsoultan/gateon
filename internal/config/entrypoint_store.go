package config

import (
	"context"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// EntryPointStore defines the contract for working with entrypoint configurations.
// It is implemented by EntryPointRegistry.
type EntryPointStore interface {
	List(ctx context.Context) []*gateonv1.EntryPoint
	ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.EntryPoint, int32)
	Get(ctx context.Context, id string) (*gateonv1.EntryPoint, bool)
	Update(ctx context.Context, ep *gateonv1.EntryPoint) error
	Delete(ctx context.Context, id string) error
}
