package entrypoint

import (
	"context"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Service encapsulates entrypoint business logic: validation, ID generation, type inference, persistence.
type Service interface {
	ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.EntryPoint, int32)
	GetEntryPoint(ctx context.Context, id string) (*gateonv1.EntryPoint, bool)
	SaveEntryPoint(ctx context.Context, ep *gateonv1.EntryPoint) error
	DeleteEntryPoint(ctx context.Context, id string) error
}
