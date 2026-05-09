package tls

import (
	"context"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Service encapsulates TLS option business logic: validation, ID generation, persistence.
type Service interface {
	ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.TLSOption, int32)
	GetTLSOption(ctx context.Context, id string) (*gateonv1.TLSOption, bool)
	SaveTLSOption(ctx context.Context, opt *gateonv1.TLSOption) error
	DeleteTLSOption(ctx context.Context, id string) error
}
