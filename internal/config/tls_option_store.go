package config

import (
	"context"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TLSOptionStore defines the contract for working with TLS option configurations.
// It is implemented by TLSOptionRegistry.
type TLSOptionStore interface {
	List(ctx context.Context) []*gateonv1.TLSOption
	ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.TLSOption, int32)
	All(ctx context.Context) map[string]*gateonv1.TLSOption
	Get(ctx context.Context, id string) (*gateonv1.TLSOption, bool)
	Update(ctx context.Context, opt *gateonv1.TLSOption) error
	Delete(ctx context.Context, id string) error
}
