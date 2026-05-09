package canary

import (
	"context"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Service handles automated traffic shifting.
type Service interface {
	StartCanary(ctx context.Context, req *gateonv1.StartCanaryRequest) (string, error)
}
