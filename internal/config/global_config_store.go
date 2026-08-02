// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package config

import (
	"context"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// GlobalConfigStore defines the contract for working with global configuration.
// It is implemented by GlobalRegistry.
type GlobalConfigStore interface {
	Get(ctx context.Context) *gateonv1.GlobalConfig
	GetCertificate(id string) (*gateonv1.Certificate, bool)
	Update(ctx context.Context, conf *gateonv1.GlobalConfig) error
	ConfigFileExists() bool
}
