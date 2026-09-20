// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"context"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The global-config store double used by the factory tests. It lived beside a
// geoip test that moved to the security package, while factory_coverage_test.go
// stayed here and still needs it -- the same "a shared helper sits in whichever
// file someone first needed it" shape this refactor keeps turning up, in test
// code this time.

type mockGlobalConfigStore struct {
	config *gateonv1.GlobalConfig
}

func (m *mockGlobalConfigStore) Get(ctx context.Context) *gateonv1.GlobalConfig {
	return m.config
}
func (m *mockGlobalConfigStore) GetCertificate(id string) (*gateonv1.Certificate, bool) {
	if m.config != nil && m.config.Tls != nil {
		for _, c := range m.config.Tls.Certificates {
			if c.Id == id {
				return c, true
			}
		}
	}
	return nil, false
}
func (m *mockGlobalConfigStore) Update(ctx context.Context, conf *gateonv1.GlobalConfig) error {
	m.config = conf
	return nil
}
func (m *mockGlobalConfigStore) ConfigFileExists() bool { return true }
