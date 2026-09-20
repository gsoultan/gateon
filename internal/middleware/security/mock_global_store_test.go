// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"context"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

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
