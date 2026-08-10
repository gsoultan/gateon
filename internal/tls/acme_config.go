// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tls

type AcmeConfig struct {
	Enabled       bool
	Email         string
	CAServer      string
	ChallengeType string // "http", "tls-alpn"
}
