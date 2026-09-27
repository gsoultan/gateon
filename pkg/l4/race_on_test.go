// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build race

package l4

// raceDetector reports a -race build, in which sync.Pool drops a quarter of
// what it is given and allocation counts include the difference.
const raceDetector = true
