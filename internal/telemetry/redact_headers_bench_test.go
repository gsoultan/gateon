// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"strings"
	"testing"
)

// browserRequestHeaders is a header block as FormatHeaders writes it for an
// ordinary browser navigation through a proxy: the shape nearly every trace
// carries, with a session cookie and nothing credential-shaped elsewhere.
var browserRequestHeaders = strings.Join([]string{
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
	"Accept-Encoding: gzip, deflate, br, zstd",
	"Accept-Language: en-GB,en-US;q=0.9,en;q=0.8",
	"Cache-Control: max-age=0",
	"Connection: keep-alive",
	"Cookie: _ga=GA1.1.1234567890.1700000000; sid=7f3c2a9e4b1d4c8f9a0b",
	"Forwarded: for=198.51.100.17;proto=https;host=shop.example.com",
	"Referer: https://shop.example.com/catalog?page=2&sort=price",
	"Sec-Ch-Ua: \"Chromium\";v=\"141\", \"Not?A_Brand\";v=\"8\"",
	"Sec-Ch-Ua-Mobile: ?0",
	"Sec-Ch-Ua-Platform: \"macOS\"",
	"Sec-Fetch-Dest: document",
	"Sec-Fetch-Mode: navigate",
	"Sec-Fetch-Site: same-origin",
	"Upgrade-Insecure-Requests: 1",
	"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
	"X-Forwarded-For: 198.51.100.17",
	"X-Request-Id: 01JABCDEF0123456789XYZ",
}, "\n")

// BenchmarkRedactHeaders is the cost the store's loop pays per kept trace and
// threat for each header block (review 3, F4: masking by shape must not make
// the common, credential-free header cost more allocations).
func BenchmarkRedactHeaders(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = RedactHeaders(browserRequestHeaders)
	}
}
