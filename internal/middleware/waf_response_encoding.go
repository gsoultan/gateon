// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Response-body inspection only means anything against bytes the application
// will actually render. An origin that answers `Accept-Encoding: gzip, br` with
// a compressed body hands the WAF a DEFLATE stream, and there is no grammar in a
// DEFLATE stream: no rule matches, and the response is reported clean while the
// browser decompresses and paints the card number. That is the whole of DLP
// disabled by one request header, and it is the same bypass gwaf already closes
// on the request path (see Transaction.decompress) — the response path simply
// never had the equivalent.
//
// Two halves close it. Outbound, the client's Accept-Encoding is narrowed to
// what this file can undo, so an origin cannot answer in an encoding that would
// blind the inspection. Inbound, whatever encoding does come back is undone for
// inspection while the original bytes are forwarded to the client untouched —
// so the client keeps its compression and Content-Length stays honest.

// Encodings that can be undone here. Brotli and zstd are deliberately absent:
// neither is in the standard library, and adding a decompressor to the request
// path is a supply-chain decision rather than a bug fix. They are handled by
// not asking for them.
const (
	encodingIdentity = ""
	encodingGzip     = "gzip"
	encodingDeflate  = "deflate"
)

var errEncodingUnsupported = errors.New("waf: response content-encoding cannot be decoded")

// negotiateInspectableEncoding rewrites a client's Accept-Encoding into one
// whose answer this file can read.
//
// The empty string means "send no Accept-Encoding upstream": Go's http.Transport
// then adds gzip on its own behalf and transparently decompresses the response
// before the proxy ever sees it, which is the cheapest correct outcome. That is
// only safe when the client sent no preference of its own, because the response
// forwarded to it is then plaintext.
//
// The second return reports whether the header should be replaced at all. A
// client that already asked for something readable is left alone.
func negotiateInspectableEncoding(clientAccept string) (string, bool) {
	if strings.TrimSpace(clientAccept) == "" {
		// No preference from the client, and none set here: Transport's own
		// transparent gzip applies and the body arrives already decoded.
		return "", false
	}
	if acceptsEncoding(clientAccept, encodingGzip) {
		// The client reads gzip, so the origin may keep compressing: the bytes
		// are inflated for inspection and forwarded compressed, unchanged.
		return encodingGzip, true
	}
	if acceptsEncoding(clientAccept, encodingDeflate) {
		return encodingDeflate, true
	}
	// The client wants only encodings that cannot be undone here (brotli, zstd),
	// so nothing may be forwarded compressed. Identity costs bandwidth on this
	// hop and is the only answer that keeps the response inspectable.
	return "identity", true
}

// acceptsEncoding reports whether an Accept-Encoding header offers name with a
// non-zero quality value. A bare `*` counts, since it invites anything.
func acceptsEncoding(header, name string) bool {
	for len(header) > 0 {
		var part string
		if i := strings.IndexByte(header, ','); i >= 0 {
			part, header = header[:i], header[i+1:]
		} else {
			part, header = header, ""
		}
		token, q := splitCodingQuality(part)
		if q {
			continue // q=0 is a refusal, not an offer.
		}
		if strings.EqualFold(token, name) || token == "*" {
			return true
		}
	}
	return false
}

// splitCodingQuality splits one Accept-Encoding element into its coding token
// and whether that coding was refused outright with q=0.
func splitCodingQuality(part string) (token string, refused bool) {
	token = part
	if i := strings.IndexByte(part, ';'); i >= 0 {
		token = part[:i]
		for _, param := range strings.Split(part[i+1:], ";") {
			param = strings.TrimSpace(param)
			if !strings.HasPrefix(strings.ToLower(param), "q=") {
				continue
			}
			// Only an exact zero refuses; q=0.001 is a very weak yes and the
			// origin may still pick it, so it has to stay inspectable.
			switch strings.TrimSpace(param[2:]) {
			case "0", "0.", "0.0", "0.00", "0.000":
				refused = true
			}
		}
	}
	return strings.TrimSpace(token), refused
}

// decodableEncoding maps a response Content-Encoding onto an encoding this file
// can undo. The second return is false when the header names something else, in
// which case the body is undecodable rather than plaintext — a distinction that
// has to survive, because "could not be read" is not "was read and found clean".
func decodableEncoding(contentEncoding string) (string, bool) {
	enc := strings.TrimSpace(contentEncoding)
	if enc == "" {
		return encodingIdentity, true
	}
	// A chain of encodings would have to be undone in order, and no origin worth
	// supporting sends one. Treating it as undecodable is the safe reading.
	if strings.IndexByte(enc, ',') >= 0 {
		return "", false
	}
	switch strings.ToLower(enc) {
	case "identity":
		return encodingIdentity, true
	case "gzip", "x-gzip":
		return encodingGzip, true
	case "deflate":
		return encodingDeflate, true
	default:
		return "", false
	}
}

// gzipReaderPool keeps inflate state off the per-response path. gzip.NewReader
// allocates a 32 KiB window every time it is called, which on a response-
// inspecting route is a per-request allocation in exactly the place the hot-path
// budget forbids one.
var gzipReaderPool = sync.Pool{New: func() any { return new(gzip.Reader) }}

var flateReaderPool = sync.Pool{New: func() any { return flate.NewReader(nil) }}

// inflateForInspection undoes enc over src, returning at most limit bytes.
//
// The cap is the point: a compressed body is an amplifier, and inflating one
// without a ceiling turns a small response into an unbounded allocation chosen
// by the origin. Hitting the cap is reported through truncated rather than as an
// error — the prefix is real and worth inspecting, it just is not the whole
// body, and the caller has to be able to say so.
func inflateForInspection(enc string, src []byte, limit int) (out []byte, truncated bool, err error) {
	if len(src) == 0 {
		return nil, false, nil
	}
	var r io.Reader
	switch enc {
	case encodingGzip:
		zr, _ := gzipReaderPool.Get().(*gzip.Reader)
		if resetErr := zr.Reset(bytes.NewReader(src)); resetErr != nil {
			gzipReaderPool.Put(zr)
			return nil, false, resetErr
		}
		defer func() {
			_ = zr.Close()
			gzipReaderPool.Put(zr)
		}()
		r = zr
	case encodingDeflate:
		fr, _ := flateReaderPool.Get().(io.ReadCloser)
		// HTTP "deflate" is zlib-wrapped in the RFC and raw DEFLATE in the wild.
		// flate.Reader reads the raw form; a zlib header is two bytes that the
		// raw reader rejects, so it is skipped when present.
		body := src
		if len(body) >= 2 && body[0]&0x0f == 0x08 && (uint16(body[0])<<8|uint16(body[1]))%31 == 0 {
			body = body[2:]
		}
		if resetErr := fr.(flate.Resetter).Reset(bytes.NewReader(body), nil); resetErr != nil {
			flateReaderPool.Put(fr)
			return nil, false, resetErr
		}
		defer func() {
			_ = fr.Close()
			flateReaderPool.Put(fr)
		}()
		r = fr
	default:
		return nil, false, errEncodingUnsupported
	}

	// limit+1 so a body that exactly fills the ceiling is distinguishable from
	// one that overruns it.
	buf := make([]byte, 0, min(limit, 64<<10))
	w := bytes.NewBuffer(buf)
	n, err := io.Copy(w, io.LimitReader(r, int64(limit)+1))
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		// A stream that stops early still decoded a real prefix — an origin that
		// was cut off mid-response is common enough that discarding what did
		// decode would reintroduce the blind spot this exists to close.
		return w.Bytes(), false, err
	}
	if n > int64(limit) {
		return w.Bytes()[:limit], true, nil
	}
	return w.Bytes(), false, nil
}

// acceptEncodingHeader is the canonical map key, used directly so the rewrite
// costs one map assignment rather than a textproto canonicalisation per request.
const acceptEncodingHeader = "Accept-Encoding"

// forceInspectableEncoding narrows the outbound Accept-Encoding so the origin
// cannot answer in an encoding the response phase would be blind to. It returns
// the header's previous value so the caller can put it back.
func forceInspectableEncoding(h http.Header) (prev []string, had bool) {
	prev, had = h[acceptEncodingHeader]
	want, replace := negotiateInspectableEncoding(strings.Join(prev, ", "))
	if !replace {
		// The client expressed no preference, so Transport's transparent gzip
		// applies and the body arrives decoded. Deleting a header that is not
		// there would still be a write; leaving it alone is free.
		return prev, had
	}
	h[acceptEncodingHeader] = []string{want}
	return prev, had
}

// restoreAcceptEncoding puts back what the client sent, so access logs,
// telemetry and fingerprinting downstream still see the real request.
func restoreAcceptEncoding(h http.Header, prev []string, had bool) {
	if had {
		h[acceptEncodingHeader] = prev
		return
	}
	delete(h, acceptEncodingHeader)
}

// Inspecting a response costs a buffer to hold it and a pass over every byte,
// and both are wasted on a body no data-leak rule could ever match. A JPEG, a
// font or a video segment cannot contain a PEM header or a `\b`-anchored card
// number in any form a regex over raw bytes would find, yet at enterprise tier
// every one of them was being held to the ceiling and scanned. On the deployment
// this targets — two cores, two gigabytes — that is the difference between
// response inspection being affordable and being the reason the box runs out of
// memory under a burst of image traffic.
//
// So the gate is the content type, and it errs toward inspecting: an unknown or
// absent type is read, because an origin that leaks a secret in a body it
// declined to label is exactly the case a data-leak control exists for. Only
// types that are positively known to be opaque are skipped.

// responseBodyInspectable reports whether a response with this Content-Type is
// worth holding and scanning.
func responseBodyInspectable(contentType string) bool {
	// Parameters (charset, boundary) say nothing about readability.
	mediaType := contentType
	if i := strings.IndexByte(mediaType, ';'); i >= 0 {
		mediaType = mediaType[:i]
	}
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))

	if mediaType == "" {
		// No declared type. The origin may be leaking text it never labelled,
		// and the cost of reading it is already bounded by the ceiling.
		return true
	}

	base, sub, _ := strings.Cut(mediaType, "/")
	switch base {
	case "text":
		return true
	case "image", "audio", "video", "font":
		return false
	case "application":
		return applicationSubtypeInspectable(sub)
	case "multipart":
		// A multipart response can carry a text part, and its own framing is
		// plain enough for a rule to match across.
		return true
	default:
		// "model", "chemical", a vendor tree nobody here has seen: unknown means
		// inspect, for the same reason an absent type does.
		return true
	}
}

// applicationSubtypeInspectable decides the application/* tree, which is the
// only one where the answer is not obvious from the top-level type: it holds
// both JSON and JavaScript and ZIP archives and PDFs.
func applicationSubtypeInspectable(sub string) bool {
	// A structured-syntax suffix describes the encoding rather than the vendor,
	// so application/vnd.api+json reads as JSON without needing to be listed.
	if i := strings.LastIndexByte(sub, '+'); i >= 0 {
		switch sub[i+1:] {
		case "json", "xml", "yaml", "text":
			return true
		case "zip", "gzip":
			return false
		}
	}
	switch sub {
	case "json", "xml", "javascript", "ecmascript", "x-javascript",
		"x-www-form-urlencoded", "graphql", "ld+json", "yaml", "x-yaml",
		"x-ndjson", "csv", "sql", "x-sh", "x-httpd-php":
		return true
	case "octet-stream", "pdf", "zip", "gzip", "x-gzip", "x-tar", "x-bzip2",
		"x-7z-compressed", "x-rar-compressed", "wasm", "java-archive",
		"vnd.ms-fontobject", "x-protobuf", "protobuf", "grpc", "grpc+proto":
		// Opaque containers. A secret inside a ZIP is a real leak and this does
		// not catch it — archive inspection is a different control with a
		// different cost, and pretending a regex over compressed bytes covers it
		// would be the worse answer.
		return false
	default:
		return true
	}
}
