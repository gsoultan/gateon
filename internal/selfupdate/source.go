// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/cloudmeta"
	"github.com/gsoultan/gateon/internal/mgmtaddr"
)

// DefaultSource is where gateon's releases are published.
const DefaultSource = "https://github.com/gsoultan/gateon/releases"

// The bounds on one check. Every one is explicit: the release source is a
// host the gateway connects to on its own, every day.
const (
	fetchTimeout   = 20 * time.Second
	maxRedirects   = 5
	maxSourceLen   = 2048
	checksumsFile  = "checksums.txt"
	signatureFile  = "checksums.txt.sig"
	latestDownload = "/latest/download/"
)

// ErrSource is wrapped by every refusal of a release source.
var ErrSource = errors.New("update.source_url")

// errNotFound is a release file the source does not have.
var errNotFound = errors.New("the release source has no such file")

// ValidateSource refuses a release source the gateway will not fetch. Empty
// is the default source and is accepted.
//
// The release list decides which version the dashboard offers, so whoever can
// rewrite it in transit decides that: it must be https://. Plain http:// is
// accepted only to this host's loopback, where a mirror has no network path
// to be tampered with on.
func ValidateSource(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if len(raw) > maxSourceLen {
		return fmt.Errorf("%w is longer than %d characters", ErrSource, maxSourceLen)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return fmt.Errorf("%w must be an absolute URL such as %s", ErrSource, DefaultSource)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%w must not carry credentials, a query or a fragment", ErrSource)
	}
	return checkFetchURL(u)
}

// checkFetchURL is the rule a release source and every redirect from it must
// pass: https, or http to loopback, and never a cloud metadata service.
func checkFetchURL(u *url.URL) error {
	host := u.Hostname()
	if cloudmeta.IsMetadataHostOrAddr(host) {
		return fmt.Errorf("%w must not name a cloud instance metadata service", ErrSource)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if loopbackHost(host) {
			return nil
		}
	}
	return fmt.Errorf("%w must use https:// (http:// only for a mirror on this host's loopback address)", ErrSource)
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Unmap().IsLoopback()
}

// newClient is the client release files are fetched with. Its dialer refuses
// the management listener and cloud metadata addresses after the name is
// resolved (ADR 0052, ADR 0077), and it follows a redirect only to a URL
// checkFetchURL accepts, so an https:// source cannot hand the read to http://.
func newClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: mgmtaddr.Control}
	return &http.Client{
		Timeout: fetchTimeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			MaxIdleConns:          2,
			IdleConnTimeout:       30 * time.Second,
		},
		CheckRedirect: checkRedirect,
	}
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	return checkFetchURL(req.URL)
}

// source is a validated release source.
type source struct {
	base string // no trailing slash
}

func newSource(raw string) (source, error) {
	if err := ValidateSource(raw); err != nil {
		return source{}, err
	}
	base := strings.TrimRight(strings.TrimSpace(raw), "/")
	if base == "" {
		base = DefaultSource
	}
	return source{base: base}, nil
}

func (s source) checksumsURL() string { return s.base + latestDownload + checksumsFile }
func (s source) signatureURL() string { return s.base + latestDownload + signatureFile }

// notesURL is the release page of v, where the source is laid out as GitHub's
// is. v is a parsed Version, so nothing remote reaches the URL but digits.
func (s source) notesURL(v Version) string { return s.base + "/tag/v" + v.String() }

// fetcher reads release files. The HTTP one is what runs; tests supply their
// own.
type fetcher interface {
	// fetch returns the body of url, refusing one longer than limit. A file
	// the source does not have is errNotFound.
	fetch(ctx context.Context, url string, limit int64) ([]byte, error)
}

type httpFetcher struct {
	client    *http.Client
	userAgent string
}

func (f httpFetcher) fetch(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", f.userAgent)
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch release file: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, errNotFound
	}
	// An error page is not a release list: its body would parse as one that
	// names no archive, and be reported as malformed rather than unreachable.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("the release source answered %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read release file: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%w: the file is longer than %d bytes", ErrMalformed, limit)
	}
	return body, nil
}

// downloadTimeout bounds the download of one release archive. An archive is
// tens of megabytes, which fetchTimeout would cut off on a slow link.
const downloadTimeout = 10 * time.Minute

// releaseDownload is where the files of one named release are, at a source
// laid out as GitHub's is.
const releaseDownload = "/download/v"

// ReleaseFiles names the files of one release at a release source.
type ReleaseFiles struct {
	base string // ends in "/"
}

// FilesOf is where the files of release v are at rawSource. v is a parsed
// Version, so nothing reaches the URL but digits.
func FilesOf(rawSource string, v Version) (ReleaseFiles, error) {
	src, err := newSource(rawSource)
	if err != nil {
		return ReleaseFiles{}, err
	}
	return ReleaseFiles{base: src.base + releaseDownload + v.String() + "/"}, nil
}

// Checksums is the URL of the release list.
func (f ReleaseFiles) Checksums() string { return f.base + checksumsFile }

// Signature is the URL of the signature over the release list.
func (f ReleaseFiles) Signature() string { return f.base + signatureFile }

// Artifact is the URL of a file the release list names. name comes from
// ParseChecksums, which refuses one holding a path separator.
func (f ReleaseFiles) Artifact(name string) string { return f.base + url.PathEscape(name) }

// Downloader reads release files with the client the check uses: https only,
// never the management listener or a cloud metadata address, and no redirect
// to anything checkFetchURL refuses.
type Downloader struct {
	small httpFetcher
	large *http.Client
}

// NewDownloader builds a Downloader that identifies itself as version.
func NewDownloader(version string) *Downloader {
	large := newClient()
	large.Timeout = downloadTimeout
	return &Downloader{
		small: httpFetcher{client: newClient(), userAgent: "gateon/" + version},
		large: large,
	}
}

// Fetch returns the body of rawURL, refusing one longer than limit.
func (d *Downloader) Fetch(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	return d.small.fetch(ctx, rawURL, limit)
}

// Download copies the body of rawURL into w and refuses one longer than
// limit. What was written before a refusal is the caller's to discard.
func (d *Downloader) Download(ctx context.Context, rawURL string, w io.Writer, limit int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", d.small.userAgent)
	resp, err := d.large.Do(req)
	if err != nil {
		return fmt.Errorf("download release archive: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("the release source answered %d", resp.StatusCode)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fmt.Errorf("download release archive: %w", err)
	}
	if n > limit {
		return fmt.Errorf("%w: the archive is longer than %d bytes", ErrMalformed, limit)
	}
	return nil
}
