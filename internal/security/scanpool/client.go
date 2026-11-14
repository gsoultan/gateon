// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package scanpool

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
)

const (
	// dialTimeout bounds connecting to a scanner, inside the scan's deadline.
	dialTimeout = 2 * time.Second
	// chunkSize is how much of a file one INSTREAM chunk carries. clamd
	// refuses a chunk larger than its StreamMaxLength; this is far below any
	// value that would be configured.
	chunkSize = 32 << 10
	// maxReplyBytes bounds the one line read back. A verdict is a signature
	// name and a word.
	maxReplyBytes = 1024
	// maxQuotedReply is how much of an unexpected reply an error repeats.
	maxQuotedReply = 120

	schemeTCP  = "tcp"
	schemeUnix = "unix"

	instreamCommand = "nINSTREAM\n"
	pingCommand     = "nPING\n"
	pongReply       = "PONG"
	replyPrefix     = "stream: "
	replyClean      = "stream: OK"
	suffixFound     = " FOUND"
	suffixError     = " ERROR"
)

// Verdict is what a scanner said about one file.
type Verdict struct {
	// Found is true when the scanner named a signature.
	Found bool
	// Signature is the name it gave, empty when Found is false.
	Signature string
}

// errWorkerFault marks a failure that says something about the scanner and
// nothing about the file: it could not be reached, it hung up, or what it
// sent back was not a verdict. See Pool.Scan for why the distinction matters.
var errWorkerFault = errors.New("scanner fault")

// ErrNotScanned is returned when clamd answered, and its answer was that it
// could not scan this file.
var ErrNotScanned = errors.New("the scanner could not scan the file")

func workerFault(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errWorkerFault, fmt.Sprintf(format, args...))
}

// endpoint is a scanner address split into what net.Dial takes.
type endpoint struct {
	network, address string
}

// parseEndpoint reads an address the way the gateway always has: tcp://host:port,
// unix:///path, and anything else as the path of a unix socket.
func parseEndpoint(addr string) (endpoint, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return endpoint{}, fmt.Errorf("scanner address %q: %w", addr, err)
	}
	switch u.Scheme {
	case schemeTCP:
		if u.Host == "" {
			return endpoint{}, fmt.Errorf("scanner address %q has no host", addr)
		}
		return endpoint{schemeTCP, u.Host}, nil
	case schemeUnix:
		return endpoint{schemeUnix, u.Path}, nil
	default:
		return endpoint{schemeUnix, addr}, nil
	}
}

// dial connects to the scanner and puts the scan's deadline on the
// connection, so no read or write on it can outlive the scan. Closing the
// connection when ctx ends is what interrupts one in progress.
func (e endpoint) dial(ctx context.Context, deadline time.Time) (net.Conn, func() bool, error) {
	d := net.Dialer{Timeout: dialTimeout, Deadline: deadline}
	conn, err := d.DialContext(ctx, e.network, e.address)
	if err != nil {
		// A dial that ctx ended is the caller leaving, not the scanner
		// failing: report the cancellation itself so the caller can tell
		// the two apart and the scanner keeps its health.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, fmt.Errorf("connect: %w", ctxErr)
		}
		return nil, nil, workerFault("connect: %v", err)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, nil, workerFault("set deadline: %v", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	return conn, stop, nil
}

// scan sends content to the scanner as one INSTREAM and returns its verdict.
func (e endpoint) scan(ctx context.Context, content []byte, deadline time.Time) (Verdict, error) {
	conn, stop, err := e.dial(ctx, deadline)
	if err != nil {
		return Verdict{}, err
	}
	defer func() {
		stop()
		_ = conn.Close()
	}()

	sendErr := sendInstream(conn, content)
	line, readErr := readLine(conn)
	if err := ctx.Err(); err != nil {
		return Verdict{}, err
	}
	// A scanner that refuses a stream part-way says why and hangs up, so the
	// send fails and the reason is in the reply: read it before reporting.
	if readErr == nil {
		return parseVerdict(line)
	}
	if isTimeout(readErr) && sendErr == nil {
		// Everything was delivered and no verdict came inside the deadline.
		// How long a file takes to scan is the file's doing as much as the
		// scanner's, so this is not a fault of the scanner.
		return Verdict{}, fmt.Errorf("no verdict before the scan deadline: %w", context.DeadlineExceeded)
	}
	if sendErr != nil {
		return Verdict{}, workerFault("send: %v", sendErr)
	}
	return Verdict{}, workerFault("no verdict: %v", readErr)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// sendInstream writes the command, the content in length-prefixed chunks and
// the zero-length chunk that ends the stream.
func sendInstream(conn net.Conn, content []byte) error {
	w := bufio.NewWriterSize(conn, 4096)
	if _, err := w.WriteString(instreamCommand); err != nil {
		return err
	}
	var size [4]byte
	for len(content) > 0 {
		n := min(len(content), chunkSize)
		binary.BigEndian.PutUint32(size[:], uint32(n))
		if _, err := w.Write(size[:]); err != nil {
			return err
		}
		if _, err := w.Write(content[:n]); err != nil {
			return err
		}
		content = content[n:]
	}
	if _, err := w.Write([]byte{0, 0, 0, 0}); err != nil {
		return err
	}
	return w.Flush()
}

// readLine reads one newline-terminated line of at most maxReplyBytes. A reply
// that ends without its newline is not a line: a verdict cut short is not a
// verdict.
func readLine(conn net.Conn) (string, error) {
	r := bufio.NewReaderSize(io.LimitReader(conn, maxReplyBytes), maxReplyBytes)
	line, err := r.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) {
			return "", io.ErrUnexpectedEOF
		}
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// parseVerdict reads clamd's reply to INSTREAM. Exactly "stream: OK" is clean
// and "stream: <name> FOUND" is a detection. A reply ending in ERROR is clamd
// saying it did not scan the file. Anything else did not come from clamd.
//
// The reply used to be searched for FOUND and everything else taken as clean,
// which forwarded a file clamd had refused to scan, and every file when the
// address was not a clamd at all.
func parseVerdict(line string) (Verdict, error) {
	if line == replyClean {
		return Verdict{}, nil
	}
	if name, ok := strings.CutSuffix(line, suffixFound); ok {
		if name, ok = strings.CutPrefix(name, replyPrefix); ok && name != "" {
			return Verdict{Found: true, Signature: name}, nil
		}
	}
	if strings.HasSuffix(line, suffixError) {
		return Verdict{}, fmt.Errorf("%w: %s", ErrNotScanned, quoteReply(line))
	}
	return Verdict{}, workerFault("unexpected reply %s", quoteReply(line))
}

// quoteReply is a reply made safe to put in an error or a log line: bounded
// and quoted, since it is whatever the other end chose to send.
func quoteReply(line string) string {
	if len(line) > maxQuotedReply {
		line = line[:maxQuotedReply]
	}
	return fmt.Sprintf("%q", line)
}

// ping asks the scanner whether it is there. It is the cheap check: it proves
// a clamd is listening, not that it detects anything.
func (e endpoint) ping(ctx context.Context, deadline time.Time) error {
	conn, stop, err := e.dial(ctx, deadline)
	if err != nil {
		return err
	}
	defer func() {
		stop()
		_ = conn.Close()
	}()
	if _, err := io.WriteString(conn, pingCommand); err != nil {
		return workerFault("send: %v", err)
	}
	line, err := readLine(conn)
	if err != nil {
		return workerFault("no reply: %v", err)
	}
	if line != pongReply {
		return workerFault("unexpected reply %s", quoteReply(line))
	}
	return nil
}
