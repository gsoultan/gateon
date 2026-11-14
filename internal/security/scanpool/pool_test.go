// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package scanpool

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

const scanTimeout = 5 * time.Second

func mustPool(t *testing.T, scanners ...*fakeClamd) *Pool {
	t.Helper()
	addrs := make([]string, len(scanners))
	for i, s := range scanners {
		addrs[i] = s.addr
	}
	p, err := New(addrs)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func healthOf(t *testing.T, p *Pool, s *fakeClamd) bool {
	t.Helper()
	for _, w := range p.Status() {
		if w.Addr == s.addr {
			return w.Healthy
		}
	}
	t.Fatalf("no status for %s", s.addr)
	return false
}

func TestAFileArrivesWholeAndItsVerdictIsRead(t *testing.T) {
	// Larger than one chunk and not a multiple of it, so the split, the last
	// short chunk and the terminator are all on the wire.
	file := bytes.Repeat([]byte("0123456789abcdef"), (3*chunkSize+1000)/16)
	s := newFakeClamd(t, answers(clean))
	verdict, err := mustPool(t, s).Scan(t.Context(), file, scanTimeout)
	if err != nil || verdict.Found {
		t.Fatalf("clean file: verdict %+v, err %v", verdict, err)
	}
	if got := s.files(); len(got) != 1 || !bytes.Equal(got[0], file) {
		t.Fatalf("the scanner did not receive the file as sent (%d files)", len(got))
	}

	s.become(answers(eicar))
	verdict, err = mustPool(t, s).Scan(t.Context(), []byte("x"), scanTimeout)
	if err != nil || !verdict.Found || verdict.Signature != "Win.Test.EICAR_HDB-1" {
		t.Fatalf("infected file: verdict %+v, err %v", verdict, err)
	}

	verdict, err = mustPool(t, newFakeClamd(t, answers(clean))).Scan(t.Context(), nil, scanTimeout)
	if err != nil || verdict.Found {
		t.Fatalf("empty file: verdict %+v, err %v", verdict, err)
	}
}

// One scanner down: the file is scanned on the other, the caller sees a
// verdict and not the failure, and after two faults the dead one is passed
// over without being tried.
func TestOneScannerDownIsScannedOnTheOther(t *testing.T) {
	down, up := newFakeClamd(t, hangsUp), newFakeClamd(t, answers(clean))
	p := mustPool(t, down, up)

	for i := range faultThreshold {
		if _, err := p.Scan(t.Context(), []byte("f"), scanTimeout); err != nil {
			t.Fatalf("scan %d with one scanner up: %v", i, err)
		}
	}
	if healthOf(t, p, down) || !healthOf(t, p, up) {
		t.Fatalf("status after %d faults: %+v", faultThreshold, p.Status())
	}
	tried := down.accepted.Load()
	for range 5 {
		if _, err := p.Scan(t.Context(), []byte("f"), scanTimeout); err != nil {
			t.Fatalf("scan with one scanner unhealthy: %v", err)
		}
	}
	if got := down.accepted.Load(); got != tried {
		t.Errorf("the unhealthy scanner was tried %d more times", got-tried)
	}
}

// All scanners down: the caller gets the error, to refuse or forward by its
// own setting. The pool keeps trying, so the one that comes back is used by
// the next scan and nothing has to be restarted.
func TestAllScannersDownIsAnErrorAndARecoveryIsNoticed(t *testing.T) {
	a, b := newFakeClamd(t, hangsUp), newFakeClamd(t, hangsUp)
	p := mustPool(t, a, b)
	for range 3 {
		if _, err := p.Scan(t.Context(), []byte("f"), scanTimeout); !errors.Is(err, errWorkerFault) {
			t.Fatalf("err = %v, want a scanner fault", err)
		}
	}
	if healthOf(t, p, a) || healthOf(t, p, b) {
		t.Fatalf("status with both down: %+v", p.Status())
	}

	a.become(answers(clean))
	b.become(answers(clean))
	if _, err := p.Scan(t.Context(), []byte("f"), scanTimeout); err != nil {
		t.Fatalf("scan after both came back: %v", err)
	}
	if !healthOf(t, p, a) && !healthOf(t, p, b) {
		t.Fatalf("neither scanner rejoined: %+v", p.Status())
	}
}

// An unhealthy scanner is tried again once its window has passed, and one
// good scan puts it back.
func TestAnUnhealthyScannerIsRetriedAfterItsWindow(t *testing.T) {
	flaky, steady := newFakeClamd(t, hangsUp), newFakeClamd(t, answers(clean))
	p := mustPool(t, flaky, steady)
	clock := time.Now()
	p.now = func() time.Time { return clock }

	for range faultThreshold {
		_, _ = p.Scan(t.Context(), []byte("f"), scanTimeout)
	}
	if healthOf(t, p, flaky) {
		t.Fatal("the scanner was not marked unhealthy")
	}
	flaky.become(answers(clean))
	clock = clock.Add(retryAfter + time.Second)
	if !healthOf(t, p, flaky) {
		t.Fatal("the scanner is still passed over after its window")
	}
}

// What a client sends must not be able to take a scanner out of rotation. A
// file clamd cannot scan and a file that takes longer than the deadline are
// both the file's doing: neither counts against the scanner, and neither is
// sent to a second scanner to fail there too.
func TestWhatTheFileCausesIsNotHeldAgainstTheScanner(t *testing.T) {
	for _, tc := range []struct {
		name    string
		behave  func(*fakeClamd, net.Conn)
		timeout time.Duration
		want    error
	}{
		{"clamd refuses the stream", answers("INSTREAM size limit exceeded. ERROR\n"), scanTimeout, ErrNotScanned},
		{"clamd cannot read the file", answers("stream: Can't allocate memory ERROR\n"), scanTimeout, ErrNotScanned},
		{"no verdict inside the deadline", readsAndNeverAnswers, 150 * time.Millisecond, context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first, other := newFakeClamd(t, tc.behave), newFakeClamd(t, tc.behave)
			p := mustPool(t, first, other)
			for range faultThreshold + 1 {
				verdict, err := p.Scan(t.Context(), []byte("f"), tc.timeout)
				if !errors.Is(err, tc.want) || verdict.Found {
					t.Fatalf("verdict %+v, err %v, want %v", verdict, err, tc.want)
				}
				if errors.Is(err, errWorkerFault) {
					t.Fatalf("counted as a scanner fault: %v", err)
				}
			}
			if !healthOf(t, p, first) || !healthOf(t, p, other) {
				t.Errorf("a scanner was marked unhealthy: %+v", p.Status())
			}
			if n := first.accepted.Load() + other.accepted.Load(); n != faultThreshold+1 {
				t.Errorf("%d connections for %d scans: the file was retried elsewhere", n, faultThreshold+1)
			}
		})
	}
}

// A reply that is not a verdict is never clean, and is the scanner's fault.
func TestAReplyThatIsNotAVerdictIsAFault(t *testing.T) {
	for _, reply := range []string{
		"", "stream: OK", "stream: OK \n", "stream: OK but\n", "OK\n", " FOUND\n", "stream:  FOUND\n",
		"other: Eicar FOUND\n", "HTTP/1.1 400 Bad Request\n", "PONG\n", strings.Repeat("A", 4*maxReplyBytes) + "\n",
	} {
		s := newFakeClamd(t, answers(reply))
		verdict, err := mustPool(t, s).Scan(t.Context(), []byte("f"), scanTimeout)
		if !errors.Is(err, errWorkerFault) || verdict.Found {
			t.Errorf("reply %.40q: verdict %+v, err %v, want a scanner fault", reply, verdict, err)
		}
		if err != nil && len(err.Error()) > 400 {
			t.Errorf("reply %.40q: a %d-byte error repeats the reply unbounded", reply, len(err.Error()))
		}
	}
}

// A scanner that accepts the connection and stops reading must not hold the
// request past its deadline. The client this replaces set no deadline on its
// writes, so a file larger than the socket buffers blocked there for good,
// holding one of the route's scan slots each time.
func TestAScannerThatStopsReadingCannotHoldAScanPastItsDeadline(t *testing.T) {
	p := mustPool(t, newFakeClamd(t, neverReads))
	file := make([]byte, 32<<20)
	const timeout = 300 * time.Millisecond

	start := time.Now()
	_, err := p.Scan(t.Context(), file, timeout)
	if err == nil {
		t.Fatal("a scan nobody read returned a verdict")
	}
	if took := time.Since(start); took > 10*timeout {
		t.Errorf("the scan took %s against a %s deadline", took, timeout)
	}
}

// A client that goes away ends its scan at once, and that is not the
// scanner's fault either.
func TestACancelledRequestEndsItsScan(t *testing.T) {
	s := newFakeClamd(t, readsAndNeverAnswers)
	p := mustPool(t, s)
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := p.Scan(ctx, []byte("f"), time.Hour)
		result <- err
	}()
	<-s.sawConn
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if !healthOf(t, p, s) {
		t.Error("a cancelled request was held against the scanner")
	}
}

func TestTheLeastBusyHealthyScannerIsChosen(t *testing.T) {
	p, err := New([]string{"tcp://127.0.0.1:1", "tcp://127.0.0.1:2", "tcp://127.0.0.1:3"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	p.workers[0].inFlight.Store(3)
	p.workers[1].inFlight.Store(1)
	p.workers[2].inFlight.Store(0)
	p.workers[2].passOverUntil.Store(now.Add(time.Minute).UnixNano())
	if got := p.pick(now, nil); got != p.workers[1] {
		t.Errorf("picked %s, want the least busy healthy scanner", got.addr)
	}
	if got := p.pick(now, p.workers[1]); got != p.workers[0] {
		t.Errorf("picked %s for the retry, want the other healthy scanner", got.addr)
	}
	p.workers[0].passOverUntil.Store(now.Add(time.Second).UnixNano())
	p.workers[1].passOverUntil.Store(now.Add(time.Hour).UnixNano())
	if got := p.pick(now, nil); got != p.workers[0] {
		t.Errorf("with none healthy picked %s, want the one due back first", got.addr)
	}
	if got := p.pick(now, p.workers[0]); got == nil || got == p.workers[0] {
		t.Error("the retry was offered the scanner already tried, or none")
	}
}

func TestAPoolIsBoundedAndItsAddressesAreRead(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, ErrNoScanners) {
		t.Errorf("no addresses: %v", err)
	}
	many := make([]string, MaxWorkers+1)
	for i := range many {
		many[i] = "tcp://127.0.0.1:3310"
	}
	if _, err := New(many); err == nil {
		t.Errorf("%d addresses were accepted", len(many))
	}
	if _, err := New(many[:MaxWorkers]); err != nil {
		t.Errorf("%d addresses refused: %v", MaxWorkers, err)
	}
	for _, bad := range []string{"tcp://", "tcp://%zz"} {
		if _, err := New([]string{bad}); err == nil {
			t.Errorf("address %q was accepted", bad)
		}
	}
	for addr, want := range map[string]endpoint{
		"tcp://10.0.0.5:3310":          {schemeTCP, "10.0.0.5:3310"},
		"unix:///run/clamav/clamd.ctl": {schemeUnix, "/run/clamav/clamd.ctl"},
		"/run/clamav/clamd.ctl":        {schemeUnix, "/run/clamav/clamd.ctl"},
	} {
		if got, err := parseEndpoint(addr); err != nil || got != want {
			t.Errorf("parseEndpoint(%q) = %+v, %v, want %+v", addr, got, err, want)
		}
	}
}

// A scanner that accepts and never answers cannot be caught by scans, by
// design. Probe is what catches it, and what brings a scanner back.
func TestProbeFindsAScannerThatScansCannot(t *testing.T) {
	silent, alive := newFakeClamd(t, readsAndNeverAnswers), newFakeClamd(t, pongs)
	p := mustPool(t, silent, alive)
	for range faultThreshold {
		p.Probe(t.Context(), 150*time.Millisecond)
	}
	if healthOf(t, p, silent) || !healthOf(t, p, alive) {
		t.Fatalf("status after probing: %+v", p.Status())
	}
	silent.become(pongs)
	p.Probe(t.Context(), scanTimeout)
	if !healthOf(t, p, silent) {
		t.Error("a scanner that answers again was not brought back")
	}
}

// A request that is already gone when its scan starts must say so, not blame
// the scanner. The dial is where that cancellation lands, and it used to be
// reported as a connect fault with the cause flattened to text, so the caller
// saw "scanner fault" for a client that had simply left. The test above hit
// this whenever its cancel fell between clamd accepting the connection and
// the client's dial returning; starting cancelled reaches the same path
// every time.
func TestARequestCancelledBeforeItsDialIsNotAScannerFault(t *testing.T) {
	s := newFakeClamd(t, readsAndNeverAnswers)
	p := mustPool(t, s)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := p.Scan(ctx, []byte("f"), time.Hour)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if errors.Is(err, errWorkerFault) {
		t.Errorf("err = %v: a cancelled dial was reported as the scanner's fault", err)
	}
	if !healthOf(t, p, s) {
		t.Error("a cancelled request was held against the scanner")
	}
}
