// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build unix

package sockets

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// manager stands in for the service manager: it receives what a gateway
// sends to its notification socket and holds the descriptors, as systemd's
// file-descriptor store does.
type manager struct {
	t    *testing.T
	conn *net.UnixConn
	path string
	// held is the descriptors stored, by name.
	held map[string][]int
}

func newManager(t *testing.T) *manager {
	t.Helper()
	path := filepath.Join(t.TempDir(), "notify")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	m := &manager{t: t, conn: conn, path: path, held: map[string][]int{}}
	t.Cleanup(func() {
		_ = conn.Close()
		for _, fds := range m.held {
			for _, fd := range fds {
				_ = syscall.Close(fd)
			}
		}
	})
	return m
}

// process reads every message sent so far and applies it to the store.
func (m *manager) process() (messages []string) {
	m.t.Helper()
	buf, oob := make([]byte, 4096), make([]byte, 4096)
	for {
		_ = m.conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, oobn, _, _, err := m.conn.ReadMsgUnix(buf, oob)
		if err != nil {
			return messages
		}
		msg := string(buf[:n])
		messages = append(messages, msg)
		name := field(msg, "FDNAME")
		switch {
		case strings.Contains(msg, "FDSTOREREMOVE=1"):
			for _, fd := range m.held[name] {
				_ = syscall.Close(fd)
			}
			delete(m.held, name)
		case strings.Contains(msg, "FDSTORE=1"):
			m.held[name] = append(m.held[name], rights(m.t, oob[:oobn])...)
		}
	}
}

func field(msg, key string) string {
	for _, line := range strings.Split(msg, "\n") {
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			return v
		}
	}
	return ""
}

func rights(t *testing.T, oob []byte) []int {
	t.Helper()
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		t.Fatal(err)
	}
	var fds []int
	for _, msg := range msgs {
		got, err := syscall.ParseUnixRights(&msg)
		if err != nil {
			t.Fatal(err)
		}
		fds = append(fds, got...)
	}
	return fds
}

// restart is the next process: a store built from what the manager holds,
// passed the way the manager passes it.
func (m *manager) restart() *Store {
	m.t.Helper()
	var fds []int
	var names []string
	for name, held := range m.held {
		for _, fd := range held {
			// The manager keeps its own copy; the process gets a duplicate.
			dup, err := syscall.Dup(fd)
			if err != nil {
				m.t.Fatal(err)
			}
			fds, names = append(fds, dup), append(names, name)
		}
	}
	return inheritFrom(fds, names, newNotifier(m.path))
}

func (m *manager) start() *Store {
	return inheritFrom(nil, nil, newNotifier(m.path))
}

func listen(t *testing.T, s *Store, addr string) net.Listener {
	t.Helper()
	l, err := s.Listen(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// TestAConnectionMadeDuringTheRestartIsServed is the property the package
// exists for. The old process has closed its listener and exited; the new
// one has not started. A client connecting then used to be refused.
func TestAConnectionMadeDuringTheRestartIsServed(t *testing.T) {
	m := newManager(t)
	old := listen(t, m.start(), "127.0.0.1:0")
	addr := old.Addr().String()
	m.process()
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	client, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("a client connecting while no gateway is running: %v", err)
	}
	defer func() { _ = client.Close() }()
	if _, err := client.Write([]byte("GET / during the restart")); err != nil {
		t.Fatal(err)
	}

	next := listen(t, m.restart(), addr)
	if next.Addr().String() != addr {
		t.Fatalf("the new process listens on %s, want %s", next.Addr(), addr)
	}
	_ = next.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
	conn, err := next.Accept()
	if err != nil {
		t.Fatalf("the new process did not find the waiting connection: %v", err)
	}
	defer func() { _ = conn.Close() }()
	got := make([]byte, 24)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "GET / during the restart" {
		t.Fatalf("read %q (%v)", got, err)
	}
	if sent := m.process(); len(sent) != 0 {
		t.Fatalf("an adopted socket was stored a second time: %q", sent)
	}
}

// TestWithoutAManagerARestartStillRefuses is the control for the test
// above: it is the store that keeps the socket open, not the test.
func TestWithoutAManagerARestartStillRefuses(t *testing.T) {
	old := listen(t, inheritFrom(nil, nil, nil), "127.0.0.1:0")
	addr := old.Addr().String()
	_ = old.Close()
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		_ = c.Close()
		t.Fatal("a closed listener with nobody holding it accepted a connection")
	}
	var none *Store
	l := listen(t, none, "127.0.0.1:0")
	if l.Addr().(*net.TCPAddr).Port == 0 {
		t.Fatal("a nil store did not listen")
	}
	none.DiscardUnclaimed()
}

func TestADatagramSentDuringTheRestartIsRead(t *testing.T) {
	m := newManager(t)
	old, err := m.start().ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := old.LocalAddr().String()
	m.process()
	_ = old.Close()

	client, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if _, err := client.Write([]byte("during")); err != nil {
		t.Fatal(err)
	}

	next, err := m.restart().ListenUDP(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = next.Close() }()
	_ = next.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, _, err := next.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "during" {
		t.Fatalf("read %q (%v)", buf[:n], err)
	}
}

// TestASocketIsAdoptedForWhereItIsBoundWhateverItIsCalled: the name is the
// manager's label and nothing the gateway should believe. A socket passed
// under another entrypoint's name must not be served as that entrypoint.
func TestASocketIsAdoptedForWhereItIsBoundWhateverItIsCalled(t *testing.T) {
	m := newManager(t)
	a := listen(t, m.start(), "127.0.0.1:0")
	b := listen(t, m.start(), "127.0.0.1:0")
	m.process()
	nameA, nameB := storeName(networkTCP, a.Addr()), storeName(networkTCP, b.Addr())
	// Swap the labels, as a confused or hostile manager might.
	m.held[nameA], m.held[nameB] = m.held[nameB], m.held[nameA]

	next := m.restart()
	gotA := listen(t, next, a.Addr().String())
	if gotA.Addr().String() != a.Addr().String() {
		t.Fatalf("asked for %s, serving %s", a.Addr(), gotA.Addr())
	}
	// Another address with the same port is another entrypoint.
	_, port, _ := net.SplitHostPort(b.Addr().String())
	if in := next.claim(networkTCP, net.JoinHostPort("127.0.0.2", port)); in != nil {
		t.Fatalf("a socket bound to 127.0.0.1 was handed to a listener on 127.0.0.2: %+v", in)
	}
	// A UDP entrypoint on the same port must not be given the TCP socket.
	in := next.claim(networkUDP, b.Addr().String())
	if in != nil {
		t.Fatalf("a TCP socket was handed to a UDP listener: %+v", in)
	}
}

func TestSameHost(t *testing.T) {
	cases := []struct {
		host, bound string
		want        bool
	}{
		{"", "::", true},
		{"", "0.0.0.0", true},
		{"", "127.0.0.1", false},
		{"0.0.0.0", "0.0.0.0", true},
		// "::" also takes IPv6: not what an IPv4-only entrypoint asked for.
		{"0.0.0.0", "::", false},
		{"127.0.0.1", "127.0.0.1", true},
		{"127.0.0.1", "::ffff:127.0.0.1", true},
		{"127.0.0.1", "127.0.0.2", false},
		{"::1", "::1", true},
		{"localhost", "127.0.0.1", false},
	}
	for _, c := range cases {
		if got := sameHost(c.host, netip.MustParseAddr(c.bound)); got != c.want {
			t.Errorf("sameHost(%q, %s) = %v, want %v", c.host, c.bound, got, c.want)
		}
	}
}

// TestASocketNoEntrypointWantsIsClosedAndDropped: an entrypoint was removed
// or moved to another port. Its old socket, left open, would accept
// connections that nothing ever answers.
func TestASocketNoEntrypointWantsIsClosedAndDropped(t *testing.T) {
	m := newManager(t)
	first := m.start()
	kept := listen(t, first, "127.0.0.1:0")
	gone := listen(t, first, "127.0.0.1:0")
	m.process()
	keptAddr, goneAddr := kept.Addr().String(), gone.Addr().String()
	_, _ = kept.Close(), gone.Close()

	next := m.restart()
	listen(t, next, keptAddr)
	next.DiscardUnclaimed()
	sent := m.process()
	want := "FDSTOREREMOVE=1\nFDNAME=" + storeName(networkTCP, gone.Addr())
	if len(sent) != 1 || sent[0] != want {
		t.Fatalf("the manager was told %q, want %q", sent, want)
	}
	if c, err := net.DialTimeout("tcp", goneAddr, time.Second); err == nil {
		_ = c.Close()
		t.Fatal("the removed entrypoint's port still accepts connections")
	}
	if c, err := net.DialTimeout("tcp", keptAddr, time.Second); err != nil {
		t.Fatalf("the entrypoint still configured was dropped with it: %v", err)
	} else {
		_ = c.Close()
	}
}

// TestADescriptorThatIsNotAListenerIsClosedAndDropped: what arrives in the
// environment is not chosen by this process.
func TestADescriptorThatIsNotAListenerIsClosedAndDropped(t *testing.T) {
	m := newManager(t)
	file, err := os.Create(filepath.Join(t.TempDir(), "not-a-socket"))
	if err != nil {
		t.Fatal(err)
	}
	fileFD, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	unbound, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}

	s := inheritFrom([]int{fileFD, unbound}, []string{"a-file", "unbound"}, newNotifier(m.path))
	if len(s.inherited) != 0 || s.stored != 0 {
		t.Fatalf("inherited %d descriptors, counting %d as stored", len(s.inherited), s.stored)
	}
	for _, fd := range []int{fileFD, unbound} {
		if err := syscall.Close(fd); !errors.Is(err, syscall.EBADF) {
			t.Errorf("descriptor %d was left open (%v)", fd, err)
		}
	}
	sent := strings.Join(m.process(), "|")
	for _, name := range []string{"a-file", "unbound"} {
		if !strings.Contains(sent, "FDSTOREREMOVE=1\nFDNAME="+name) {
			t.Errorf("the manager was not asked to drop %q: %q", name, sent)
		}
	}
}

func TestNoMoreSocketsAreStoredThanTheManagerIsAskedToKeep(t *testing.T) {
	m := newManager(t)
	s := m.start()
	s.stored = MaxStored - 1
	listen(t, s, "127.0.0.1:0")
	listen(t, s, "127.0.0.1:0")
	if sent := m.process(); len(sent) != 1 {
		t.Fatalf("%d sockets stored past a limit that left room for one", len(sent))
	}
}

func TestDescriptorsMeantForAnotherProcessAreNotTaken(t *testing.T) {
	t.Setenv(envListenFDs, "2")
	t.Setenv(envListenNames, "a:b")
	t.Setenv(envListenPID, strconv.Itoa(os.Getpid()+1))
	if fds, _ := passedFDs(); len(fds) != 0 {
		t.Fatalf("took %v from an environment addressed to another process", fds)
	}
	t.Setenv(envListenPID, strconv.Itoa(os.Getpid()))
	fds, names := passedFDs()
	if len(fds) != 2 || fds[0] != firstFD || fds[1] != firstFD+1 || len(names) != 2 {
		t.Fatalf("passedFDs = %v %v", fds, names)
	}
	t.Setenv(envListenFDs, "100000")
	if fds, _ := passedFDs(); len(fds) != maxInherited {
		t.Fatalf("looked at %d descriptors, want the bound of %d", len(fds), maxInherited)
	}
}

func TestTheHandoffIsOnUnlessSwitchedOff(t *testing.T) {
	for value, want := range map[string]bool{"": true, "true": true, "nonsense": true, "false": false, "0": false} {
		t.Setenv(EnvHandoff, value)
		if got := enabled(); got != want {
			t.Errorf("%s=%q: enabled = %v, want %v", EnvHandoff, value, got, want)
		}
	}
	if n := newNotifier(""); n != nil {
		t.Fatal("a notifier was built with no manager to talk to")
	}
	if n := newNotifier("relative/path"); n != nil {
		t.Fatal("a notification socket that is neither a path nor abstract was accepted")
	}
}
