// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build unix

package sockets

import (
	"errors"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
)

// The service manager's side of the protocol (sd_listen_fds(3)).
const (
	envListenPID   = "LISTEN_PID"
	envListenFDs   = "LISTEN_FDS"
	envListenNames = "LISTEN_FDNAMES"
	envNotify      = "NOTIFY_SOCKET"
	// firstFD is where passed descriptors start.
	firstFD = 3
	// maxInherited bounds how many passed descriptors are looked at. The
	// manager is asked to keep MaxStored; this is slack, not a second limit.
	maxInherited = 4 * MaxStored
)

// Inherit takes over the sockets the service manager passed to this process
// and returns the store new ones are handed to. It is called once, before
// anything listens.
func Inherit() *Store {
	fds, names := passedFDs()
	s := inheritFrom(fds, names, newNotifier(os.Getenv(envNotify)))
	// A child process must not take these for its own.
	for _, key := range []string{envListenPID, envListenFDs, envListenNames} {
		_ = os.Unsetenv(key)
	}
	if !enabled() {
		s.DiscardUnclaimed()
		s.mu.Lock()
		s.notify = nil
		s.mu.Unlock()
	}
	return s
}

// enabled is the profile's default unless EnvHandoff says otherwise.
func enabled() bool {
	if on, err := strconv.ParseBool(strings.TrimSpace(os.Getenv(EnvHandoff))); err == nil {
		return on
	}
	return config.CurrentTierDefaults().SocketHandoff
}

// passedFDs is the descriptors the manager says it passed to this process.
func passedFDs() (fds []int, names []string) {
	if pid, err := strconv.Atoi(os.Getenv(envListenPID)); err != nil || pid != os.Getpid() {
		return nil, nil
	}
	n, err := strconv.Atoi(os.Getenv(envListenFDs))
	if err != nil || n <= 0 {
		return nil, nil
	}
	n = min(n, maxInherited)
	names = strings.Split(os.Getenv(envListenNames), ":")
	for i := range n {
		fds = append(fds, firstFD+i)
	}
	return fds, names
}

// Adopt is a store holding fds as if the service manager had passed them
// under names, with no manager to hand new sockets to. It is the part of
// Inherit that does not read the process's environment, for a caller that
// has descriptors from somewhere else: the tests of the listeners.
func Adopt(fds []int, names []string) *Store {
	return inheritFrom(fds, names, nil)
}

// inheritFrom builds a store from descriptors and the manager's names for
// them. A descriptor that is not a listening TCP socket or a UDP socket
// bound to an address is closed and dropped.
func inheritFrom(fds []int, names []string, notify *notifier) *Store {
	s := &Store{notify: notify, kept: make(map[string]bool)}
	for i, fd := range fds {
		name := ""
		if i < len(names) {
			name = names[i]
		}
		s.stored++
		syscall.CloseOnExec(fd)
		in, err := describe(fd, name)
		if err != nil {
			logger.L.LogWarn("the service manager passed a descriptor the gateway cannot listen on; closing it",
				"name", name, "error", err)
			_ = syscall.Close(fd)
			s.dropLocked(name)
			continue
		}
		s.inherited = append(s.inherited, in)
	}
	return s
}

// describe reads what kind of socket fd is and where it is bound, from the
// socket itself.
func describe(fd int, name string) (*inherited, error) {
	kind, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil {
		return nil, err
	}
	in := &inherited{name: name}
	switch kind {
	case syscall.SOCK_STREAM:
		in.network = networkTCP
	case syscall.SOCK_DGRAM:
		in.network = networkUDP
	default:
		return nil, errors.New("neither a stream nor a datagram socket")
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		return nil, err
	}
	switch a := sa.(type) {
	case *syscall.SockaddrInet4:
		in.addr = netip.AddrPortFrom(netip.AddrFrom4(a.Addr), uint16(a.Port)) // #nosec G115 -- a port read from a bound socket
	case *syscall.SockaddrInet6:
		in.addr = netip.AddrPortFrom(netip.AddrFrom16(a.Addr), uint16(a.Port)) // #nosec G115 -- a port read from a bound socket
	default:
		return nil, errors.New("not an IP socket")
	}
	if in.addr.Port() == 0 {
		return nil, errors.New("not bound to a port")
	}
	in.file = os.NewFile(uintptr(fd), name) // #nosec G115 -- a descriptor number
	return in, nil
}

// notifier talks to the service manager's notification socket (sd_notify(3)).
type notifier struct {
	// path is the socket's path, or "@name" for one in the abstract namespace.
	path string
}

// newNotifier is nil when there is no service manager to talk to.
func newNotifier(path string) *notifier {
	if !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "@") {
		return nil
	}
	return &notifier{path: path}
}

// store hands the socket behind raw to the manager under name. FDPOLL=0:
// the manager must keep it until asked to drop it, not until it sees an
// event on it.
func (n *notifier) store(name string, raw syscall.Conn) error {
	rc, err := raw.SyscallConn()
	if err != nil {
		return err
	}
	var sendErr error
	err = rc.Control(func(fd uintptr) {
		sendErr = n.send("FDSTORE=1\nFDPOLL=0\nFDNAME="+name, syscall.UnixRights(int(fd))) // #nosec G115 -- a descriptor number
	})
	return errors.Join(err, sendErr)
}

func (n *notifier) remove(name string) error {
	return n.send("FDSTOREREMOVE=1\nFDNAME="+name, nil)
}

// send writes one datagram to the manager, with rights when a descriptor
// goes with it. A socket per message: there are a handful in a process's
// life, all at its start.
func (n *notifier) send(state string, rights []byte) error {
	// Under the fork lock, as the standard library opens sockets where
	// SOCK_CLOEXEC is not everywhere: a child forked in between must not
	// inherit this one.
	syscall.ForkLock.RLock()
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err == nil {
		syscall.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Close(fd) }()
	return syscall.Sendmsg(fd, []byte(state), rights, &syscall.SockaddrUnix{Name: n.path}, 0)
}
