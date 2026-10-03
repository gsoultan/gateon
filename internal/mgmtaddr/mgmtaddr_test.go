// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package mgmtaddr

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

// testPort stands in for the management listener's port.
const testPort = 18733

// withPort registers p as the management port for the test.
func withPort(t *testing.T, p int) {
	t.Helper()
	prev := Register(p)
	t.Cleanup(func() { Register(prev) })
}

// hostAddr is an address of one of this host's interfaces that is neither
// loopback nor link-local, or the zero Addr when it has none.
func hostAddr(t *testing.T) netip.Addr {
	t.Helper()
	for _, a := range readHostAddrs() {
		if !a.IsLoopback() && !a.IsLinkLocalUnicast() {
			return a
		}
	}
	return netip.Addr{}
}

// localForms are the ways to write an address the management listener
// answers on (review finding MGMT-N2): loopback in both families, the rest of
// 127/8, the unspecified addresses, a v4-mapped loopback, an empty host, and
// the names that resolve to loopback.
func localForms(t *testing.T, port int) []string {
	t.Helper()
	p := strconv.Itoa(port)
	forms := []string{
		"http://127.0.0.1:" + p, "http://127.0.0.2:" + p + "/x", "http://[::1]:" + p,
		"http://0.0.0.0:" + p, "http://[::]:" + p, "http://[::ffff:127.0.0.1]:" + p,
		"http://:" + p, "http://localhost:" + p, "h2c://localhost:" + p, "https://127.0.0.1:" + p,
		"h2://[::1]:" + p, "tcp://127.0.0.1:" + p, "127.0.0.1:" + p, "localhost:" + p,
		"  HTTP://LOCALHOST:" + p + "  ",
	}
	if a := hostAddr(t); a.IsValid() {
		forms = append(forms, "http://"+netip.AddrPortFrom(a, uint16(port)).String())
	}
	return forms
}

func TestCheckTargetRefusesEveryLocalFormOfTheManagementAddress(t *testing.T) {
	withPort(t, testPort)
	for _, target := range localForms(t, testPort) {
		err := CheckTarget(context.Background(), target)
		if err == nil {
			t.Errorf("target %q was accepted; it connects to the management listener", target)
			continue
		}
		if !strings.Contains(err.Error(), strings.TrimSpace(target)) {
			t.Errorf("refusal %q does not name the target %q", err, target)
		}
	}
}

func TestCheckTargetAcceptsWhatDoesNotReachTheManagementListener(t *testing.T) {
	withPort(t, testPort)
	p := strconv.Itoa(testPort)
	for _, target := range []string{
		"http://127.0.0.1:" + strconv.Itoa(testPort+1), // another port on loopback
		"http://192.0.2.10:" + p,                       // the port on another host
		"udp://127.0.0.1:" + p,                         // UDP never reaches the TCP listener
		"h3://127.0.0.1:" + p,
		"http://127.0.0.1", // port 80
		"not a target",
	} {
		if err := CheckTarget(context.Background(), target); err != nil {
			t.Errorf("target %q was refused: %v", target, err)
		}
	}
	withPort(t, 0) // no listener: nothing is refused
	if err := CheckTarget(context.Background(), "http://127.0.0.1:"+p); err != nil {
		t.Errorf("with no management listener registered, a target was refused: %v", err)
	}
}

// TestCheckTargetUsesTheSchemesDefaultPort: a URL that names no port connects
// to its scheme's, which can be the management port.
func TestCheckTargetUsesTheSchemesDefaultPort(t *testing.T) {
	withPort(t, 80)
	for _, target := range []string{"http://127.0.0.1", "h2c://localhost/", "ws://[::1]"} {
		if CheckTarget(context.Background(), target) == nil {
			t.Errorf("target %q connects to port 80, the management port, and was accepted", target)
		}
	}
	if err := CheckTarget(context.Background(), "https://127.0.0.1"); err != nil {
		t.Errorf("https://127.0.0.1 connects to 443, not the management port 80, and was refused: %v", err)
	}
}

func TestControlRefusesAConnectionToTheManagementListener(t *testing.T) {
	withPort(t, testPort)
	p := strconv.Itoa(testPort)
	refused := []string{"127.0.0.1:" + p, "[::1]:" + p, "0.0.0.0:" + p, "[::ffff:127.0.0.1]:" + p, "127.9.9.9:" + p}
	if a := hostAddr(t); a.IsValid() {
		refused = append(refused, netip.AddrPortFrom(a, testPort).String())
		if a.Is4() { // written v4-mapped, as a dual-stack socket reports it
			refused = append(refused, netip.AddrPortFrom(netip.AddrFrom16(a.As16()), testPort).String())
		}
	}
	for _, addr := range refused {
		if err := Control("tcp4", addr, nil); !errors.Is(err, ErrManagementListener) {
			t.Errorf("Control(tcp4, %s) = %v, want ErrManagementListener", addr, err)
		}
	}
	for _, c := range []struct{ network, addr string }{
		{"tcp", "127.0.0.1:" + strconv.Itoa(testPort+1)},
		{"tcp", "192.0.2.10:" + p},
		{"udp", "127.0.0.1:" + p},
	} {
		if err := Control(c.network, c.addr, nil); err != nil {
			t.Errorf("Control(%s, %s) = %v, want nil", c.network, c.addr, err)
		}
	}
}

// TestADialerWithControlCannotReachTheListener drives the hook the way the
// proxy does, through net.Dialer, at a real listener registered as the
// management one -- by a name, so the refusal is decided on the resolved
// address.
func TestADialerWithControlCannotReachTheListener(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	unregister := RegisterListener(l.Addr())
	defer unregister()
	d := net.Dialer{Control: Control}
	addr := net.JoinHostPort("localhost", strconv.Itoa(l.Addr().(*net.TCPAddr).Port))
	if c, err := d.DialContext(context.Background(), "tcp", addr); !errors.Is(err, ErrManagementListener) {
		if c != nil {
			_ = c.Close()
		}
		t.Fatalf("dial %s = %v, want ErrManagementListener", addr, err)
	}
	unregister()
	if Port() != 0 {
		t.Fatalf("after unregister the management port is %d, want 0", Port())
	}
}

// TestControlDoesNotAllocate: it runs on every backend connection.
func TestControlDoesNotAllocate(t *testing.T) {
	withPort(t, testPort)
	if n := testing.AllocsPerRun(100, func() { _ = Control("tcp4", "192.0.2.10:8443", nil) }); n != 0 {
		t.Errorf("Control allocated %.0f times per connection to another port", n)
	}
	if n := testing.AllocsPerRun(100, func() { _ = Control("tcp4", "192.0.2.10:18733", nil) }); n != 0 {
		t.Errorf("Control allocated %.0f times per connection to the management port on another host", n)
	}
}

// BenchmarkControl is the hook's cost on a backend connection: another port
// (every connection but one to the management port's number), and the
// management port on another host (an interface lookup, cached).
func BenchmarkControl(b *testing.B) {
	prev := Register(testPort)
	defer Register(prev)
	for _, c := range []struct{ name, addr string }{
		{"other-port", "192.0.2.10:8443"},
		{"mgmt-port-remote-host", "192.0.2.10:" + strconv.Itoa(testPort)},
	} {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = Control("tcp4", c.addr, nil)
			}
		})
	}
}
