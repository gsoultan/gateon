// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package mgmtaddr

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// TestControlRefusesCloudMetadata (ADR 0077): the dial hook every data-plane
// backend connection carries refuses the metadata service, also while no
// management listener has bound -- the check used to return before looking at
// any address whose port was not the management port.
func TestControlRefusesCloudMetadata(t *testing.T) {
	withPort(t, 0)
	for _, addr := range []string{
		"169.254.169.254:80", "[::ffff:169.254.169.254]:80", "[64:ff9b::a9fe:a9fe]:80",
		"[fd00:ec2::254]:80", "100.100.100.200:80", "169.254.170.2:80", "[fe80::1%eth0]:8080",
	} {
		if err := Control("tcp", addr, nil); !errors.Is(err, ErrCloudMetadata) {
			t.Errorf("Control(tcp, %s) = %v, want ErrCloudMetadata", addr, err)
		}
	}
	for _, addr := range []string{"10.0.0.5:8080", "192.168.1.10:80", "127.0.0.1:9000", "100.64.0.5:80", "[::1]:80"} {
		if err := Control("tcp", addr, nil); err != nil {
			t.Errorf("Control(tcp, %s) = %v, want nil", addr, err)
		}
	}
}

// TestADialerRefusesANameThatResolvesToMetadata drives the hook the way the
// proxy does, through net.Dialer, for a target saved as a name that resolves
// to 169.254.169.254 only when it is dialled. The save-time check never sees
// that address; the dial must refuse it before connect(2).
func TestADialerRefusesANameThatResolvesToMetadata(t *testing.T) {
	withPort(t, 0)
	d := net.Dialer{Control: Control, Resolver: fakeResolver(t, netip.MustParseAddr("169.254.169.254"))}
	c, err := d.DialContext(context.Background(), "tcp4", "innocent.example:80")
	if c != nil {
		_ = c.Close()
	}
	if !errors.Is(err, ErrCloudMetadata) {
		t.Fatalf("dial innocent.example (resolving to 169.254.169.254) = %v, want ErrCloudMetadata", err)
	}
}

// TestControlDoesNotAllocateForMetadataCheck: the metadata check runs on
// every backend connection.
func TestControlDoesNotAllocateForMetadataCheck(t *testing.T) {
	withPort(t, 0)
	if n := testing.AllocsPerRun(100, func() { _ = Control("tcp4", "10.0.0.5:8080", nil) }); n != 0 {
		t.Errorf("Control allocated %.0f times per connection to a private backend", n)
	}
}

// fakeResolver answers every A query with a, from memory: the test needs a
// name that resolves to the metadata address without a network or a hosts
// file.
func fakeResolver(t *testing.T, a netip.Addr) *net.Resolver {
	t.Helper()
	return &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go serveOneDNS(server, a)
		return client, nil
	}}
}

// serveOneDNS reads DNS queries from c, over the TCP framing the Go resolver
// uses on a stream connection, and answers each with a.
func serveOneDNS(c net.Conn, a netip.Addr) {
	defer c.Close()
	for {
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		q := make([]byte, int(l[0])<<8|int(l[1]))
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		var p dnsmessage.Parser
		h, err := p.Start(q)
		if err != nil {
			return
		}
		qs, err := p.AllQuestions()
		if err != nil || len(qs) == 0 {
			return
		}
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true})
		_ = b.StartQuestions()
		_ = b.Question(qs[0])
		_ = b.StartAnswers()
		if qs[0].Type == dnsmessage.TypeA {
			_ = b.AResource(dnsmessage.ResourceHeader{Name: qs[0].Name, Class: dnsmessage.ClassINET, TTL: 60},
				dnsmessage.AResource{A: a.As4()})
		}
		out, err := b.Finish()
		if err != nil {
			return
		}
		if _, err := c.Write(append([]byte{byte(len(out) >> 8), byte(len(out))}, out...)); err != nil {
			return
		}
	}
}
