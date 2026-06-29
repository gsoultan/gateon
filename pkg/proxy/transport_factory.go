package proxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

const clientRemoteAddrContextKey contextKey = 1

type backendTransportFactory struct {
	tlsConfig        *tls.Config
	transportConfig  *TransportConfig
	identitySelector *tlsClientIdentitySelector
	cache            sync.Map
}

func newBackendTransportFactory(tlsConfig *tls.Config, transportConfig *TransportConfig, identitySelector *tlsClientIdentitySelector) *backendTransportFactory {
	return &backendTransportFactory{
		tlsConfig:        tlsConfig,
		transportConfig:  transportConfig,
		identitySelector: identitySelector,
	}
}

func (f *backendTransportFactory) HealthCheckTransport() http.RoundTripper {
	if v, ok := f.cache.Load("__healthcheck"); ok {
		return v.(http.RoundTripper)
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = f.tlsConfig
	if v, loaded := f.cache.LoadOrStore("__healthcheck", t); loaded {
		return v.(http.RoundTripper)
	}
	return t
}

func (f *backendTransportFactory) TransportFor(state *targetState, req *http.Request) http.RoundTripper {
	if state == nil {
		return f.HealthCheckTransport()
	}

	selectedIdentity := (*tlsClientIdentity)(nil)
	cacheKey := state.transportKey
	if f.identitySelector != nil {
		selectedIdentity = f.identitySelector.Select(req)
		if selectedIdentity != nil {
			cacheKey += "|cert:" + selectedIdentity.id
		}
	}

	if v, ok := f.cache.Load(cacheKey); ok {
		return v.(http.RoundTripper)
	}

	rt := f.buildTransport(state, selectedIdentity)
	if v, loaded := f.cache.LoadOrStore(cacheKey, rt); loaded {
		return v.(http.RoundTripper)
	}
	return rt
}

func (f *backendTransportFactory) Close() {
	if f == nil {
		return
	}
	f.cache.Range(func(_, value any) bool {
		if c, ok := value.(interface{ CloseIdleConnections() }); ok {
			c.CloseIdleConnections()
		}
		if c, ok := value.(interface{ Close() error }); ok {
			_ = c.Close()
		}
		return true
	})
}

func (f *backendTransportFactory) buildTransport(state *targetState, selectedIdentity *tlsClientIdentity) http.RoundTripper {
	if state == nil {
		return f.HealthCheckTransport()
	}

	scheme := strings.ToLower(state.transportScheme)
	if scheme == "" && state.parsedURL != nil {
		scheme = strings.ToLower(state.parsedURL.Scheme)
	}

	tlsCfg := cloneTLSConfigWithIdentity(f.tlsConfig, selectedIdentity)

	proxyProtocolEnabled := state.proxyProtocolEnabled
	if proxyProtocolEnabled && (scheme == "h2" || scheme == "h2c" || scheme == "h3") {
		logger.L.LogWarn("proxy protocol is only supported for HTTP/1 backends; disabling for this target",
			"target", state.url,
			"scheme", scheme)
		proxyProtocolEnabled = false
	}

	switch scheme {
	case "h3":
		return &http3.Transport{TLSClientConfig: tlsCfg}
	case "h2c":
		return &http2.Transport{
			AllowHTTP:       true,
			ReadIdleTimeout: 30 * time.Second,
			PingTimeout:     15 * time.Second,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				var d net.Dialer
				conn, err := d.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				return conn, nil
			},
		}
	case "h2":
		return &http2.Transport{
			TLSClientConfig: tlsCfg,
			ReadIdleTimeout: 30 * time.Second,
			PingTimeout:     15 * time.Second,
		}
	default:
		t := http.DefaultTransport.(*http.Transport).Clone()
		tc := f.transportConfig
		if tc == nil {
			tc = &TransportConfig{}
		}
		t.MaxIdleConns = tc.maxIdleConns()
		t.MaxIdleConnsPerHost = tc.maxIdleConnsPerHost()
		t.IdleConnTimeout = tc.idleConnTimeout()
		t.ResponseHeaderTimeout = 1 * time.Minute
		t.ExpectContinueTimeout = 1 * time.Second
		t.ForceAttemptHTTP2 = !proxyProtocolEnabled
		t.TLSClientConfig = tlsCfg

		if proxyProtocolEnabled {
			t.DisableKeepAlives = true
			t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				conn, err := d.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				if err := writeProxyHeaderByAddr(conn, clientRemoteAddrFromContext(ctx), conn.RemoteAddr(), state.proxyProtocolVersion); err != nil {
					_ = conn.Close()
					return nil, err
				}
				return conn, nil
			}
		}

		if selectedIdentity != nil && f.identitySelector != nil && f.identitySelector.strategy != gateonv1.TlsClientCertSelectionStrategy_TLS_CLIENT_CERT_SELECTION_STRATEGY_STATIC {
			t.DisableKeepAlives = true
		}

		return t
	}
}

type targetBoundRoundTripper struct {
	state   *targetState
	factory *backendTransportFactory
}

func (t *targetBoundRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.factory.TransportFor(t.state, req).RoundTrip(req)
}

type tlsClientIdentity struct {
	id               string
	certificate      tls.Certificate
	matchHosts       []string
	matchHeader      string
	matchHeaderValue string
}

type tlsClientIdentitySelector struct {
	strategy   gateonv1.TlsClientCertSelectionStrategy
	identities []tlsClientIdentity
}

func newTLSClientIdentitySelector(cfg *gateonv1.TlsClientConfig) (*tlsClientIdentitySelector, error) {
	if cfg == nil || len(cfg.CertIdentities) == 0 {
		return nil, nil
	}

	selector := &tlsClientIdentitySelector{strategy: cfg.CertSelectionStrategy}
	var combinedErr error
	for _, item := range cfg.CertIdentities {
		if item.CertFile == "" || item.KeyFile == "" {
			continue
		}
		certFile := config.ResolvePath(item.CertFile)
		keyFile := config.ResolvePath(item.KeyFile)
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			combinedErr = errors.Join(combinedErr, fmt.Errorf("failed to load tls client identity %q: %w", item.Id, err))
			continue
		}

		hosts := make([]string, 0, len(item.MatchHosts))
		for _, host := range item.MatchHosts {
			norm := normalizeHostForMatch(host)
			if norm != "" {
				hosts = append(hosts, norm)
			}
		}

		selector.identities = append(selector.identities, tlsClientIdentity{
			id:               item.Id,
			certificate:      cert,
			matchHosts:       hosts,
			matchHeader:      http.CanonicalHeaderKey(item.MatchHeader),
			matchHeaderValue: item.MatchHeaderValue,
		})
	}

	if len(selector.identities) == 0 {
		return nil, combinedErr
	}

	return selector, combinedErr
}

func (s *tlsClientIdentitySelector) Select(req *http.Request) *tlsClientIdentity {
	if s == nil || req == nil {
		return nil
	}

	switch s.strategy {
	case gateonv1.TlsClientCertSelectionStrategy_TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HOST:
		host := normalizeHostForMatch(req.Header.Get("X-Forwarded-Host"))
		if host == "" {
			host = normalizeHostForMatch(req.Host)
		}
		if host == "" {
			return nil
		}
		for i := range s.identities {
			if slices.Contains(s.identities[i].matchHosts, host) {
				return &s.identities[i]
			}
		}
	case gateonv1.TlsClientCertSelectionStrategy_TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HEADER:
		for i := range s.identities {
			item := &s.identities[i]
			if item.matchHeader == "" {
				continue
			}
			hv := req.Header.Get(item.matchHeader)
			if hv == "" {
				continue
			}
			if item.matchHeaderValue == "" || hv == item.matchHeaderValue {
				return item
			}
		}
	}

	return nil
}

func cloneTLSConfigWithIdentity(base *tls.Config, selectedIdentity *tlsClientIdentity) *tls.Config {
	// Fail secure: default to a verifying config when no base is supplied.
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if base != nil {
		cfg = base.Clone()
	}
	if selectedIdentity != nil {
		cfg.Certificates = []tls.Certificate{selectedIdentity.certificate}
	}
	return cfg
}

func withClientRemoteAddr(ctx context.Context, remoteAddr string) context.Context {
	if remoteAddr == "" {
		return ctx
	}
	return context.WithValue(ctx, clientRemoteAddrContextKey, remoteAddr)
}

func clientRemoteAddrFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(clientRemoteAddrContextKey).(string)
	return v
}

type proxyBuffer struct {
	data []byte
}

var proxyBufferPool = sync.Pool{
	New: func() any {
		return &proxyBuffer{data: make([]byte, 0, 128)}
	},
}

func normalizeHostForMatch(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	host = httputil.StripPort(host)
	return strings.Trim(host, "[]")
}

func writeProxyHeaderByAddr(conn net.Conn, clientRemoteAddr string, backendAddr net.Addr, version gateonv1.ProxyProtocolVersion) error {
	srcIP, srcPort, srcOK := parseTCPAddr(clientRemoteAddr)
	dstIP, dstPort, dstOK := parseTCPAddrFromNetAddr(backendAddr)
	return writeProxyHeader(conn, srcIP, srcPort, srcOK, dstIP, dstPort, dstOK, version)
}

func writeProxyHeader(conn net.Conn, srcIP net.IP, srcPort uint16, srcOK bool, dstIP net.IP, dstPort uint16, dstOK bool, version gateonv1.ProxyProtocolVersion) error {
	if conn == nil {
		return fmt.Errorf("nil connection")
	}

	if version == gateonv1.ProxyProtocolVersion_PROXY_PROTOCOL_VERSION_UNSPECIFIED {
		version = gateonv1.ProxyProtocolVersion_PROXY_PROTOCOL_VERSION_V1
	}

	switch version {
	case gateonv1.ProxyProtocolVersion_PROXY_PROTOCOL_VERSION_V2:
		return writeProxyHeaderV2(conn, srcIP, srcPort, srcOK, dstIP, dstPort, dstOK)
	default:
		return writeProxyHeaderV1(conn, srcIP, srcPort, srcOK, dstIP, dstPort, dstOK)
	}
}

func writeProxyHeaderV1(conn net.Conn, srcIP net.IP, srcPort uint16, srcOK bool, dstIP net.IP, dstPort uint16, dstOK bool) error {
	if !srcOK || !dstOK {
		_, err := conn.Write([]byte("PROXY UNKNOWN\r\n"))
		return err
	}

	family := "TCP4"
	srcAddr, _ := netip.AddrFromSlice(srcIP)
	srcAddr = srcAddr.Unmap()
	dstAddr, _ := netip.AddrFromSlice(dstIP)
	dstAddr = dstAddr.Unmap()
	if !srcAddr.Is4() || !dstAddr.Is4() {
		family = "TCP6"
	}

	pb := proxyBufferPool.Get().(*proxyBuffer)
	defer proxyBufferPool.Put(pb)

	pb.data = pb.data[:0]
	pb.data = append(pb.data, "PROXY "...)
	pb.data = append(pb.data, family...)
	pb.data = append(pb.data, ' ')
	pb.data = srcAddr.AppendTo(pb.data)
	pb.data = append(pb.data, ' ')
	pb.data = dstAddr.AppendTo(pb.data)
	pb.data = append(pb.data, ' ')
	pb.data = strconv.AppendUint(pb.data, uint64(srcPort), 10)
	pb.data = append(pb.data, ' ')
	pb.data = strconv.AppendUint(pb.data, uint64(dstPort), 10)
	pb.data = append(pb.data, "\r\n"...)

	_, err := conn.Write(pb.data)
	return err
}

func writeProxyHeaderV2(conn net.Conn, srcIP net.IP, srcPort uint16, srcOK bool, dstIP net.IP, dstPort uint16, dstOK bool) error {
	const (
		verCommandProxy = 0x21
		familyUnspec    = 0x00
		familyTCPv4     = 0x11
		familyTCPv6     = 0x21
	)

	sig := [12]byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}
	family := byte(familyUnspec)
	payloadLen := uint16(0)

	var header [52]byte // 16 bytes header + 36 bytes for IPv6 + ports
	copy(header[0:12], sig[:])
	header[12] = verCommandProxy

	if srcOK && dstOK {
		if src4, dst4 := srcIP.To4(), dstIP.To4(); src4 != nil && dst4 != nil {
			family = familyTCPv4
			payloadLen = 12
			copy(header[16:20], src4)
			copy(header[20:24], dst4)
			binary.BigEndian.PutUint16(header[24:26], srcPort)
			binary.BigEndian.PutUint16(header[26:28], dstPort)
		} else {
			src16 := srcIP.To16()
			dst16 := dstIP.To16()
			if src16 != nil && dst16 != nil {
				family = familyTCPv6
				payloadLen = 36
				copy(header[16:32], src16)
				copy(header[32:48], dst16)
				binary.BigEndian.PutUint16(header[48:50], srcPort)
				binary.BigEndian.PutUint16(header[50:52], dstPort)
			}
		}
	}

	header[13] = family
	binary.BigEndian.PutUint16(header[14:16], payloadLen)
	_, err := conn.Write(header[:16+payloadLen])
	return err
}

func parseTCPAddr(raw string) (net.IP, uint16, bool) {
	if raw == "" {
		return nil, 0, false
	}

	var host, port string
	if last := strings.LastIndexByte(raw, ':'); last != -1 && !strings.HasSuffix(raw, "]") {
		host = raw[:last]
		port = raw[last+1:]
	} else {
		host = raw
	}

	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return nil, 0, false
	}

	if port == "" {
		return ip, 0, true
	}

	// Optimization: try numeric port first to avoid expensive net.LookupPort
	if p, err := strconv.ParseUint(port, 10, 16); err == nil {
		return ip, uint16(p), true
	}

	portNum, err := net.LookupPort("tcp", port)
	if err != nil {
		return nil, 0, false
	}

	return ip, uint16(portNum), true
}

func parseTCPAddrFromNetAddr(addr net.Addr) (net.IP, uint16, bool) {
	if addr == nil {
		return nil, 0, false
	}
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.IP, uint16(tcp.Port), true
	}
	return parseTCPAddr(addr.String())
}
