package proxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"

	"github.com/gsoultan/gateon/internal/config"
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
		logger.L.Warn().
			Str("target", state.url).
			Str("scheme", scheme).
			Msg("proxy protocol is only supported for HTTP/1 backends; disabling for this target")
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
				if err := writeProxyHeader(conn, clientRemoteAddrFromContext(ctx), conn.RemoteAddr(), state.proxyProtocolVersion); err != nil {
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

type targetAwareRoundTripper struct {
	factory *backendTransportFactory
}

func (t *targetAwareRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if t == nil || t.factory == nil {
		return http.DefaultTransport.RoundTrip(req)
	}
	state, _ := req.Context().Value(targetStateContextKey).(*targetState)
	return t.factory.TransportFor(state, req).RoundTrip(req)
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
	cfg := &tls.Config{InsecureSkipVerify: true}
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

func normalizeHostForMatch(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	return strings.Trim(host, "[]")
}

func writeProxyHeader(conn net.Conn, clientRemoteAddr string, backendAddr net.Addr, version gateonv1.ProxyProtocolVersion) error {
	if conn == nil {
		return fmt.Errorf("nil connection")
	}

	srcIP, srcPort, srcOK := parseTCPAddr(clientRemoteAddr)
	dstIP, dstPort, dstOK := parseTCPAddrFromNetAddr(backendAddr)

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
	if srcIP.To4() == nil || dstIP.To4() == nil {
		family = "TCP6"
	}
	line := fmt.Appendf(nil, "PROXY %s %s %s %d %d\r\n", family, srcIP.String(), dstIP.String(), srcPort, dstPort)
	_, err := conn.Write(line)
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
	var payload []byte

	if srcOK && dstOK {
		if src4, dst4 := srcIP.To4(), dstIP.To4(); src4 != nil && dst4 != nil {
			family = familyTCPv4
			payloadLen = 12
			payload = make([]byte, payloadLen)
			copy(payload[0:4], src4)
			copy(payload[4:8], dst4)
			binary.BigEndian.PutUint16(payload[8:10], srcPort)
			binary.BigEndian.PutUint16(payload[10:12], dstPort)
		} else {
			src16 := srcIP.To16()
			dst16 := dstIP.To16()
			if src16 != nil && dst16 != nil {
				family = familyTCPv6
				payloadLen = 36
				payload = make([]byte, payloadLen)
				copy(payload[0:16], src16)
				copy(payload[16:32], dst16)
				binary.BigEndian.PutUint16(payload[32:34], srcPort)
				binary.BigEndian.PutUint16(payload[34:36], dstPort)
			}
		}
	}

	header := make([]byte, 16+len(payload))
	copy(header[0:12], sig[:])
	header[12] = verCommandProxy
	header[13] = family
	binary.BigEndian.PutUint16(header[14:16], payloadLen)
	copy(header[16:], payload)
	_, err := conn.Write(header)
	return err
}

func parseTCPAddr(raw string) (net.IP, uint16, bool) {
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return nil, 0, false
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return nil, 0, false
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
	return parseTCPAddr(addr.String())
}
