package proxy

import (
	"net/url"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type targetState struct {
	url                  string
	parsedURL            *url.URL // pre-parsed to avoid per-request url.Parse
	cacheKey             string   // pre-computed proxy cache key (scheme://host/path)
	transportScheme      string
	transportKey         string
	proxyProtocolEnabled bool
	proxyProtocolVersion gateonv1.ProxyProtocolVersion
	weight               int32
	alive                bool
	requestCount         uint64
	errorCount           uint64
	latencySumMs         uint64
	activeConn           int32
}

func newTargetState(rawURL string, weight int32) *targetState {
	return newTargetStateWithProxy(rawURL, weight, false, gateonv1.ProxyProtocolVersion_PROXY_PROTOCOL_VERSION_UNSPECIFIED)
}

func newTargetStateWithProxy(rawURL string, weight int32, proxyEnabled bool, proxyVersion gateonv1.ProxyProtocolVersion) *targetState {
	ts := &targetState{
		url:                  rawURL,
		alive:                true,
		weight:               weight,
		proxyProtocolEnabled: proxyEnabled,
		proxyProtocolVersion: proxyVersion,
	}
	if parsed, err := url.Parse(rawURL); err == nil {
		ts.transportScheme = parsed.Scheme
		// Normalize scheme for proxy cache key
		normalized := *parsed
		switch normalized.Scheme {
		case "h2c":
			normalized.Scheme = "http"
		case "h2", "h3":
			normalized.Scheme = "https"
		}
		ts.parsedURL = &normalized
		ts.cacheKey = normalized.Scheme + "://" + normalized.Host + normalized.Path
		ts.transportKey = normalized.Scheme + "|" + ts.transportScheme + "|" + rawURL
		if ts.proxyProtocolEnabled {
			ts.transportKey += "|pp:" + ts.proxyProtocolVersion.String()
		}
	}
	return ts
}

func newTargetStateFromTarget(target *gateonv1.Target) *targetState {
	if target == nil {
		return newTargetState("", 1)
	}
	return newTargetStateWithProxy(target.Url, target.Weight, target.ProxyProtocolEnabled, target.ProxyProtocolVersion)
}
