// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ebpf

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/gsoultan/gateon/internal/logger"
)

// IPv6 keys, mirroring bpf/xdp_rate_limit.c. Blocking and rate limiting are
// keyed by the /64 an address sits in: an IPv6 client is handed a whole /64 and
// can send from any address in it, so a shun or a limit per address is evaded
// by changing the last 64 bits. The allowlist and telemetry are per address.

// ipv6Key is the address as struct in6_addr keys it: its sixteen bytes, which
// cilium/ebpf marshals as they are.
func ipv6Key(ip net.IP) [16]byte {
	var key [16]byte
	copy(key[:], ip.To16())
	return key
}

// prefix64Key is the /64 an IPv6 address sits in, as the programs key it: the
// first eight bytes, read in the host's order so that cilium/ebpf marshals them
// back unchanged -- the same reasoning as ipToUint32.
func prefix64Key(ip net.IP) uint64 {
	return binary.NativeEndian.Uint64(ip.To16()[:8])
}

// prefix64String names the /64 a prefix64Key came from, for logs.
func prefix64String(key uint64) string {
	ip := make(net.IP, 16)
	binary.NativeEndian.PutUint64(ip[:8], key)
	return (&net.IPNet{IP: ip, Mask: net.CIDRMask(64, 128)}).String()
}

// parseAddress accepts a bare IPv4 or IPv6 address; is4 reports which.
func parseAddress(s string) (ip net.IP, is4 bool, err error) {
	ip = net.ParseIP(s)
	if ip == nil {
		return nil, false, fmt.Errorf("invalid IP: %s", s)
	}
	if v4 := ip.To4(); v4 != nil {
		return v4, true, nil
	}
	return ip, false, nil
}

// shunKey names the map a shun of ip goes into and its key there: the address
// for IPv4, its /64 for IPv6.
func shunKey(s string) (mapName string, key any, err error) {
	ip, is4, err := parseAddress(s)
	if err != nil {
		return "", nil, err
	}
	if is4 {
		k, err := ipToUint32(s)
		return "shunned_ips", k, err
	}
	return "shunned_prefixes6", prefix64Key(ip), nil
}

// limitKey is shunKey for the adaptive rate limits.
func limitKey(s string) (mapName string, key any, err error) {
	ip, is4, err := parseAddress(s)
	if err != nil {
		return "", nil, err
	}
	if is4 {
		k, err := ipToUint32(s)
		return "adaptive_limits", k, err
	}
	return "adaptive_limits6", prefix64Key(ip), nil
}

// allowlist is the management allowlist as the two kernel maps key it.
type allowlist struct {
	v4 map[uint32]struct{}
	v6 map[[16]byte]struct{}
}

func compareIPv6Keys(a, b [16]byte) int { return bytes.Compare(a[:], b[:]) }

func showIPv4Key(k uint32) string   { return uint32ToIP(k).String() }
func showIPv6Key(k [16]byte) string { return net.IP(k[:]).String() }

// syncAllowlist makes mp hold next, deleting what prev installed and next no
// longer names; see UpdateManagementWhitelist for why only that. It returns
// what reached the kernel, which is what the next call has to diff against.
func syncAllowlist[K comparable](mp *ebpf.Map, prev, next map[K]struct{},
	show func(K) string, compare func(a, b K) int) (map[K]struct{}, error) {
	var firstErr error
	for _, key := range revokedWhitelistKeys(prev, next, compare) {
		// ErrKeyNotExist is not a failure: the entry may have been evicted with
		// the previous collection, or never made it in.
		if err := mp.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			logger.L.LogError("failed to revoke a management-whitelist entry; that address still "+
				"reaches the management port at XDP level", "ip", show(key), "error", err)
			firstErr = cmp.Or(firstErr, err)
			continue
		}
		logger.L.LogInfo("Revoked management whitelist entry at XDP level", "ip", show(key))
	}

	installed := make(map[K]struct{}, len(next))
	for key := range next {
		if err := mp.Update(key, uint32(1), ebpf.UpdateAny); err != nil {
			logger.L.LogError("failed to install a management-whitelist entry", "ip", show(key), "error", err)
			firstErr = cmp.Or(firstErr, err)
			continue
		}
		installed[key] = struct{}{}
	}
	return installed, firstErr
}

// revokedWhitelistKeys is the set difference prev\next, sorted so the caller's
// behaviour does not depend on Go's randomised map iteration order.
func revokedWhitelistKeys[K comparable](prev, next map[K]struct{}, compare func(a, b K) int) []K {
	var revoked []K
	for key := range prev {
		if _, keep := next[key]; !keep {
			revoked = append(revoked, key)
		}
	}
	slices.SortFunc(revoked, compare)
	return revoked
}

// topIPv6 reads the IPv6 telemetry map into stats.
func topIPv6(mp *ebpf.Map, stats []IPStat) ([]IPStat, error) {
	var (
		key   [16]byte
		value uint64
	)
	iter := mp.Iterate()
	for iter.Next(&key, &value) {
		stats = append(stats, IPStat{IP: net.IP(key[:]).String(), Count: value})
	}
	return stats, iter.Err()
}
