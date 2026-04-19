package telemetry

import (
	"sync"
	"time"
)

type DiagnosticStats struct {
	mu                 sync.RWMutex
	entrypointStats    map[string]*EPStats
	recentTLSErrors    []HandshakeErrorInfo
	maxRecentTLSErrors int
}

type EPStats struct {
	TotalConnections  int64
	ActiveConnections int64
	LastError         string
	LastSeen          time.Time
}

type HandshakeErrorInfo struct {
	Timestamp    time.Time
	RemoteAddr   string
	Error        string
	EntryPointID string
}

var (
	GlobalDiagnostics = &DiagnosticStats{
		entrypointStats:    make(map[string]*EPStats),
		maxRecentTLSErrors: 50,
	}
)

func (d *DiagnosticStats) RecordConnection(epID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.entrypointStats[epID]
	if !ok {
		s = &EPStats{}
		d.entrypointStats[epID] = s
	}
	s.TotalConnections++
	s.ActiveConnections++
	s.LastSeen = time.Now()
}

func (d *DiagnosticStats) RecordDisconnect(epID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if s, ok := d.entrypointStats[epID]; ok {
		s.ActiveConnections--
	}
}

func (d *DiagnosticStats) RecordEPError(epID string, err string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.entrypointStats[epID]
	if !ok {
		s = &EPStats{}
		d.entrypointStats[epID] = s
	}
	s.LastError = err
}

func (d *DiagnosticStats) RecordTLSError(epID, remoteAddr, err string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	info := HandshakeErrorInfo{
		Timestamp:    time.Now(),
		RemoteAddr:   remoteAddr,
		Error:        err,
		EntryPointID: epID,
	}

	d.recentTLSErrors = append([]HandshakeErrorInfo{info}, d.recentTLSErrors...)
	if len(d.recentTLSErrors) > d.maxRecentTLSErrors {
		d.recentTLSErrors = d.recentTLSErrors[:d.maxRecentTLSErrors]
	}
}

func (d *DiagnosticStats) GetEPStats(epID string) EPStats {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if s, ok := d.entrypointStats[epID]; ok {
		return *s
	}
	return EPStats{}
}

func (d *DiagnosticStats) GetRecentTLSErrors() []HandshakeErrorInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()
	res := make([]HandshakeErrorInfo, len(d.recentTLSErrors))
	copy(res, d.recentTLSErrors)
	return res
}
