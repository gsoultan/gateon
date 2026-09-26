// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/ebpf"
)

// ebpfReporting is an eBPF manager that reports one attach state, which is all
// GET /v1/system/interfaces asks of it.
type ebpfReporting struct {
	ebpf.Manager
	stats ebpf.MapStats
}

func (m ebpfReporting) GetMapStats() (ebpf.MapStats, error) { return m.stats, nil }

// interfacesAPI is the slice of the API GET /v1/system/interfaces reads.
type interfacesAPI struct {
	GlobalAndAuthAPI
	mgr ebpf.Manager
}

func (a interfacesAPI) GetGlobals() config.GlobalConfigStore { return nil }
func (a interfacesAPI) GetEbpfManager() ebpf.Manager         { return a.mgr }

// TestSystemInterfacesReportsEBPFUnderTheDashboardsKeys: the settings card
// reads ebpf.attachMode and ebpf.loadError (EbpfStatus in
// useNetworkInterfaces.ts), and this endpoint wrote attach_mode and load_error.
// Neither was ever read, so an attached program always rendered as "XDP
// attached (native mode)" -- on an ENA NIC that had fallen back to the TC hook
// that hid the warning that port knocking, phantom ports and load balancing were
// not in force -- and a failed attach never showed its reason.
func TestSystemInterfacesReportsEBPFUnderTheDashboardsKeys(t *testing.T) {
	mux := http.NewServeMux()
	registerDiagnosticHandlers(mux, interfacesAPI{mgr: ebpfReporting{stats: ebpf.MapStats{
		Attached: true, Interface: "ens5", AttachMode: "tcx", LoadError: "native XDP refused",
	}}}, &Deps{})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/system/interfaces", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body)
	}

	var resp struct {
		Ebpf map[string]any `json:"ebpf"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := resp.Ebpf["attachMode"]; got != "tcx" {
		t.Errorf("ebpf.attachMode = %v, want \"tcx\"; ebpf = %v", got, resp.Ebpf)
	}
	if got := resp.Ebpf["loadError"]; got != "native XDP refused" {
		t.Errorf("ebpf.loadError = %v, want the load error; ebpf = %v", got, resp.Ebpf)
	}
}

// TestRecommendedIndexIsTheInterfaceEBPFWouldUse: the picker used to recommend
// the first up, non-loopback interface with an IPv4 address. On a host whose
// default route is on a later interface that named one NIC while the gateway,
// left unconfigured, attached to another.
func TestRecommendedIndexIsTheInterfaceEBPFWouldUse(t *testing.T) {
	infos := []netInterfaceInfo{{Name: "lo"}, {Name: "docker0"}, {Name: "ens5"}}
	const firstUpWithIPv4 = 1 // docker0

	if got := recommendedIndex(infos, "ens5", firstUpWithIPv4); got != 2 {
		t.Errorf("default-route interface listed third: got index %d, want 2 (ens5)", got)
	}
	if got := recommendedIndex(infos, "ens9", firstUpWithIPv4); got != firstUpWithIPv4 {
		t.Errorf("default-route interface not listed: got index %d, want the fallback %d", got, firstUpWithIPv4)
	}
	if got := recommendedIndex(infos, "", firstUpWithIPv4); got != firstUpWithIPv4 {
		t.Errorf("no default-route interface: got index %d, want the fallback %d", got, firstUpWithIPv4)
	}
	if got := recommendedIndex(infos, "", -1); got != -1 {
		t.Errorf("nothing to recommend: got index %d, want -1", got)
	}
}
