// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package upgrade

import (
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Proto renders the view as the API reports it.
func (v View) Proto() *gateonv1.UpgradeStatus {
	out := &gateonv1.UpgradeStatus{
		Blocker:          blockerProto[v.Blocker],
		AutoInstall:      v.Auto.Enabled,
		AutoInstallByEnv: v.Auto.ByEnv,
		AutoInstallScope: scopeProto[v.Auto.Scope],
		WindowStart:      clock(v.Auto.Window.Start),
		WindowEnd:        clock(v.Auto.Window.End),
	}
	if v.Current != nil {
		out.Current = v.Current.Proto()
	}
	for _, h := range v.History {
		out.History = append(out.History, h.Proto())
	}
	return out
}

// Proto renders one install. The nonce stays behind: it is between the
// helper and the gateway.
func (s Status) Proto() *gateonv1.UpgradeRecord {
	return &gateonv1.UpgradeRecord{
		Phase:            phaseProto[s.Phase],
		Reason:           reasonProto[s.Reason],
		TargetVersion:    s.Target,
		PreviousVersion:  s.Previous,
		StartedAt:        unix(s.StartedAt),
		FinishedAt:       unix(s.FinishedAt),
		RequestedBy:      s.RequestedBy,
		Automatic:        s.Automatic,
		DatabaseRestored: s.RestoreDatabase && s.Phase == PhaseRolledBack,
	}
}

func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

var blockerProto = map[Blocker]gateonv1.UpgradeBlocker{
	BlockerNone:         gateonv1.UpgradeBlocker_UPGRADE_BLOCKER_UNSPECIFIED,
	BlockerOrchestrated: gateonv1.UpgradeBlocker_UPGRADE_BLOCKER_ORCHESTRATED,
	BlockerNoHelper:     gateonv1.UpgradeBlocker_UPGRADE_BLOCKER_NO_HELPER,
	BlockerNoKey:        gateonv1.UpgradeBlocker_UPGRADE_BLOCKER_NO_KEY,
	BlockerDevBuild:     gateonv1.UpgradeBlocker_UPGRADE_BLOCKER_DEVELOPMENT_BUILD,
}

var scopeProto = map[Scope]gateonv1.UpdateScope{
	ScopePatch: gateonv1.UpdateScope_UPDATE_SCOPE_PATCH,
	ScopeMinor: gateonv1.UpdateScope_UPDATE_SCOPE_MINOR,
	ScopeMajor: gateonv1.UpdateScope_UPDATE_SCOPE_MAJOR,
}

var phaseProto = map[Phase]gateonv1.UpgradePhase{
	PhaseDownloading: gateonv1.UpgradePhase_UPGRADE_PHASE_DOWNLOADING,
	PhaseRequested:   gateonv1.UpgradePhase_UPGRADE_PHASE_REQUESTED,
	PhaseInstalling:  gateonv1.UpgradePhase_UPGRADE_PHASE_INSTALLING,
	PhaseRestarting:  gateonv1.UpgradePhase_UPGRADE_PHASE_RESTARTING,
	PhaseRollingBack: gateonv1.UpgradePhase_UPGRADE_PHASE_ROLLING_BACK,
	PhaseSucceeded:   gateonv1.UpgradePhase_UPGRADE_PHASE_SUCCEEDED,
	PhaseRolledBack:  gateonv1.UpgradePhase_UPGRADE_PHASE_ROLLED_BACK,
	PhaseRefused:     gateonv1.UpgradePhase_UPGRADE_PHASE_REFUSED,
	PhaseFailed:      gateonv1.UpgradePhase_UPGRADE_PHASE_FAILED,
}

var reasonProto = map[Reason]gateonv1.UpgradeReason{
	ReasonSignature: gateonv1.UpgradeReason_UPGRADE_REASON_SIGNATURE,
	ReasonChecksum:  gateonv1.UpgradeReason_UPGRADE_REASON_CHECKSUM,
	ReasonMalformed: gateonv1.UpgradeReason_UPGRADE_REASON_MALFORMED,
	ReasonNotNewer:  gateonv1.UpgradeReason_UPGRADE_REASON_NOT_NEWER,
	ReasonNoKey:     gateonv1.UpgradeReason_UPGRADE_REASON_NO_KEY,
	ReasonInstall:   gateonv1.UpgradeReason_UPGRADE_REASON_INSTALL,
	ReasonNotReady:  gateonv1.UpgradeReason_UPGRADE_REASON_NOT_READY,
	ReasonMigrated:  gateonv1.UpgradeReason_UPGRADE_REASON_MIGRATED,
	ReasonDownload:  gateonv1.UpgradeReason_UPGRADE_REASON_DOWNLOAD,
	ReasonHelper:    gateonv1.UpgradeReason_UPGRADE_REASON_HELPER,
}
