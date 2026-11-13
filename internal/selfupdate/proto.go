// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package selfupdate

import gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"

// Proto is s as the API reports it.
func (s Status) Proto() *gateonv1.UpdateStatus {
	out := &gateonv1.UpdateStatus{
		CurrentVersion:  s.Current,
		LatestVersion:   s.Latest,
		UpdateAvailable: s.UpdateAvailable,
		Signature:       signatureProto[s.Signature],
		State:           stateProto[s.State],
		Failure:         failureProto[s.Failure],
		ReleaseNotesUrl: s.NotesURL,
		SourceUrl:       s.Source,
		InstallKind:     kindProto[s.InstallKind],
		DisabledByEnv:   s.DisabledByEnv,
		ReleaseBuild:    s.ReleaseBuild,
	}
	if !s.CheckedAt.IsZero() {
		out.CheckedAt = s.CheckedAt.Unix()
	}
	return out
}

var stateProto = map[CheckState]gateonv1.UpdateCheckState{
	StatePending:  gateonv1.UpdateCheckState_UPDATE_CHECK_STATE_PENDING,
	StateOK:       gateonv1.UpdateCheckState_UPDATE_CHECK_STATE_OK,
	StateFailed:   gateonv1.UpdateCheckState_UPDATE_CHECK_STATE_FAILED,
	StateDisabled: gateonv1.UpdateCheckState_UPDATE_CHECK_STATE_DISABLED,
}

var signatureProto = map[SignatureState]gateonv1.UpdateSignature{
	SignatureUnknown:  gateonv1.UpdateSignature_UPDATE_SIGNATURE_UNSPECIFIED,
	SignatureVerified: gateonv1.UpdateSignature_UPDATE_SIGNATURE_VERIFIED,
	SignatureNoKey:    gateonv1.UpdateSignature_UPDATE_SIGNATURE_NO_KEY,
}

var failureProto = map[Failure]gateonv1.UpdateFailure{
	FailureNone:        gateonv1.UpdateFailure_UPDATE_FAILURE_UNSPECIFIED,
	FailureUnreachable: gateonv1.UpdateFailure_UPDATE_FAILURE_UNREACHABLE,
	FailureSignature:   gateonv1.UpdateFailure_UPDATE_FAILURE_SIGNATURE,
	FailureMalformed:   gateonv1.UpdateFailure_UPDATE_FAILURE_MALFORMED,
	FailureSource:      gateonv1.UpdateFailure_UPDATE_FAILURE_SOURCE,
}

var kindProto = map[InstallKind]gateonv1.InstallKind{
	InstallOther:      gateonv1.InstallKind_INSTALL_KIND_OTHER,
	InstallSystemd:    gateonv1.InstallKind_INSTALL_KIND_SYSTEMD,
	InstallContainer:  gateonv1.InstallKind_INSTALL_KIND_CONTAINER,
	InstallKubernetes: gateonv1.InstallKind_INSTALL_KIND_KUBERNETES,
}
