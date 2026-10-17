// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package service

import (
	"errors"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestSaveRefusesACloudMetadataTarget (ADR 0077): a service pointed at the
// cloud instance metadata service, behind a Host() route on a public
// entrypoint, handed the instance's identity and role credentials -- IMDSv2's
// token PUT included -- to anyone who sent the route's Host. The save is
// refused naming the target, in every form that reaches the service, and
// nothing is stored.
func TestSaveRefusesACloudMetadataTarget(t *testing.T) {
	for _, target := range []string{
		"http://169.254.169.254", "http://169.254.169.254/latest/meta-data/",
		"https://169.254.169.254:443", "h2c://169.254.169.254", "tcp://169.254.169.254:80", "grpc://169.254.169.254:80", "ws://[fd00:ec2::254]",
		"169.254.169.254:80", "169.254.169.254", "http://169.254.170.2/v2/credentials",
		"http://[fd00:ec2::254]", "http://100.100.100.200/latest/meta-data",
		"http://metadata.google.internal/computeMetadata/v1/", "http://METADATA.GOOGLE.INTERNAL.:80",
		"http://[::ffff:169.254.169.254]", "http://[64:ff9b::a9fe:a9fe]",
		"http://169.254.10.10:8080", "http://[fe80::1]:8080",
	} {
		store := &fakeServiceStore{services: map[string]*gateonv1.Service{}}
		s := NewService(store, &fakeRouteStore{updateErr: map[string]error{}}, &recordingInvalidator{}, nil)
		err := s.SaveService(t.Context(), &gateonv1.Service{Id: "imds", WeightedTargets: []*gateonv1.Target{
			{Url: "http://192.0.2.10:8080", Weight: 1}, {Url: target, Weight: 1},
		}})
		if !errors.Is(err, ErrInvalidService) || !strings.Contains(err.Error(), strings.TrimSpace(target)) ||
			!strings.Contains(err.Error(), "metadata") {
			t.Errorf("save with target %s: err = %v, want ErrInvalidService naming it and cloud metadata", target, err)
		}
		if len(store.services) != 0 {
			t.Errorf("a service targeting %s was stored", target)
		}
	}
}

// TestSaveKeepsPrivateTargets: the refusal is the metadata service, not the
// private networks backends live on. RFC 1918, loopback away from the
// management port, the rest of 100.64/10 and a name that merely starts with
// "metadata" all save.
func TestSaveKeepsPrivateTargets(t *testing.T) {
	for _, target := range []string{
		"http://10.0.0.5:8080", "http://192.168.1.10", "http://172.16.0.1:3000",
		"http://127.0.0.1:9000", "h2c://[::1]:9000", "http://100.64.0.5:8080",
		"http://metadata-api.internal:8080", "http://metadata:8080", "tcp://10.1.2.3:5432",
	} {
		s := NewService(&fakeServiceStore{services: map[string]*gateonv1.Service{}},
			&fakeRouteStore{updateErr: map[string]error{}}, &recordingInvalidator{}, nil)
		if err := s.SaveService(t.Context(), &gateonv1.Service{
			WeightedTargets: []*gateonv1.Target{{Url: target, Weight: 1}},
		}); err != nil {
			t.Errorf("target %s refused: %v", target, err)
		}
	}
}
