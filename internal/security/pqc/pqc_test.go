// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package pqc

import (
	"bytes"
	"testing"
)

func TestMLKEM(t *testing.T) {
	pk, sk, err := GenerateMLKEM768KeyPair()
	if err != nil {
		t.Fatalf("GenerateMLKEM768KeyPair failed: %v", err)
	}

	ss, ct, err := EncapsulateMLKEM768(pk)
	if err != nil {
		t.Fatalf("EncapsulateMLKEM768 failed: %v", err)
	}

	ss2, err := DecapsulateMLKEM768(sk, ct)
	if err != nil {
		t.Fatalf("DecapsulateMLKEM768 failed: %v", err)
	}

	if !bytes.Equal(ss, ss2) {
		t.Error("Shared secrets do not match")
	}
}

func TestMLDSA(t *testing.T) {
	pk, sk, err := GenerateMLDSA65KeyPair()
	if err != nil {
		t.Fatalf("GenerateMLDSA65KeyPair failed: %v", err)
	}

	msg := []byte("hello quantum world")
	sig, err := SignMLDSA65(sk, msg, nil)
	if err != nil {
		t.Fatalf("SignMLDSA65 failed: %v", err)
	}

	if !VerifyMLDSA65(pk, msg, nil, sig) {
		t.Error("Signature verification failed")
	}

	if VerifyMLDSA65(pk, []byte("tampered"), nil, sig) {
		t.Error("Signature verification should have failed for tampered message")
	}
}
