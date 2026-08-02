// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package tpm

import (
	"testing"
)

func TestSigner_Fallback(t *testing.T) {
	// NewSigner should succeed even if TPM is missing by falling back to software.
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	defer signer.Close()

	msg := []byte("test identity")
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) == 0 {
		t.Error("Empty signature returned")
	}

	pub := signer.PublicKey()
	if pub == nil {
		t.Error("Nil public key returned")
	}
}
