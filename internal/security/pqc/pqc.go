// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package pqc

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// GenerateMLKEM768KeyPair generates a new ML-KEM-768 key pair.
func GenerateMLKEM768KeyPair() (*mlkem768.PublicKey, *mlkem768.PrivateKey, error) {
	pk, sk, err := mlkem768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ML-KEM-768 key pair: %w", err)
	}
	return pk, sk, nil
}

// EncapsulateMLKEM768 encapsulates a shared secret for a given public key.
func EncapsulateMLKEM768(pk *mlkem768.PublicKey) ([]byte, []byte, error) {
	scheme := mlkem768.Scheme()
	ct := make([]byte, scheme.CiphertextSize())
	ss := make([]byte, scheme.SharedKeySize())
	seed := make([]byte, scheme.EncapsulationSeedSize())
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, nil, fmt.Errorf("failed to generate seed for encapsulation: %w", err)
	}
	pk.EncapsulateTo(ct, ss, seed)
	return ss, ct, nil
}

// DecapsulateMLKEM768 decapsulates a shared secret from a ciphertext using a private key.
func DecapsulateMLKEM768(sk *mlkem768.PrivateKey, ciphertext []byte) ([]byte, error) {
	scheme := mlkem768.Scheme()
	if len(ciphertext) != scheme.CiphertextSize() {
		return nil, fmt.Errorf("invalid ciphertext size: expected %d, got %d", scheme.CiphertextSize(), len(ciphertext))
	}
	ss := make([]byte, scheme.SharedKeySize())
	sk.DecapsulateTo(ss, ciphertext)
	return ss, nil
}

// GenerateMLDSA65KeyPair generates a new ML-DSA-65 key pair.
func GenerateMLDSA65KeyPair() (*mldsa65.PublicKey, *mldsa65.PrivateKey, error) {
	pk, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ML-DSA-65 key pair: %w", err)
	}
	return pk, sk, nil
}

// SignMLDSA65 signs a message using a ML-DSA-65 private key.
func SignMLDSA65(sk *mldsa65.PrivateKey, message []byte, context []byte) ([]byte, error) {
	scheme := mldsa65.Scheme()
	sig := make([]byte, scheme.SignatureSize())
	err := mldsa65.SignTo(sk, message, context, true, sig)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message with ML-DSA-65: %w", err)
	}
	return sig, nil
}

// VerifyMLDSA65 verifies a ML-DSA-65 signature.
func VerifyMLDSA65(pk *mldsa65.PublicKey, message []byte, context []byte, signature []byte) bool {
	return mldsa65.Verify(pk, message, context, signature)
}
