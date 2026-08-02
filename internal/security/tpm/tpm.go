// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/gsoultan/gateon/internal/logger"
)

// Signer defines the interface for TPM-based or fallback identity signing.
type Signer interface {
	Sign(digest []byte) ([]byte, error)
	PublicKey() crypto.PublicKey
	Close() error
}

// NewSigner creates a new Signer, attempting to use hardware TPM 2.0 first,
// and falling back to a software-based ECDSA implementation if not available.
func NewSigner() (Signer, error) {
	s, err := NewHardwareSigner()
	if err == nil {
		logger.L.LogInfo("Successfully initialized hardware TPM 2.0 signer")
		return s, nil
	}

	logger.L.LogInfo("Hardware TPM 2.0 not found or failed to initialize, falling back to software signer", "error", err)
	return NewSoftwareSigner()
}

// HardwareSigner implements Signer using a TPM 2.0 device.
type HardwareSigner struct {
	tpm    transport.TPMCloser
	handle *tpm2.AuthHandle
	pubKey crypto.PublicKey
}

// NewHardwareSigner initializes a hardware-backed signer using the TPM.
func NewHardwareSigner() (*HardwareSigner, error) {
	tpmPath := "/dev/tpmrm0"
	if _, err := os.Stat(tpmPath); os.IsNotExist(err) {
		tpmPath = "/dev/tpm0"
	}

	rwc, err := linuxtpm.Open(tpmPath)
	if err != nil {
		return nil, fmt.Errorf("could not open TPM device: %w", err)
	}

	// Create a Primary Key in the Endorsement hierarchy for identity.
	// We use an ECC P-256 template that allows signing.
	srk := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				SignEncrypt:         true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					CurveID: tpm2.TPMECCNistP256,
					Scheme: tpm2.TPMTECCScheme{
						Scheme: tpm2.TPMAlgECDSA,
						Details: tpm2.NewTPMUAsymScheme(
							tpm2.TPMAlgECDSA,
							&tpm2.TPMSSigSchemeECDSA{
								HashAlg: tpm2.TPMAlgSHA256,
							},
						),
					},
				},
			),
		}),
	}

	rsp, err := srk.Execute(rwc)
	if err != nil {
		rwc.Close()
		return nil, fmt.Errorf("failed to create TPM primary key: %w", err)
	}

	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		rwc.Close()
		return nil, fmt.Errorf("failed to parse TPM public key contents: %w", err)
	}

	eccPub, err := pub.Unique.ECC()
	if err != nil {
		rwc.Close()
		return nil, fmt.Errorf("TPM key is not ECC: %w", err)
	}

	details, err := pub.Parameters.ECCDetail()
	if err != nil {
		rwc.Close()
		return nil, fmt.Errorf("failed to get ECC details from TPM key: %w", err)
	}

	goPub, err := tpm2.ECDSAPub(details, eccPub)
	if err != nil {
		rwc.Close()
		return nil, fmt.Errorf("failed to convert to ecdsa.PublicKey: %w", err)
	}

	return &HardwareSigner{
		tpm: rwc,
		handle: &tpm2.AuthHandle{
			Handle: rsp.ObjectHandle,
			Name:   rsp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		pubKey: goPub,
	}, nil
}

// Sign signs a 32-byte digest using the TPM's private key.
func (s *HardwareSigner) Sign(digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("TPM signing requires a 32-byte digest (SHA-256)")
	}

	sign := tpm2.Sign{
		KeyHandle: s.handle,
		Digest:    tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}

	rsp, err := sign.Execute(s.tpm)
	if err != nil {
		return nil, fmt.Errorf("TPM sign command failed: %w", err)
	}

	sig, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("failed to get ECDSA signature from TPM: %w", err)
	}

	return append(sig.SignatureR.Buffer, sig.SignatureS.Buffer...), nil
}

// PublicKey returns the Go-compatible public key.
func (s *HardwareSigner) PublicKey() crypto.PublicKey {
	return s.pubKey
}

// Close flushes the TPM handle and closes the transport.
func (s *HardwareSigner) Close() error {
	flush := tpm2.FlushContext{FlushHandle: s.handle.Handle}
	_, _ = flush.Execute(s.tpm)
	return s.tpm.Close()
}

// SoftwareSigner provides a software-only fallback using standard crypto.
type SoftwareSigner struct {
	priv *ecdsa.PrivateKey
}

func NewSoftwareSigner() (*SoftwareSigner, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &SoftwareSigner{priv: priv}, nil
}

func (s *SoftwareSigner) Sign(digest []byte) ([]byte, error) {
	r, sigS, err := ecdsa.Sign(rand.Reader, s.priv, digest)
	if err != nil {
		return nil, err
	}
	return append(r.Bytes(), sigS.Bytes()...), nil
}

func (s *SoftwareSigner) PublicKey() crypto.PublicKey {
	return s.priv.Public()
}

func (s *SoftwareSigner) Close() error {
	return nil
}
