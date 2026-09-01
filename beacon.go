package verify

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// QuicknetPublicKey is drand quicknet's fixed group public key (G2, 96 bytes
// compressed). Beacons are useless to forge without the matching secret shares,
// which are split across the League of Entropy — this key is all a verifier
// needs to authenticate any round.
const QuicknetPublicKey = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"

// drandDST is the RFC-9380 domain separation tag for drand quicknet
// (scheme bls-unchained-g1-rfc9380: signatures on G1).
var drandDST = []byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_")

// VerifyBeacon checks that `signature` is drand quicknet's genuine beacon
// signature for `round`, against the fixed public key. This is the trust
// anchor: it proves the randomness (sha256(signature)) really came from drand
// and was not fabricated or ground by whoever produced the round data.
//
// For an unchained beacon the signed message is sha256(uint64-be(round)); the
// check is the BLS pairing e(signature, g2) == e(H(message)->G1, publicKey).
func VerifyBeacon(round uint64, signature []byte) error {
	var rb [8]byte
	binary.BigEndian.PutUint64(rb[:], round)
	msg := sha256.Sum256(rb[:])

	h, err := bls.HashToG1(msg[:], drandDST)
	if err != nil {
		return fmt.Errorf("hash-to-curve: %w", err)
	}

	var sig bls.G1Affine
	if _, err := sig.SetBytes(signature); err != nil {
		return fmt.Errorf("bad signature point: %w", err)
	}

	pkBytes, err := hex.DecodeString(QuicknetPublicKey)
	if err != nil {
		return fmt.Errorf("bad public key hex: %w", err)
	}
	var pub bls.G2Affine
	if _, err := pub.SetBytes(pkBytes); err != nil {
		return fmt.Errorf("bad public key point: %w", err)
	}

	_, _, _, g2 := bls.Generators()
	var negPub bls.G2Affine
	negPub.Neg(&pub)

	// e(sig, g2) == e(H, pub)  ⇔  e(sig, g2) · e(H, -pub) == 1
	ok, err := bls.PairingCheck([]bls.G1Affine{sig, h}, []bls.G2Affine{g2, negPub})
	if err != nil {
		return fmt.Errorf("pairing: %w", err)
	}
	if !ok {
		return errors.New("drand signature does not verify against quicknet public key")
	}
	return nil
}

// BeaconRandomness is the round's randomness derived from its verified
// signature: sha256(signature). Callers should VerifyBeacon first.
func BeaconRandomness(signature []byte) [32]byte { return sha256.Sum256(signature) }
