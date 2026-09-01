package verify

import (
	"encoding/hex"
	"testing"
)

// Real drand quicknet round-1000 vector (docs fixture).
const (
	beaconRound   = 1000
	beaconSigHex  = "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"
	beaconRandHex = "fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd"
)

func TestVerifyBeacon_acceptsRealVector(t *testing.T) {
	sig, _ := hex.DecodeString(beaconSigHex)
	if err := VerifyBeacon(beaconRound, sig); err != nil {
		t.Fatalf("real round-1000 beacon should verify: %v", err)
	}
	if got := hex.EncodeToString(func() []byte { r := BeaconRandomness(sig); return r[:] }()); got != beaconRandHex {
		t.Fatalf("randomness = %s, want %s", got, beaconRandHex)
	}
}

func TestVerifyBeacon_rejectsWrongRound(t *testing.T) {
	sig, _ := hex.DecodeString(beaconSigHex)
	if err := VerifyBeacon(beaconRound+1, sig); err == nil {
		t.Fatal("a valid signature must not verify against the wrong round")
	}
}

func TestVerifyBeacon_rejectsTamperedSignature(t *testing.T) {
	sig, _ := hex.DecodeString(beaconSigHex)
	sig[0] ^= 0x01 // flip a bit
	if err := VerifyBeacon(beaconRound, sig); err == nil {
		t.Fatal("a tampered signature must not verify")
	}
}
