package verify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestVerifyRound_example drives the full file-based flow the CLI uses against
// the checked-in round-1000 vector.
func TestVerifyRound_example(t *testing.T) {
	rep, err := VerifyRound("testdata/round-1000")
	if err != nil {
		t.Fatalf("VerifyRound: %v", err)
	}
	if !rep.OK() {
		t.Fatalf("round did not verify: entrantsHashOK=%v merkleRootOK=%v winnersOK=%v",
			rep.EntrantsHashOK, rep.MerkleRootOK, rep.WinnersOK)
	}
}

// bundleFromDir rebuilds the single-file Bundle from a round-<N>/ directory —
// exactly the shape the app downloads (inputs/expected as objects, entrants as
// the raw CSV text).
func bundleFromDir(t *testing.T, dir string) Bundle {
	t.Helper()
	var in Inputs
	if err := readJSON(filepath.Join(dir, "inputs.json"), &in); err != nil {
		t.Fatal(err)
	}
	var exp Expected
	if err := readJSON(filepath.Join(dir, "expected.json"), &exp); err != nil {
		t.Fatal(err)
	}
	csv, err := os.ReadFile(filepath.Join(dir, "entrants.csv"))
	if err != nil {
		t.Fatal(err)
	}
	return Bundle{Inputs: in, Entrants: string(csv), Expected: exp}
}

// TestVerifyBundleData_matchesDir proves the single-bundle path produces the
// SAME verification result as the directory path — the whole point of letting
// users download one file instead of us publishing round-<N>/ dirs.
func TestVerifyBundleData_matchesDir(t *testing.T) {
	rep, err := VerifyBundleData(bundleFromDir(t, "testdata/round-1000"))
	if err != nil {
		t.Fatalf("VerifyBundleData: %v", err)
	}
	if !rep.OK() {
		t.Fatalf("bundle did not verify: beaconOK=%v entrantsHashOK=%v merkleRootOK=%v winnersOK=%v",
			rep.BeaconOK, rep.EntrantsHashOK, rep.MerkleRootOK, rep.WinnersOK)
	}
}

// TestVerifyBundle_fromFile drives the exact CLI path: a downloaded
// round-<N>.lotto-verify.json on disk → PASS.
func TestVerifyBundle_fromFile(t *testing.T) {
	b := bundleFromDir(t, "testdata/round-1000")
	path := filepath.Join(t.TempDir(), "round-1000.lotto-verify.json")
	data, _ := json.MarshalIndent(b, "", "  ")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := VerifyBundle(path)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if !rep.OK() {
		t.Fatal("downloaded bundle did not verify")
	}
}

// TestVerifyBundleData_detectsTampering flips one winner's amount and expects a
// FAIL — the guarantee that a doctored bundle can't pass.
func TestVerifyBundleData_detectsTampering(t *testing.T) {
	b := bundleFromDir(t, "testdata/round-1000")
	if len(b.Expected.Winners) == 0 {
		t.Fatal("fixture has no winners")
	}
	b.Expected.Winners[0].Amount = "1" // lie about the top prize
	rep, err := VerifyBundleData(b)
	if err != nil {
		t.Fatalf("VerifyBundleData: %v", err)
	}
	if rep.OK() {
		t.Fatal("a tampered winner amount must NOT verify")
	}
}
