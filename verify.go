package verify

import (
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Inputs is a round's public inputs (round-<N>/inputs.json).
type Inputs struct {
	Round           uint64      `json:"round"`
	DrandRound      uint64      `json:"drandRound"`
	ServerSeed      string      `json:"serverSeed"`      // 0x… 32 bytes, revealed at finalize
	DrandSignature  string      `json:"drandSignature"`  // 0x… 48-byte compressed beacon signature
	DrandRandomness string      `json:"drandRandomness"` // 0x… 32 bytes = sha256(beacon signature)
	Pot             string      `json:"pot"`             // integer USDG base units (6dp)
	Tiers           []PrizeTier `json:"tiers"`
}

// Expected is a round's published outcome (round-<N>/expected.json).
type Expected struct {
	EntrantsHash string `json:"entrantsHash"`
	MerkleRoot   string `json:"merkleRoot"`
	Winners      []struct {
		Rank    int    `json:"rank"`
		Address string `json:"address"`
		Amount  string `json:"amount"`
	} `json:"winners"`
}

// Report is the outcome of re-running a round.
type Report struct {
	Round            uint64
	BeaconChecked    bool // whether a drand signature was present to verify
	BeaconOK         bool // the signature is drand's genuine beacon for the round
	EntrantsHashOK   bool
	MerkleRootOK     bool
	WinnersOK        bool
	ComputedRoot     string
	ComputedEntrants string
	Winners          []Winner
}

func (r Report) OK() bool {
	return (!r.BeaconChecked || r.BeaconOK) && r.EntrantsHashOK && r.MerkleRootOK && r.WinnersOK
}

func mustHex(s string) []byte { b, _ := hex.DecodeString(strings.TrimPrefix(s, "0x")); return b }

// Bundle is the single self-contained file the app hands a verifier
// (round-<N>.lotto-verify.json): the same inputs / entrants / expected as the
// round-<N>/ directory, wrapped into one download so no per-round data ever has
// to be committed to this repo. `entrants` is the raw entrants.csv text.
// The top-level "round" field is intentionally omitted: it is informational
// only and the app emits it as a number while a hand-made file might use a
// string, so ignoring it keeps both shapes valid. The authoritative round
// number is Inputs.Round.
type Bundle struct {
	Inputs   Inputs   `json:"inputs"`
	Entrants string   `json:"entrants"`
	Expected Expected `json:"expected"`
}

// LoadEntrants reads round-<N>/entrants.csv ("address,weight" with a header).
func LoadEntrants(path string) ([]Entrant, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseEntrants(f)
}

// parseEntrants reads "address,weight" rows (with header) from any source — a
// file (LoadEntrants) or the bundle's embedded CSV string (VerifyBundleData).
func parseEntrants(r io.Reader) ([]Entrant, error) {
	rows, err := csv.NewReader(r).ReadAll()
	if err != nil {
		return nil, err
	}
	var out []Entrant
	for i, row := range rows {
		if i == 0 && strings.EqualFold(strings.TrimSpace(row[0]), "address") {
			continue // header
		}
		if len(row) < 2 {
			return nil, fmt.Errorf("entrants.csv line %d: want address,weight", i+1)
		}
		a, err := ParseAddress(row[0])
		if err != nil {
			return nil, fmt.Errorf("entrants.csv line %d: %w", i+1, err)
		}
		w, err := strconv.ParseUint(strings.TrimSpace(row[1]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("entrants.csv line %d: bad weight: %w", i+1, err)
		}
		out = append(out, Entrant{Addr: a, Weight: w})
	}
	return out, nil
}

// VerifyRound re-runs the draw for a round DIRECTORY (round-<N>/ with
// inputs.json, entrants.csv, expected.json) and compares the result to its
// published expected.json. For a real round you would ALSO check the computed
// root/entrantsHash against the on-chain finalize/freeze values and verify the
// drand signature — see README.
func VerifyRound(dir string) (Report, error) {
	var in Inputs
	if err := readJSON(filepath.Join(dir, "inputs.json"), &in); err != nil {
		return Report{}, err
	}
	var exp Expected
	if err := readJSON(filepath.Join(dir, "expected.json"), &exp); err != nil {
		return Report{}, err
	}
	entrants, err := LoadEntrants(filepath.Join(dir, "entrants.csv"))
	if err != nil {
		return Report{}, err
	}
	return runVerify(in, exp, entrants)
}

// VerifyBundle re-runs the draw from a single downloaded bundle file
// (round-<N>.lotto-verify.json). This is the self-serve path: a user downloads
// the bundle straight from the app and runs it here — no per-round data is ever
// committed to this repo.
func VerifyBundle(path string) (Report, error) {
	var b Bundle
	if err := readJSON(path, &b); err != nil {
		return Report{}, err
	}
	return VerifyBundleData(b)
}

// VerifyBundleData re-runs the draw from an already-parsed Bundle (the embedded
// entrants CSV is parsed here), so callers can verify a bundle held in memory.
func VerifyBundleData(b Bundle) (Report, error) {
	entrants, err := parseEntrants(strings.NewReader(b.Entrants))
	if err != nil {
		return Report{}, err
	}
	return runVerify(b.Inputs, b.Expected, entrants)
}

// runVerify is the shared core: re-run the draw from parsed inputs + entrants
// and compare against the published expected outcome. Identical for the
// directory and single-bundle paths.
func runVerify(in Inputs, exp Expected, entrants []Entrant) (Report, error) {
	pot, ok := new(big.Int).SetString(in.Pot, 10)
	if !ok {
		return Report{}, fmt.Errorf("bad pot %q", in.Pot)
	}
	tiers := in.Tiers
	if len(tiers) == 0 {
		tiers = DefaultTiers()
	}

	winners := ComputeWinners(entrants, pot, tiers, mustHex(in.ServerSeed), mustHex(in.DrandRandomness))
	root := MerkleRoot(winners)
	eh := EntrantsHash(entrants)

	rep := Report{
		Round:            in.Round,
		Winners:          winners,
		ComputedRoot:     "0x" + hex.EncodeToString(root[:]),
		ComputedEntrants: "0x" + hex.EncodeToString(eh[:]),
	}
	// Trust anchor: verify the beacon signature is drand's genuine value for the
	// round, and that the randomness the draw used is sha256 of it.
	if in.DrandSignature != "" {
		rep.BeaconChecked = true
		sig := mustHex(in.DrandSignature)
		beaconRand := BeaconRandomness(sig)
		rep.BeaconOK = VerifyBeacon(in.DrandRound, sig) == nil &&
			hex.EncodeToString(beaconRand[:]) == strings.TrimPrefix(with0x(in.DrandRandomness), "0x")
	}
	rep.MerkleRootOK = strings.EqualFold(rep.ComputedRoot, with0x(exp.MerkleRoot))
	rep.EntrantsHashOK = strings.EqualFold(rep.ComputedEntrants, with0x(exp.EntrantsHash))
	rep.WinnersOK = winnersMatch(winners, exp)
	return rep, nil
}

func winnersMatch(got []Winner, exp Expected) bool {
	if len(got) != len(exp.Winners) {
		return false
	}
	for i, w := range got {
		if !strings.EqualFold(w.Addr.Hex(), with0x(exp.Winners[i].Address)) || w.Amount.String() != exp.Winners[i].Amount {
			return false
		}
	}
	return true
}

func with0x(s string) string {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return s
	}
	return "0x" + s
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
