// Command gen writes the round-1000 example vector (testdata/round-1000) from
// the same inputs the backend's worked example uses. It exists so the checked-in
// example data is produced by this reference implementation, not hand-typed.
//
//	go run ./cmd/gen
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	verify "github.com/streakfun/lotto-verify"
)

const (
	serverSeed = "8d0e029a9fc5f7f1efdaf856cdad40b081af8559b868c276784d5ece64ade560"
	randomness = "fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd"
	// Real drand quicknet round-1000 compressed BLS signature.
	signature = "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"
)

func main() {
	dir := "testdata/round-1000"
	entrants := exampleEntrants()
	pot := big.NewInt(10_000_000000)
	tiers := verify.DefaultTiers()

	seed, _ := hex.DecodeString(serverSeed)
	rnd, _ := hex.DecodeString(randomness)
	winners := verify.ComputeWinners(entrants, pot, tiers, seed, rnd)
	root := verify.MerkleRoot(winners)
	eh := verify.EntrantsHash(entrants)

	// inputs.json
	writeJSON(filepath.Join(dir, "inputs.json"), map[string]any{
		"round":           1,
		"drandRound":      1000,
		"serverSeed":      "0x" + serverSeed,
		"drandSignature":  "0x" + signature,
		"drandRandomness": "0x" + randomness,
		"pot":             pot.String(),
		"tiers":           tiers,
	})

	// entrants.csv
	var csv = "address,weight\n"
	for _, e := range entrants {
		csv += fmt.Sprintf("%s,%d\n", e.Addr.Hex(), e.Weight)
	}
	must(os.WriteFile(filepath.Join(dir, "entrants.csv"), []byte(csv), 0o644))

	// expected.json
	ws := make([]map[string]any, len(winners))
	for i, w := range winners {
		ws[i] = map[string]any{"rank": i + 1, "address": w.Addr.Hex(), "amount": w.Amount.String()}
	}
	writeJSON(filepath.Join(dir, "expected.json"), map[string]any{
		"entrantsHash": "0x" + hex.EncodeToString(eh[:]),
		"merkleRoot":   "0x" + hex.EncodeToString(root[:]),
		"winners":      ws,
	})

	fmt.Printf("wrote %s: %d entrants, %d winners, root 0x%s\n", dir, len(entrants), len(winners), hex.EncodeToString(root[:]))
}

func exampleEntrants() []verify.Entrant {
	counts := map[int]uint64{1: 250, 2: 180, 3: 140, 4: 40, 5: 35, 6: 30, 7: 28, 8: 25, 9: 22, 10: 20}
	out := make([]verify.Entrant, 0, 50)
	for i := 1; i <= 50; i++ {
		var a verify.Address
		new(big.Int).SetUint64(uint64(i)).FillBytes(a[:])
		w, ok := counts[i]
		if !ok {
			w = uint64(1 + (i*3)%12)
		}
		if i == 4 {
			w += 10
		}
		if i == 5 {
			w += 8
		}
		out = append(out, verify.Entrant{Addr: a, Weight: w})
	}
	return out
}

func writeJSON(path string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	must(os.WriteFile(path, append(b, '\n'), 0o644))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
