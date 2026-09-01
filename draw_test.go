package verify

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// round1000Entrants rebuilds the exact 50-wallet entrant set used by the
// backend's worked example (backend/pkg/lotto/examplerun_test.go). Keeping this
// in lockstep with the backend is the whole point: if this reference draw
// reproduces the backend's merkle root, the two implementations agree.
func round1000Entrants() []Entrant {
	counts := map[int]uint64{1: 250, 2: 180, 3: 140, 4: 40, 5: 35, 6: 30, 7: 28, 8: 25, 9: 22, 10: 20}
	out := make([]Entrant, 0, 50)
	for i := 1; i <= 50; i++ {
		var a Address
		new(big.Int).SetUint64(uint64(i)).FillBytes(a[:])
		w, ok := counts[i]
		if !ok {
			w = uint64(1 + (i*3)%12)
		}
		if i == 4 {
			w += 10 // wallet #4 also bought 10 tickets
		}
		if i == 5 {
			w += 8 // wallet #5 was granted 8 free tickets
		}
		out = append(out, Entrant{Addr: a, Weight: w})
	}
	return out
}

const (
	round1000ServerSeed = "8d0e029a9fc5f7f1efdaf856cdad40b081af8559b868c276784d5ece64ade560"
	round1000Randomness = "fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd"
	round1000MerkleRoot = "60fe504bb9f24228d72685f7e13c13fa7cfa89e5a9290ff6b6f67aaf28e083f9"
)

// TestReproducesBackendRoot is the cross-implementation oracle: this
// dependency-light reference must produce the SAME merkle root the backend's
// production selection code committed for the same inputs. A match proves the
// EIP-55 ordering, the HMAC draw, the biggest-first assignment, and the OZ
// merkle are all byte-identical to production.
func TestReproducesBackendRoot(t *testing.T) {
	seed, _ := hex.DecodeString(round1000ServerSeed)
	rnd, _ := hex.DecodeString(round1000Randomness)
	pot := big.NewInt(10_000_000000) // 10,000 USDG

	winners := ComputeWinners(round1000Entrants(), pot, DefaultTiers(), seed, rnd)
	if len(winners) != 30 {
		t.Fatalf("winners = %d, want 30", len(winners))
	}
	got := hex.EncodeToString(func() []byte { r := MerkleRoot(winners); return r[:] }())
	if got != round1000MerkleRoot {
		t.Fatalf("merkle root mismatch:\n got  %s\n want %s (backend production value)", got, round1000MerkleRoot)
	}
}
