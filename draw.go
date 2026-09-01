package verify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"sort"
)

// Entrant is one wallet's frozen ticket weight for a round.
type Entrant struct {
	Addr   Address
	Weight uint64
}

// PrizeTier awards Count winners Bps basis points of the pot EACH.
type PrizeTier struct {
	Count uint
	Bps   uint16
}

// DefaultTiers is the launch structure: 40 winners summing to 100% of the pot.
func DefaultTiers() []PrizeTier {
	return []PrizeTier{
		{1, 2600}, {1, 1200}, {1, 900}, {2, 550}, {5, 300}, {10, 140}, {10, 130},
	}
}

// tierBps flattens tiers into one bps-per-rank slice (index 0 = top prize).
func tierBps(tiers []PrizeTier) []uint16 {
	var out []uint16
	for _, t := range tiers {
		for i := uint(0); i < t.Count; i++ {
			out = append(out, t.Bps)
		}
	}
	return out
}

// PrizeAmounts is each rank's payout = floor(pot*bps/10000), top prize first.
func PrizeAmounts(pot *big.Int, tiers []PrizeTier) []*big.Int {
	bps := tierBps(tiers)
	out := make([]*big.Int, len(bps))
	for i, b := range bps {
		out[i] = new(big.Int).Quo(new(big.Int).Mul(pot, big.NewInt(int64(b))), big.NewInt(10000))
	}
	return out
}

// sortEntrants returns entrants with weight > 0, in canonical draw order
// (ascending EIP-55 Hex), matching the backend's Window.Wallets.
func sortEntrants(entrants []Entrant) []Entrant {
	pool := make([]Entrant, 0, len(entrants))
	for _, e := range entrants {
		if e.Weight > 0 {
			pool = append(pool, e)
		}
	}
	sort.Slice(pool, func(i, j int) bool { return pool[i].Addr.Hex() < pool[j].Addr.Hex() })
	return pool
}

// EntrantsHash is the on-chain commitment to the frozen entrant list:
// keccak256 of each (20-byte addr ++ 32-byte big-endian weight) in canonical
// order. Must equal the entrantsHash stored at endLottoRound.
func EntrantsHash(entrants []Entrant) [32]byte {
	pool := sortEntrants(entrants)
	var buf []byte
	for _, e := range pool {
		buf = append(buf, e.Addr[:]...)
		var w [32]byte
		new(big.Int).SetUint64(e.Weight).FillBytes(w[:])
		buf = append(buf, w[:]...)
	}
	var out [32]byte
	copy(out[:], keccak256(buf))
	return out
}

// DrawWinners picks up to k distinct winners, weighted without replacement, in
// draw order (index 0 = first drawn). Draw i uses
// HMAC-SHA256(serverSeed, randomness || uint64-be(i)) mod remainingTotal.
// Byte-identical to the backend's lotto.DrawWinners.
func DrawWinners(entrants []Entrant, k int, serverSeed, randomness []byte) []Address {
	pool := sortEntrants(entrants)
	var total uint64
	for _, e := range pool {
		total += e.Weight
	}
	if k > len(pool) {
		k = len(pool)
	}
	winners := make([]Address, 0, k)
	for i := 0; i < k && total > 0; i++ {
		mac := hmac.New(sha256.New, serverSeed)
		mac.Write(randomness)
		var ib [8]byte
		binary.BigEndian.PutUint64(ib[:], uint64(i))
		mac.Write(ib[:])
		r := new(big.Int).Mod(new(big.Int).SetBytes(mac.Sum(nil)), new(big.Int).SetUint64(total)).Uint64()

		var cum uint64
		pick := len(pool) - 1
		for j := range pool {
			cum += pool[j].Weight
			if r < cum {
				pick = j
				break
			}
		}
		winners = append(winners, pool[pick].Addr)
		total -= pool[pick].Weight
		pool = append(pool[:pick], pool[pick+1:]...)
	}
	return winners
}

// Winner is a (wallet, prize) pair in prize order (index 0 = top prize).
type Winner struct {
	Addr   Address
	Amount *big.Int
}

// ComputeWinners reproduces the round's winner→amount list: draw the winners,
// then assign prizes biggest-first (first-drawn gets the grand prize) by pairing
// the draw order directly against the top-first prize ladder. So the grand prize
// is drawn first from the full ticket-weighted pool, then each smaller prize
// from the wallets that remain. Ranks that floor to zero are dropped.
// Byte-identical to the backend's computeEntries.
func ComputeWinners(entrants []Entrant, pot *big.Int, tiers []PrizeTier, serverSeed, randomness []byte) []Winner {
	amounts := PrizeAmounts(pot, tiers)
	drawn := DrawWinners(entrants, len(amounts), serverSeed, randomness)
	out := make([]Winner, 0, len(drawn))
	for i, a := range drawn {
		if amounts[i].Sign() == 0 {
			continue
		}
		out = append(out, Winner{Addr: a, Amount: amounts[i]})
	}
	return out
}
