// Command lotto-verify RE-RUNS a published lotto round from its public inputs
// and shows the proof: every input, the full winners list it recomputes, and
// the recomputed values next to the published/on-chain ones so you can see they
// match, not just a PASS stamp. It accepts either:
//
//	go run ./cmd/lotto-verify round-42.lotto-verify.json   # a bundle downloaded from the app
//	go run ./cmd/lotto-verify testdata/round-1000          # a round-<N>/ directory
package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	verify "github.com/streakfun/lotto-verify"
)

// quicknet is drand's public randomness beacon the draw is seeded from.
const quicknetChainHash = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: lotto-verify <round-bundle.json | round-dir>")
		os.Exit(2)
	}
	b, err := loadBundle(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	// Recompute the whole draw from the public inputs alone.
	rep, err := verify.VerifyBundleData(b)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	printProof(b, rep)
	if !rep.OK() {
		os.Exit(1)
	}
}

// loadBundle reads either a single downloaded bundle (.json) or a round-<N>/
// directory of the three raw files, into the one Bundle shape.
func loadBundle(arg string) (verify.Bundle, error) {
	var b verify.Bundle
	if strings.HasSuffix(strings.ToLower(arg), ".json") {
		data, err := os.ReadFile(arg)
		if err != nil {
			return b, err
		}
		return b, json.Unmarshal(data, &b)
	}
	if err := readJSONFile(filepath.Join(arg, "inputs.json"), &b.Inputs); err != nil {
		return b, err
	}
	if err := readJSONFile(filepath.Join(arg, "expected.json"), &b.Expected); err != nil {
		return b, err
	}
	csv, err := os.ReadFile(filepath.Join(arg, "entrants.csv"))
	if err != nil {
		return b, err
	}
	b.Entrants = string(csv)
	return b, nil
}

func readJSONFile(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

const (
	rule = "────────────────────────────────────────────────────────────────────────────"
	ok   = "✓"
	bad  = "✗"
)

func mark(good bool) string {
	if good {
		return ok
	}
	return bad
}

func printProof(b verify.Bundle, rep verify.Report) {
	in, exp := b.Inputs, b.Expected

	fmt.Printf("\n%s\n  LOTTO ROUND %d · PROOF OF FAIRNESS\n%s\n", rule, in.Round, rule)
	fmt.Println("  This re-runs the draw from the public inputs and shows every value it")
	fmt.Println("  produces next to the value that was published / committed on-chain.")

	// --- Public inputs -------------------------------------------------------
	fmt.Printf("\nPUBLIC INPUTS  (all fixed before the outcome could be known)\n")
	fmt.Printf("  server seed        %s\n", in.ServerSeed)
	fmt.Printf("                     its sha256 was committed on-chain at round start, so the\n")
	fmt.Printf("                     draw is locked to this seed before any bet was placed\n")
	fmt.Printf("  drand round        %d  (committed at freeze, before its randomness existed)\n", in.DrandRound)
	fmt.Printf("  drand randomness   %s\n", in.DrandRandomness)
	fmt.Printf("  pot                %s USDG  (%s base units)\n", usdg(in.Pot), in.Pot)
	fmt.Printf("  prize tiers        %s\n", tierSummary(in.Tiers))
	fmt.Printf("  entrants           %d wallets (weighted by tickets)\n", entrantCount(b.Entrants))

	// --- Step 1: beacon ------------------------------------------------------
	fmt.Printf("\nSTEP 1 · the randomness is genuine drand, not the operator's\n")
	if rep.BeaconChecked {
		fmt.Printf("  [%s] beacon signature verified against the drand quicknet public key\n", mark(rep.BeaconOK))
		fmt.Printf("  [%s] randomness == sha256(signature)  (the seed the draw actually used)\n", mark(rep.BeaconOK))
		fmt.Printf("      fetch it yourself: https://api.drand.sh/%s/public/%d\n", quicknetChainHash, in.DrandRound)
	} else {
		fmt.Printf("  [-] no drand signature in the bundle, so beacon authenticity is NOT checked\n")
	}

	// --- Step 2: entrants hash ----------------------------------------------
	fmt.Printf("\nSTEP 2 · the entrant list is the exact one frozen at draw time\n")
	fmt.Printf("  recomputed   %s\n", rep.ComputedEntrants)
	fmt.Printf("  published    %s\n", with0x(exp.EntrantsHash))
	fmt.Printf("  [%s] %s\n", mark(rep.EntrantsHashOK), matchWord(rep.EntrantsHashOK))

	// --- Step 3: winners -----------------------------------------------------
	fmt.Printf("\nSTEP 3 · the winners, RECOMPUTED from the seed (biggest prize first)\n")
	fmt.Printf("  drawn as  r_i = HMAC_SHA256(serverSeed, randomness ‖ i) mod totalTickets\n\n")
	fmt.Printf("  %-4s  %-42s  %-16s  %s\n", "RANK", "WINNER (recomputed)", "PRIZE (USDG)", "vs published")
	fmt.Printf("  %-4s  %-42s  %-16s  %s\n", "────", strings.Repeat("─", 42), strings.Repeat("─", 16), "────────────")
	allWinnersMatch := len(rep.Winners) == len(exp.Winners)
	for i, w := range rep.Winners {
		matchStr := "(no published row)"
		rowOK := false
		if i < len(exp.Winners) {
			e := exp.Winners[i]
			rowOK = strings.EqualFold(w.Addr.Hex(), with0x(e.Address)) && w.Amount.String() == e.Amount
			matchStr = mark(rowOK)
			if !rowOK {
				matchStr = fmt.Sprintf("%s  published: %s / %s", bad, e.Address, usdg(e.Amount))
			}
		}
		allWinnersMatch = allWinnersMatch && rowOK
		fmt.Printf("  #%-3d  %-42s  %-16s  %s\n", i+1, w.Addr.Hex(), usdg(w.Amount.String()), matchStr)
	}
	fmt.Printf("\n  [%s] %d/%d winners match the published list (address, amount AND order)\n",
		mark(allWinnersMatch), matchCount(rep.Winners, exp), len(exp.Winners))

	// --- Step 4: merkle root -------------------------------------------------
	fmt.Printf("\nSTEP 4 · the winner merkle root (what a claim is checked against on-chain)\n")
	fmt.Printf("  recomputed   %s\n", rep.ComputedRoot)
	fmt.Printf("  published    %s\n", with0x(exp.MerkleRoot))
	fmt.Printf("  [%s] %s\n", mark(rep.MerkleRootOK), matchWord(rep.MerkleRootOK))

	// --- Verdict -------------------------------------------------------------
	fmt.Printf("\n%s\n", rule)
	if rep.OK() {
		fmt.Printf("  RESULT: PASS. Every winner and amount reproduces from the public inputs.\n")
		fmt.Printf("  Same inputs → same output, on any machine. Nobody could have altered it.\n")
	} else {
		fmt.Printf("  RESULT: FAIL. The recomputed draw does NOT match what was published.\n")
		fmt.Printf("  The published draw is not reproducible from its inputs. Do not trust it.\n")
	}
	fmt.Printf("%s\n\n", rule)
}

func matchWord(good bool) string {
	if good {
		return "IDENTICAL"
	}
	return "MISMATCH (the recomputed value differs from what was published)"
}

func matchCount(got []verify.Winner, exp verify.Expected) int {
	n := 0
	for i, w := range got {
		if i < len(exp.Winners) &&
			strings.EqualFold(w.Addr.Hex(), with0x(exp.Winners[i].Address)) &&
			w.Amount.String() == exp.Winners[i].Amount {
			n++
		}
	}
	return n
}

func tierSummary(tiers []verify.PrizeTier) string {
	if len(tiers) == 0 {
		return "(default)"
	}
	var parts []string
	total := 0
	for _, t := range tiers {
		parts = append(parts, fmt.Sprintf("%d×%.2f%%", t.Count, float64(t.Bps)/100))
		total += int(t.Count)
	}
	return fmt.Sprintf("%d winners · %s", total, strings.Join(parts, ", "))
}

func entrantCount(csv string) int {
	n := 0
	for i, line := range strings.Split(strings.TrimSpace(csv), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if i == 0 && strings.HasPrefix(strings.ToLower(line), "address") {
			continue // header
		}
		n++
	}
	return n
}

// usdg formats 6-dp base units (a decimal string) as a USDG amount.
func usdg(base string) string {
	n, ok := new(big.Int).SetString(strings.TrimSpace(base), 10)
	if !ok {
		return base
	}
	d := big.NewInt(1_000_000)
	q, r := new(big.Int).QuoRem(new(big.Int).Abs(n), d, new(big.Int))
	s := fmt.Sprintf("%d.%06d", q, r)
	if n.Sign() < 0 {
		s = "-" + s
	}
	return s
}

func with0x(s string) string {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return s
	}
	return "0x" + s
}
