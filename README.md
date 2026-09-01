# lotto-verify

A small program that re-runs a Streakfun lottery draw so you can check the
winners yourself.

Every draw is decided by two public values: a server seed and a random number
from [drand](https://drand.love), both locked in before anyone could know the
outcome. This program takes those values and redoes the entire draw. It picks
the winners, works out each prize, and rebuilds the merkle root that the payout
contract checks claims against. If what it computes matches what the app
published and what's on-chain, the draw was honest. If it doesn't, the draw was
changed after the fact, and the output shows you exactly where.

Nothing here calls a server. You hand it one file, it does the math offline, and
it prints the result. Same file in, same result out, on any machine.

## What you need

Go 1.21 or newer (`go version` to check). That's it. The file you verify
carries everything the check needs.

On a fresh clone, run `go mod tidy` once to pull the single external library
(the one that checks the drand signature):

```
git clone https://github.com/pixel8labs/lotto-verify.git
cd lotto-verify
go mod tidy
```

## How to verify a round

1. Open the draw in the app: Lottery, then All Draws, then click the finished
   round. (Or use the Provably fair panel on the current round once it's drawn.)
2. Click **Download verifier bundle**. You get a file named
   `round-<N>.lotto-verify.json`. It holds the seed, the drand round, the full
   entrant list, and the winners the app published.
3. Point the program at that file:

```
go run ./cmd/lotto-verify round-3.lotto-verify.json
```

Use the real path to the file, for example `~/Downloads/round-3.lotto-verify.json`.

## What it shows you

It doesn't just say PASS. It lays out the whole proof so you can read it instead
of trusting it:

```
  LOTTO ROUND 3 · PROOF OF FAIRNESS

PUBLIC INPUTS  (all fixed before the outcome could be known)
  server seed        0xc7d78504…b0ef   (its sha256 was committed on-chain at round start)
  drand round        31647972          (committed at freeze, before its randomness existed)
  drand randomness   0x7e28b101…7205
  pot                396.353600 USDG
  prize tiers        30 winners · 1×26.00%, 1×12.00%, 1×9.00%, …
  entrants           43 wallets (weighted by tickets)

STEP 1 · the randomness is genuine drand, not the operator's
  [✓] beacon signature verified against the drand quicknet public key
      fetch it yourself: https://api.drand.sh/<chain>/public/31647972

STEP 2 · the entrant list is the exact one frozen at draw time
  recomputed   0xe6665f72…0d19
  published    0xe6665f72…0d19
  [✓] IDENTICAL

STEP 3 · the winners, RECOMPUTED from the seed (biggest prize first)
  RANK  WINNER (recomputed)                         PRIZE (USDG)      vs published
  #1    0x980500761478dfCad730f0eA20496075a9989bf0  103.051936        ✓
  #2    0x8EC73d831E7Ffcd7F630b86741D6db6E52BB6477  47.562432         ✓
  …
  [✓] 30/30 winners match the published list (address, amount AND order)

STEP 4 · the winner merkle root (what a claim is checked against on-chain)
  recomputed   0x6fa764b0…bb0f
  published    0x6fa764b0…bb0f
  [✓] IDENTICAL

  RESULT: PASS. Every winner and amount reproduces from the public inputs.
```

Read it top to bottom:

- **Public inputs** are the seed, the drand round and its randomness, the pot,
  and the prize split. All of them were fixed before the winners could be known.
- **Step 1** confirms the random number is a real drand beacon, and gives you a
  link to fetch that same number yourself from any drand relay.
- **Step 2** rebuilds the entrant list's hash and prints it next to the one
  committed on-chain.
- **Step 3** is the full winners list, worked out from scratch, with each prize,
  next to the list the app published. Every row should match on address, amount,
  and rank.
- **Step 4** is the merkle root it rebuilt, next to the on-chain root.

If any line differs, that row shows a ✗ with both values side by side, and the
program exits with an error code so it's safe to drop into a script. Try it:
open the JSON, change one winner's amount, run it again, and watch it fail.

You can also verify the checked-in example, which ships as a folder of the three
raw files instead of one bundle:

```
go run ./cmd/lotto-verify testdata/round-1000
```

It prints the same layout.

## How a round is decided

1. **Commit.** Before the draw, the operator commits `sha256(serverSeed)`
   on-chain. At freeze it also commits the drand round `R` and the
   `entrantsHash` (a keccak256 of the frozen `wallet → weight` list). All three
   are on-chain before the randomness for round `R` exists, so none of them can
   be chosen to fit a wanted result.
2. **Randomness.** The draw uses round `R`'s drand quicknet beacon. Its
   randomness is `sha256(signature)`. Nobody can predict or forge a given round.
3. **Draw.** For each winner `i`, the draw computes
   `r_i = HMAC_SHA256(serverSeed, drandRandomness ‖ uint64_be(i)) mod total`. It
   walks the entrants in a fixed order (ascending EIP-55 address) and removes a
   wallet's whole weight once it wins, so no wallet wins twice.
4. **Prizes.** The winners are ranked biggest prize first. The wallet drawn
   first gets the grand prize, and each next prize goes to the next wallet drawn.
   More tickets means a bigger slice of the pool, so a better chance, never a
   guaranteed win.
5. **Publish.** The server seed, the drand round and randomness, the entrant
   list, and the winners all go public, together with this code.

This program re-runs steps 3 and 4 and rebuilds the merkle root over the winners.

## What the program checks, and what you check yourself

The program proves the draw is **reproducible**: run the same inputs and you get
the same winners and the same merkle root, every time. That is what shows the
winners were computed honestly from the given randomness.

Two things close the loop, and they are yours to check against the chain:

- The `entrant-list hash` the program prints should equal the `entrantsHash`
  committed on-chain at freeze. (The entrant list itself is the wallets and
  their ticket weights over the round's block range.)
- The `merkle root` the program prints should equal the `merkleRoot` finalized
  on-chain. The app's own `/verify` endpoint refuses to serve a bundle whose
  root doesn't match the chain, but reading it off the contract yourself is the
  stronger check.

## Is the random number really drand's?

The one thing that makes the randomness nobody's to control is that it is a real
drand beacon, not a number the operator picked. `VerifyBeacon(round, signature)`
in `beacon.go` checks the round's BLS signature against drand's fixed public key:
the pairing check `e(sig, g2) == e(H(sha256(uint64_be(round)))→G1, publicKey)`,
with the quicknet key baked in, then `randomness = sha256(signature)`.

You can fetch the beacon from any relay and check it yourself:

```
https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/<R>
```

That returns `{round, randomness, signature}`. The check trusts drand's public
key, not the relay you fetched from. The same verification, against the same
round-1000 vector, also runs and passes in the backend's Solidity test
`contracts-foundry/test/lib/DrandQuicknet.t.sol`.

drand quicknet parameters:

```
chain hash : 52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971
genesis    : 1692803367   period: 3s
scheme     : bls-unchained-g1-rfc9380  (randomness = sha256(signature))
```

## The files inside a bundle

A downloaded bundle is one JSON file. The directory form (used by the checked-in
example) is the same data as three files:

```
round-<N>/
├── inputs.json     round, drandRound, serverSeed, drandRandomness, pot, tiers
├── entrants.csv    address,weight  (one row per wallet)
└── expected.json   entrantsHash, merkleRoot, winners[]
```

`testdata/round-1000` is a worked example built from a real drand quicknet round
(round 1000) with a sample 50-wallet entrant set. Regenerate it with
`go run ./cmd/gen`.

## Why the math matches production

The draw, the EIP-55 ordering, and the OpenZeppelin StandardMerkleTree in this
repo are byte-for-byte the same as the backend's production code. That is pinned
by `TestReproducesBackendRoot`, which checks this reference produces the exact
merkle root the backend committed for the round-1000 inputs. Run the whole suite
with `go test ./...`.

## Dependencies

Two, and only one touches the core draw:

- `golang.org/x/crypto/sha3` for keccak256.
- `github.com/consensys/gnark-crypto` for the BLS12-381 math behind the drand
  signature check in `beacon.go`.

Everything else (the draw, HMAC, SHA-256, the merkle tree) is the Go standard
library.
