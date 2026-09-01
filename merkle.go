package verify

import (
	"bytes"
	"sort"
)

// leaf = keccak256(keccak256(abi.encode(address, uint256))). abi.encode packs
// the address left-padded to 32 bytes followed by the 32-byte amount.
// Byte-identical to the backend's merkleevm.Leaf and Solidity's claimLotto.
func leaf(w Winner) [32]byte {
	packed := make([]byte, 64)
	copy(packed[12:32], w.Addr[:])    // address in the low 20 bytes of the first word
	w.Amount.FillBytes(packed[32:64]) // amount as a 32-byte big-endian word
	var out [32]byte
	copy(out[:], keccak256(keccak256(packed)))
	return out
}

func hashPair(a, b [32]byte) [32]byte {
	var out [32]byte
	if bytes.Compare(a[:], b[:]) < 0 {
		copy(out[:], keccak256(a[:], b[:]))
	} else {
		copy(out[:], keccak256(b[:], a[:]))
	}
	return out
}

// MerkleRoot builds the OpenZeppelin StandardMerkleTree root over the winners:
// leaves sorted by hash, internal nodes hashed commutatively. Byte-identical to
// merkleevm.New(...).Root() and what finalizeLottoRound commits.
func MerkleRoot(winners []Winner) [32]byte {
	n := len(winners)
	if n == 0 {
		return [32]byte{}
	}
	leaves := make([][32]byte, n)
	for i, w := range winners {
		leaves[i] = leaf(w)
	}
	sort.Slice(leaves, func(i, j int) bool { return bytes.Compare(leaves[i][:], leaves[j][:]) < 0 })

	tree := make([][32]byte, 2*n-1)
	for i, l := range leaves {
		tree[len(tree)-1-i] = l
	}
	for i := len(tree) - 1 - n; i >= 0; i-- {
		tree[i] = hashPair(tree[2*i+1], tree[2*i+2])
	}
	return tree[0]
}
