package verify

import (
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/sha3"
)

// Address is a 20-byte EVM address.
type Address [20]byte

// ParseAddress accepts a 0x-prefixed (or bare) 40-hex-character address.
func ParseAddress(s string) (Address, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	var a Address
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 20 {
		return a, fmt.Errorf("bad address %q", s)
	}
	copy(a[:], b)
	return a, nil
}

// Hex returns the EIP-55 checksummed "0x…" form. This MUST match
// go-ethereum's common.Address.Hex(), because the draw walks entrants in
// ascending Hex() order and a different casing would change who wins.
func (a Address) Hex() string {
	lower := hex.EncodeToString(a[:]) // 40 lowercase hex chars
	h := keccak256([]byte(lower))
	out := []byte("0x" + lower)
	for i := 0; i < 40; i++ {
		c := out[2+i]
		if c < 'a' || c > 'f' {
			continue // digits are never cased
		}
		// nibble i of the hash: high nibble for even i, low nibble for odd i.
		var nibble byte
		if i%2 == 0 {
			nibble = h[i/2] >> 4
		} else {
			nibble = h[i/2] & 0x0f
		}
		if nibble >= 8 {
			out[2+i] = c - 32 // uppercase
		}
	}
	return string(out)
}

func keccak256(chunks ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, c := range chunks {
		h.Write(c)
	}
	return h.Sum(nil)
}
