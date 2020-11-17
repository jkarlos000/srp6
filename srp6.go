package srp

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"math/big"

	"fmt"
	"strings"
)

const sByteSize = 32

func reverse(s []byte) []byte {
	runes := s
	for i, j := 0, len(runes) - 1; i < j; i, j = i + 1, j - 1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return runes
}

func Hash(u, p string) string {
	rI := strings.ToUpper(u+":"+p)
	sha := sha1.New()
	sha.Write([]byte(rI))
	return strings.ToUpper(hex.EncodeToString(sha.Sum(nil)))
}

type SRP struct {
	// large safe prime number
	N *big.Int
	// generator modulo N
	g *big.Int
	// salt
	s *big.Int
	// password verifier
	v *big.Int
}

func (srp *SRP) ComputeVerifier(rI string) {
	I := new(big.Int)
	I.SetString(rI, 16)

	sha := sha1.New()
	sha.Write(reverse(srp.s.Bytes()))
	sha.Write(I.Bytes())

	x := new(big.Int)
	x.SetBytes(reverse(sha.Sum(nil)))
	srp.v.Exp(srp.g, x, srp.N)
}

func (srp *SRP) GenerateSalt() error {
	b := make([]byte, sByteSize)
	_, err := rand.Read(b)
	if err != nil {
		return err
	}
	srp.s.SetBytes(b)
	return nil
}

func (srp *SRP) GetSalt() string {
	return fmt.Sprintf("%X", srp.s)
}

func (srp *SRP) GetVerifier() string {
	return fmt.Sprintf("%X", srp.v)
}

func New() *SRP {
	srp :=  &SRP{
		N: new(big.Int),
		g: new(big.Int),
		s: new(big.Int),
		v: new(big.Int),
	}
	srp.N.SetString("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7", 16)
	srp.g.SetString("7", 16)
	return srp
}

func (srp *SRP) ProofVerifier(v string) bool {
	_v := new(big.Int)
	_v.SetString(v, 16)

	if srp.v.Cmp(_v) == 0 {
		return true
	}

	return false
}

func (srp *SRP) SetSalt(s string) {
	srp.s.SetString(s, 16)
}

func (srp *SRP) SetVerifier(v string) {
	srp.v.SetString(v, 16)
}
