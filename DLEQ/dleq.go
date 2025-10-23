package DLEQ

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	//bn256 "github.com/ethereum/go-ethereum/crypto/bn256/google"
	"github.com/fentec-project/bn256"
)

type Prfs struct {
	C, T *big.Int
	A    *bn256.GT
	B    *bn256.G1
}

func Proof(x *big.Int, u, y1 *bn256.GT, v, y2 *bn256.G1) (*Prfs, error) {
	//生成承诺
	r, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, err
	}
	a := new(bn256.GT).ScalarMult(u, r)
	b := new(bn256.G1).ScalarMult(v, r)

	// 计算挑战
	new_hash := sha256.New()
	new_hash.Write(a.Marshal())
	new_hash.Write(b.Marshal())
	new_hash.Write(y1.Marshal())
	new_hash.Write(y2.Marshal())

	cb := new_hash.Sum(nil)
	c := new(big.Int).SetBytes(cb)
	c.Mod(c, bn256.Order)

	// 生成响应 t=r-cx
	t := new(big.Int).Mul(c, x)
	t.Sub(r, t)
	t.Mod(t, bn256.Order)

	return &Prfs{
		C: c, T: t, A: a, B: b,
	}, nil
}

// Verify verifies the DLEQ proof
func Verify(pi *Prfs, u, y1 *bn256.GT, v, y2 *bn256.G1) bool {
	ut := new(bn256.GT).ScalarMult(u, pi.T)
	vt := new(bn256.G1).ScalarMult(v, pi.T)
	cy1 := new(bn256.GT).ScalarMult(y1, pi.C)
	cy2 := new(bn256.G1).ScalarMult(y2, pi.C)
	a := new(bn256.GT).Add(ut, cy1)
	b := new(bn256.G1).Add(vt, cy2)
	return (pi.A.String() == a.String() && pi.B.String() == b.String())
}
