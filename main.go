package main

import (
	"math/big"

	"github.com/AUKUS561/PVOABE/PVGSS"
	//"github.com/ethereum/go-ethereum/tests/fuzzers/bn256"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/sample"
)

type PVOABE struct {
	pvgss *PVGSS.PVGSS
	P     *big.Int
}

func NewPVOABE() *PVOABE {
	return &PVOABE{
		pvgss: PVGSS.NewPVGSS(),
		P:     bn256.Order,
	}
}

type PublicKey struct {
	PP   *PVGSS.PublicParameter
	Base *bn256.GT //e(g,g)^alpha
}

func (pvoabe *PVOABE) Setup() (*big.Int, *PublicKey, *PVGSS.SecretKey, error) {
	PP, sk, _ := PVGSS.NewPVGSS().Setup("清华 北大 海南大学 博士 硕士 教授")
	sampler := sample.NewUniformRange(big.NewInt(1), pvoabe.P)
	alpha, _ := sampler.Sample()
	g1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	res := bn256.Pair(g1, g2)                    //e(g,g)
	base := new(bn256.GT).ScalarMult(res, alpha) //e(g,g)^alpha
	return alpha, &PublicKey{PP: PP, Base: base}, sk, nil
}
