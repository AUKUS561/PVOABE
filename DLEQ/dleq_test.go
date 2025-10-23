package DLEQ

import (
	"math/big"
	"testing"

	"github.com/fentec-project/bn256"
)

func TestDLEQ(t *testing.T) {
	//Verifier
	s := big.NewInt(666)
	g := new(bn256.GT).ScalarBaseMult(big.NewInt(1))
	h := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	gs := new(bn256.GT).ScalarMult(g, s)
	hs := new(bn256.G1).ScalarMult(h, s)

	proof, err := Proof(s, g, gs, h, hs)
	if err != nil {
		t.Error("fail to generate proof")
	}

	//Prover
	result := Verify(proof, g, gs, h, hs)
	t.Logf("result:%v", result)
}
