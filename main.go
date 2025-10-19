package main

import (
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/bn256"
)

type PublicKey struct {
	G     *bn256.G1            //群生成元g
	H     *bn256.G1            //h
	HXs   map[string]*bn256.G1 //{hx}
	Pk    *bn256.G1
	PkXs  map[string]*bn256.G1 //{Pkxs}
	Order *big.Int
}
