package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"

	//"github.com/ethereum/go-ethereum/crypto/bn256"
	"github.com/AUKUS561/PVOABE/LSSS"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/sample"
)

type PublicParameter struct {
	G     *bn256.G1            //群生成元g
	H     *bn256.G1            //h
	HXs   map[string]*bn256.G1 //{hx}
	Pk    *bn256.G1            //Pk=h^a
	PkXs  map[string]*bn256.G1 //{Pkxs}
	Order *big.Int             //群的阶
}

type SecretKey struct {
	A *big.Int //SK=a
}

type PVGSS struct {
	P *big.Int
}

func NewPVGSS() *PVGSS {
	return &PVGSS{P: bn256.Order}
}

// (SK, PP) ← PVGSS.Setup(1κ, U)
// 输入属性宇宙U，按照"清华 北大 博士 硕士 教授"格式输入，属性之间按空格分开
func (pvgss *PVGSS) Setup(attributeUniverse string) (*PublicParameter, *SecretKey, error) {
	//G1的生成元g
	g := new(bn256.G1).ScalarBaseMult(big.NewInt(1))

	//β←Zp, h = g^β
	sampler := sample.NewUniformRange(big.NewInt(1), pvgss.P)
	beta, _ := sampler.Sample()
	h := new(bn256.G1).ScalarMult(g, beta)
	//a←Zp, pk = h^a
	a, _ := sampler.Sample()
	pk := new(bn256.G1).ScalarMult(h, a)
	//对每一个属性x in U , 生成hx, 计算pkx = hx^a
	hxs := make(map[string]*bn256.G1)
	pkxs := make(map[string]*bn256.G1)
	//将整个attributeUniverse按空格分割为单个属性
	singleAtt := strings.Split(attributeUniverse, " ")
	//将每个属性通过HashToG1函数映射到G1群上
	//最终hx的结构是map[string]*bn256.G1 ,即属性名作索引，实际值为G1群元素
	for _, x := range singleAtt {
		hx := HashToG1(x)
		pkx := new(bn256.G1).ScalarMult(hx, a)
		hxs[x] = hx
		pkxs[x] = pkx
	}

	PP := &PublicParameter{
		G:     g,
		H:     h,
		HXs:   hxs,
		Pk:    pk,
		PkXs:  pkxs,
		Order: pvgss.P,
	}

	SK := &SecretKey{
		A: a,
	}

	return PP, SK, nil
}

type OSK struct {
	L   *bn256.G1
	KXs map[string]*bn256.G1
}

// OSK ← PVGSS.KeyGen(Su)
func (pvgss *PVGSS) KeyGen(pp *PublicParameter, attributeSet string) (*OSK, error) {
	p := pp.Order //群的阶p
	//t←Zp,L=g^t
	sampler := sample.NewUniformRange(big.NewInt(1), p)
	t, _ := sampler.Sample()
	l := new(bn256.G1).ScalarBaseMult(t) //L=g^t
	//{Kx = pkx^t}x∈Su
	kxs := make(map[string]*bn256.G1)
	//1.从用户属性集合attributeSet中分割出单个属性
	singleAtt := strings.Split(attributeSet, " ")
	for _, x := range singleAtt {
		//2.找到该属性对应的pkx
		_, ok := pp.PkXs[x]
		if !ok {
			return nil, fmt.Errorf("attribute %s not in public parameters", x)
		}
		//3.计算Kx=pkx^t
		kxs[x] = new(bn256.G1).ScalarMult(pp.PkXs[x], t)
	}

	return &OSK{L: l, KXs: kxs}, nil
}

type CipherText struct {
	Ci      map[int]*bn256.G1
	CiPrime *bn256.G1
}

// Ci, Ci'} ← PVGSS.Share(B, τ)
func (pvgss *PVGSS) Share(pp *PublicParameter, b *bn256.G1, msp *abe.MSP) (*CipherText, error) {
	p := pp.Order
	//生成一个随机秘密t，用于LSSS秘密分享
	sampler := sample.NewUniformRange(big.NewInt(1), p)
	t, _ := sampler.Sample()
	// {lambda_i} <- LSSS.Share(s, τ)
	lambdaI, _ := LSSS.Share(msp, t, p)
	for i, lambda := range lambdaI {
		bi := make(map[int]*bn256.G1)
		bi[i] = new(bn256.G1).ScalarMult(b, lambda) //bi=b^lambdai
		//ri<-Zp
		ri, _ := sampler.Sample()
		attri := msp.RowToAttrib[i]
		pki := pp.PkXs[attri]
		//-ri
		negRi := new(big.Int).Neg(ri)
		negRi = negRi.Mod(negRi, p)
		//pki^-ri
		part := new(bn256.G1).ScalarMult(pki, negRi)
		//ci = bi*pki^-ri
		ci := make(map[int]*bn256.G1)
		ci[i] = new(bn256.G1).Add(pki, part)
		//ci'=g^ri
		ciprime := new(bn256.G1).ScalarBaseMult(ri)
		shares[i] := &CipherText{Ci: ci, CiPrime: ciprime}
	}
	return shares, nil
}

// HashToG1函数实现将一个属性x映射到G1群上的一个点
func HashToG1(attribute string) *bn256.G1 {
	//将属性经过hash，并转化为一个大整数z
	h := sha256.Sum256([]byte(attribute))
	z := new(big.Int).SetBytes(h[:])
	//将z映射到G1群上
	g := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	hx := new(bn256.G1).ScalarMult(g, z)
	return hx
}
