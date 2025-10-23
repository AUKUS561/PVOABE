package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"strings"

	//"github.com/ethereum/go-ethereum/crypto/bn256"

	"github.com/AUKUS561/PVOABE/DLEQ"
	"github.com/AUKUS561/PVOABE/LSSS"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/sample"
	//"github.com/AppCrypto/deTTP/crypto/dleq"
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
	Ci       *bn256.G1
	CiPrime  *bn256.G1
	CiPrime2 *bn256.G2 //ciprime2专门用于配对
}

// Ci, Ci'} ← PVGSS.Share(B, τ)
func (pvgss *PVGSS) Share(pp *PublicParameter, b *bn256.G1, msp *abe.MSP) (map[int]*CipherText, error) {
	p := pp.Order
	sampler := sample.NewUniformRange(big.NewInt(1), p)
	// {lambda_i} <- LSSS.Share(s, τ)
	lambdaI, _ := LSSS.Share(msp, big.NewInt(1), p)
	shares := make(map[int]*CipherText)
	for i, lambda := range lambdaI {
		//bi=b^lambdai
		bi := new(bn256.G1).ScalarMult(b, lambda)
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
		ci := new(bn256.G1).Add(bi, part)
		//ci'=g^ri
		ciprime := new(bn256.G1).ScalarBaseMult(ri)
		ciprime2 := new(bn256.G2).ScalarBaseMult(ri)
		shares[i] = &CipherText{Ci: ci, CiPrime: ciprime, CiPrime2: ciprime2}
	}
	return shares, nil
}

// 0/1 ← PVGSS.SVerify({Ci, Ci'}, C', τ )
func (pvgss *PVGSS) SVerify(pp *PublicParameter, ct map[int]*CipherText, cprime *bn256.G2, msp *abe.MSP) bool {
	p := pp.Order
	//∀i ∈ [1, l] : Ai = e(Ci, g)e(pkρ(i), Ci')
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1)) //生成一个G2生成元g2专门用于配对
	Ais := make(map[int]*bn256.GT)
	for i, v := range ct {
		part1 := bn256.Pair(v.Ci, g2)
		part2 := bn256.Pair(pp.PkXs[msp.RowToAttrib[i]], v.CiPrime2)
		Ais[i] = new(bn256.GT).Add(part1, part2)
	}
	//验证LSSS.Recon({Ai}i∈[1,l], τ ) ?= e(pk, C′)
	left, _ := LSSS.Recon(msp, Ais, p)
	right := bn256.Pair(pp.Pk, cprime)

	return left.String() == right.String()
}

// (R, π) ← PVGSS.Recon({Ci, Ci'}, τ, OSK, sk)
func (pvgss *PVGSS) Recon(pp *PublicParameter, ct map[int]*CipherText, msp *abe.MSP, osk *OSK, sk *SecretKey) (*bn256.GT, *DLEQ.Prfs, error) {
	p := pp.Order
	riPrime := make(map[int]*bn256.GT)

	//I = {i : ρ(i) ∈ Su}
	//遍历Kx（对应用户属性集）的属性索引i，同时遍历策略矩阵msp每一行对应的属性v，若i=v
	//则找到这一行的密文ci与ci'，执行∀i ∈ I : Ri~ = e(Ci, L)e(Ci', Kρ(i))
	for i, _ := range osk.KXs {
		for j, v := range msp.RowToAttrib {
			if i == v {
				g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
				left := bn256.Pair(ct[j].Ci, g2)
				right := bn256.Pair(osk.KXs[i], ct[j].CiPrime2)
				riPrime[j] = new(bn256.GT).Add(left, right)
			}
		}
	}
	//R ← LSSS.Recon({ ˜Ri}i∈I , τ )
	rPrime, err := LSSS.Recon(msp, riPrime, p)
	if err != nil {
		log.Fatalf("Fail to execute LSSSRecon ,Error: %v", err)
	}
	//R = ˜R^1/sk
	skInv := new(big.Int).ModInverse(sk.A, p)
	r := new(bn256.GT).ScalarMult(rPrime, skInv)
	//π ← DLEQ.Proof(sk, R, ˜R, h, pk)
	pi, err := DLEQ.Proof(sk.A, r, rPrime, pp.H, pp.Pk)
	if err != nil {
		log.Fatalf("fail to generate proof")
	}
	return r, pi, nil
}

func (pvgss *PVGSS) DVerify(pp *PublicParameter, ct map[int]*CipherText, msp *abe.MSP, osk *OSK, R *bn256.GT, proof *DLEQ.Prfs) bool {
	p := pp.Order
	riPrime := make(map[int]*bn256.GT)

	//I = {i : ρ(i) ∈ Su}
	//遍历Kx（对应用户属性集）的属性索引i，同时遍历策略矩阵msp每一行对应的属性v，若i=v
	//则找到这一行的密文ci与ci'，执行∀i ∈ I : Ri~ = e(Ci, L)e(Ci', Kρ(i))
	for i, _ := range osk.KXs {
		for j, v := range msp.RowToAttrib {
			if i == v {
				g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
				left := bn256.Pair(ct[j].Ci, g2)
				right := bn256.Pair(osk.KXs[i], ct[j].CiPrime2)
				riPrime[j] = new(bn256.GT).Add(left, right)
			}
		}
	}
	//R ← LSSS.Recon({ ˜Ri}i∈I , τ )
	rPrime, err := LSSS.Recon(msp, riPrime, p)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	return DLEQ.Verify(proof, R, rPrime, pp.H, pp.Pk)
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
