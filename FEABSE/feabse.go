package feabse

import (
	"crypto/sha256"
	"log"
	"math/big"

	"github.com/AUKUS561/PVOABE/LSSS"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/sample"
)

type FEABSE struct {
	P *big.Int
}

func NewFEABSE() *FEABSE {
	return &FEABSE{
		P: bn256.Order,
	}
}

// MPK = (PP, g^β, g^γ, e(g,g)^α, {PAK_x})
type MPK struct {
	Order    *big.Int             // p
	G        *bn256.G1            // g ∈ G1
	G2       *bn256.G2            // g2 ∈ G2, Only for pairing
	EGG      *bn256.GT            // e(g, g2)
	GBeta    *bn256.G1            // g^β
	GGamma   *bn256.G1            // g^γ
	EGGAlpha *bn256.GT            // e(g, g2)^α
	G2Beta   *bn256.G2            // g2^β = (G2)^β，to compute CT^x
	PAK      map[string]*bn256.G1 // For each attr x , PAKx = g^{ηx}
}

// MSK = (α, β)
type MSK struct {
	Alpha *big.Int            // α
	Beta  *big.Int            // β
	Gamma *big.Int            // γ
	Eta   map[string]*big.Int // Attr x -> ηx
}

// Setup(U) -> (MPK, MSK)
func (feabse *FEABSE) Setup(U []string) (*MPK, *MSK) {
	sampler := sample.NewUniformRange(big.NewInt(1), feabse.P)

	// α, β, γ ← Zp
	alpha, _ := sampler.Sample()
	beta, _ := sampler.Sample()
	gamma, _ := sampler.Sample()

	// g, g2
	g := new(bn256.G1).ScalarBaseMult(big.NewInt(1))  // g ∈ G1
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1)) // g2 ∈ G2

	// e(g, g2)
	egg := bn256.Pair(g, g2)

	// e(g, g2)^α
	eggAlpha := new(bn256.GT).ScalarMult(egg, alpha)

	// g^β, g^γ
	gBeta := new(bn256.G1).ScalarMult(g, beta)
	gGamma := new(bn256.G1).ScalarMult(g, gamma)

	// g2^β
	g2Beta := new(bn256.G2).ScalarMult(g2, beta)

	//For each attr x ∈ U compute ηx 和 PAKx = g^{ηx}
	pak := make(map[string]*bn256.G1)
	etaMap := make(map[string]*big.Int)

	for _, x := range U {
		eta, _ := sampler.Sample() // ηx ← Zp
		etaMap[x] = new(big.Int).Set(eta)
		pak[x] = new(bn256.G1).ScalarMult(g, eta) // PAKx = g^{ηx}
	}

	mpk := &MPK{
		Order:    feabse.P,
		G:        g,
		G2:       g2,
		EGG:      egg,
		GBeta:    gBeta,
		GGamma:   gGamma,
		EGGAlpha: eggAlpha,
		G2Beta:   g2Beta,
		PAK:      pak,
	}

	msk := &MSK{
		Alpha: alpha,
		Beta:  beta,
		Gamma: gamma,
		Eta:   etaMap,
	}

	return mpk, msk
}

// SKdu = (D1, D2, D3, D4, D5, {Dx, Tx})
type SKdu struct {
	D1 *bn256.G2            // g^α · g^{γt}
	D2 *bn256.G2            // g^t
	D3 *bn256.G2            // g^{yβ}
	D4 *bn256.G2            // g^y
	D5 *big.Int             // β / y
	Dx map[string]*bn256.G2 // Dx = H0(x)^{t/ηx}
	Tx map[string]*bn256.G1 // Tx = H0(x)^β
}

// KeyGen(MPK, MSK, SID) → SKdu
func (feabse *FEABSE) KeyGen(mpk *MPK, msk *MSK, SID []string) *SKdu {
	sampler := sample.NewUniformRange(big.NewInt(1), feabse.P)

	// t, y ∈ Zp
	t, _ := sampler.Sample()
	y, _ := sampler.Sample()

	// D1 = g2^α · g2^{γt}
	D1alpha := new(bn256.G2).ScalarMult(mpk.G2, msk.Alpha)
	g2Gamma := new(bn256.G2).ScalarMult(mpk.G2, msk.Gamma)
	g2GammaT := new(bn256.G2).ScalarMult(g2Gamma, t)
	D1 := new(bn256.G2).Add(D1alpha, g2GammaT)

	// D2 = g2^t
	D2 := new(bn256.G2).ScalarMult(mpk.G2, t)

	// D3 = g2^{y β}
	yBeta := new(big.Int).Mul(y, msk.Beta)
	yBeta.Mod(yBeta, feabse.P)
	D3 := new(bn256.G2).ScalarMult(mpk.G2, yBeta)

	// D4 = g2^y
	D4 := new(bn256.G2).ScalarMult(mpk.G2, y)

	// D5 = β / y = β · y^{-1} mod p
	yInv := new(big.Int).ModInverse(y, feabse.P)
	D5 := new(big.Int).Mul(msk.Beta, yInv)
	D5.Mod(D5, feabse.P)

	Dx := make(map[string]*bn256.G2, len(SID))
	Tx := make(map[string]*bn256.G1, len(SID))

	for _, x := range SID {
		etaX, ok := msk.Eta[x]
		if !ok || etaX == nil {
			log.Fatal("Attr not in U")
		}

		// H0G2(x) ∈ G2，to compute Dx
		hxG2 := HashToG2(x)

		// exponent = t / ηx = t · ηx^{-1} mod p
		etaInv := new(big.Int).ModInverse(etaX, feabse.P)
		expShare := new(big.Int).Mul(t, etaInv)
		expShare.Mod(expShare, feabse.P)

		// Dx = H0_G2(x)^{t/ηx}
		Dx[x] = new(bn256.G2).ScalarMult(hxG2, expShare)

		// H0_G1(x) ∈ G1，to compute Tx
		hxG1 := HashToG1(x)
		// Tx = H0_G1(x)^β
		Tx[x] = new(bn256.G1).ScalarMult(hxG1, msk.Beta)
	}

	sk := &SKdu{
		D1: D1,
		D2: D2,
		D3: D3,
		D4: D4,
		D5: D5,
		Dx: Dx,
		Tx: Tx,
	}

	return sk
}

// IC = {IC0, IC1, ICi, ICi2}
type IC struct {
	S       *big.Int             // The random s selected during the offline phase is required for online encryption
	IC0     *bn256.GT            // IC0 = e(g,g)^{α s} = (EGGAlpha)^s
	IC1     *bn256.G1            // IC1 = g^s
	ICAttr1 map[string]*bn256.G1 // For each attr x: ICi= H0(x)^{-γx}
	ICAttr2 map[string]*bn256.G1 // For each attr x: ICi2^ = PAKx^{γx}
}

// OfflineEnc(MPK) → IC
func (feabse *FEABSE) OfflineEnc(mpk *MPK) *IC {
	sampler := sample.NewUniformRange(big.NewInt(1), feabse.P)

	// s ∈ Zp
	s, _ := sampler.Sample()

	// IC0 = e(g,g)^{αs} = (EGGAlpha)^s
	IC0 := new(bn256.GT).ScalarMult(mpk.EGGAlpha, s)

	// IC1 = g^s
	IC1 := new(bn256.G1).ScalarMult(mpk.G, s)

	// For each attr x ∈ U compute (ICi}, ICi2)
	ICAttr1 := make(map[string]*bn256.G1, len(mpk.PAK))
	ICAttr2 := make(map[string]*bn256.G1, len(mpk.PAK))

	for x, pakx := range mpk.PAK {
		// γx ← Zp
		gamma, _ := sampler.Sample()

		// H0(x) ∈ G1
		hx := HashToG1(x)

		// ICi = H0(x)^{-γx} = H0(x)^{p - γx}
		negGamma := new(big.Int).Sub(feabse.P, gamma)
		negGamma.Mod(negGamma, feabse.P)
		ICAttr1[x] = new(bn256.G1).ScalarMult(hx, negGamma)

		// ICi2 = PAKx^{γx}
		ICAttr2[x] = new(bn256.G1).ScalarMult(pakx, gamma)
	}

	return &IC{
		S:       s,
		IC0:     IC0,
		IC1:     IC1,
		ICAttr1: ICAttr1,
		ICAttr2: ICAttr2,
	}
}

// CT -> CT2 + CTx without CT1
type CT struct {
	//CT2 =  {(M, ρ), C0, C1, {Ci, Ci2}i∈[1,l]}.
	MSP *abe.MSP //(M, ρ)

	C0 *bn256.GT // C0 = Kθ · e(g,g)^{α s}
	C1 *bn256.G1 // C1 = g^s

	// 每一行 i 的 Ci1, Ci2，下标 i 就是 LSSS 矩阵的行号
	C1i map[int]*bn256.G1
	C2i map[int]*bn256.G1

	//CTx，for each attr appears in msp
	CTx map[string]*bn256.GT // attr x -> CTx
}

func (feabse *FEABSE) OnlineEnc(mpk *MPK, ic *IC, Ktheta *bn256.GT, msp *abe.MSP) (*CT, error) {
	//用 LSSS.Share 计算每一行的 share λi (ξi)
	lambdaMap, err := LSSS.Share(msp, ic.S, feabse.P)
	if err != nil {
		return nil, err
	}
	//Compute C0, C1
	// C0 = Kθ · IC0
	var C0 *bn256.GT
	if Ktheta != nil {
		C0 = new(bn256.GT).Add(ic.IC0, Ktheta)
	} else {
		C0 = new(bn256.GT).Set(ic.IC0)
	}

	// C1 = IC1 = g^s
	C1 := new(bn256.G1).Set(ic.IC1)

	//For each row i Compute Ci1, Ci2
	//    Ci1 = g^{γ λi} · ICi}
	//    Ci2 = ICi2
	numRows := len(msp.Mat)
	C1i := make(map[int]*bn256.G1, numRows)
	C2i := make(map[int]*bn256.G1, numRows)

	for i := 0; i < numRows; i++ {
		lambdaI := lambdaMap[i]

		attr := msp.RowToAttrib[i]

		ic1x, ok1 := ic.ICAttr1[attr]
		ic2x, ok2 := ic.ICAttr2[attr]
		if !ok1 || !ok2 {
			log.Fatalf("IC for attribute %s not found", attr)
		}

		// g^{γ λi} = (g^γ)^{λi}
		gGammaLambda := new(bn256.G1).ScalarMult(mpk.GGamma, lambdaI)

		// Ci^{<1>} = g^{γ λi} · ICx^{<1>}
		C1i[i] = new(bn256.G1).Add(gGammaLambda, ic1x)

		// Ci^{<2>} = ICx^{<2>}
		C2i[i] = new(bn256.G1).Set(ic2x)
	}

	//Compute CT^x = e(H0(x), g2^β)
	CTx := make(map[string]*bn256.GT)
	for _, attr := range msp.RowToAttrib {
		if _, exists := CTx[attr]; exists {
			continue
		}
		hx := HashToG1(attr)
		CTx[attr] = bn256.Pair(hx, mpk.G2Beta)
	}

	ct := &CT{
		MSP: msp,
		C0:  C0,
		C1:  C1,
		C1i: C1i,
		C2i: C2i,
		CTx: CTx,
	}

	return ct, nil
}

// TK = {D6, D2', Dx'}
type TK struct {
	D6      *bn256.G2            // (D1)^{1/D5} · Du
	D2Prime *bn256.G2            // D2^{1/D5}
	DxPrime map[string]*bn256.G2 // For each attr x: Dx' = Dx^{1/D5}
	Du      *bn256.G2            // g^u，Only for DU
}

// TKGen(MPK, SKdu) → TK
func (feabse *FEABSE) TKGen(mpk *MPK, sk *SKdu) *TK {
	sampler := sample.NewUniformRange(big.NewInt(1), feabse.P)

	// u ∈ Zp，Du = g2^u
	u, _ := sampler.Sample()
	Du := new(bn256.G2).ScalarMult(mpk.G2, u)

	// D5 inv: (1 / D5) = D5^{-1} mod p = (y/β)
	invD5 := new(big.Int).ModInverse(sk.D5, feabse.P)
	if invD5 == nil {
		log.Fatal("D5 has no inverse modulo p")
	}

	// D1^{1/D5} = D1^{invD5} ∈ G2
	D1Pow := new(bn256.G2).ScalarMult(sk.D1, invD5)

	// D6 = D1^{1/D5} · Du
	D6 := new(bn256.G2).Add(D1Pow, Du)

	// D2' = D2^{1/D5}
	D2Prime := new(bn256.G2).ScalarMult(sk.D2, invD5)

	//For each attr x: Dx' = Dx^{1/D5}
	DxPrime := make(map[string]*bn256.G2, len(sk.Dx))
	for x, Dx := range sk.Dx {
		DxPrime[x] = new(bn256.G2).ScalarMult(Dx, invD5)
	}

	tk := &TK{
		D6:      D6,
		D2Prime: D2Prime,
		DxPrime: DxPrime,
		Du:      Du,
	}

	return tk
}

// TCTGen(MPK, CT2, SID, TK) → TCT
func (feabse *FEABSE) TCTGen(mpk *MPK, ct *CT, SID []string, tk *TK) (*bn256.GT, error) {
	omegaMap, err := LSSS.ReconstructCoefficients(ct.MSP, SID, feabse.P)
	if err != nil {
		return nil, err
	}

	// numerator = e(C1, D6)
	numerator := bn256.Pair(ct.C1, tk.D6)

	// denominator 初始化为单位元 1，用 EGG^0 实现
	denominator := new(bn256.GT).ScalarMult(mpk.EGG, big.NewInt(0))

	for i, omega := range omegaMap {
		attr := ct.MSP.RowToAttrib[i]

		Ci1, ok1 := ct.C1i[i]
		Ci2, ok2 := ct.C2i[i]
		if !ok1 || !ok2 {
			log.Fatalf("TCTGen: ciphertext component for row %d (attr %s) not found", i, attr)
		}

		DxPrime, okDx := tk.DxPrime[attr]
		if !okDx {
			log.Fatalf("TCTGen: DxPrime for attribute %s not found in TK", attr)
		}

		// e(Ci1, D2')
		e1 := bn256.Pair(Ci1, tk.D2Prime)
		// e(Ci2, D'_{ρ(i)})
		e2 := bn256.Pair(Ci2, DxPrime)

		tmp := new(bn256.GT).Add(e1, e2)
		TCTi := new(bn256.GT).ScalarMult(tmp, omega)

		denominator.Add(denominator, TCTi)
	}

	// denominator^{-1} = denominator^{p-1}
	pMinusOne := new(big.Int).Sub(feabse.P, big.NewInt(1))
	denInv := new(bn256.GT).ScalarMult(denominator, pMinusOne)

	// TCT = numerator * denominator^{-1}
	TCT := new(bn256.GT).Add(numerator, denInv)

	return TCT, nil
}

// Dec(CT2, TCT, SKdu, TK) → Kθ
func (feabse *FEABSE) Dec(ct *CT, TCT *bn256.GT, sk *SKdu, tk *TK) *bn256.GT {
	//Compute e(C1, Du)
	eC1Du := bn256.Pair(ct.C1, tk.Du)

	// e(C1, Du)^{D5}
	eC1DuD5 := new(bn256.GT).ScalarMult(eC1Du, sk.D5)

	//Compute TCT^{D5}
	TCTD5 := new(bn256.GT).ScalarMult(TCT, sk.D5)

	//Compute(TCT^{D5})^{-1}
	pMinusOne := new(big.Int).Sub(feabse.P, big.NewInt(1))
	TCTD5Inv := new(bn256.GT).ScalarMult(TCTD5, pMinusOne)

	//Kθ = C0 * e(C1, Du)^{D5} * (TCT^{D5})^{-1}
	tmp := new(bn256.GT).Add(ct.C0, eC1DuD5)
	Ktheta := new(bn256.GT).Add(tmp, TCTD5Inv)

	return Ktheta
}

//——————————————————————————————————————Auxiliary Functions————————————————————————————————————————————//

// The HashToG1 function maps an attribute x to a point on the G1 group
func HashToG1(attribute string) *bn256.G1 {
	//Hash the attributes and convert them into a large integer z
	h := sha256.Sum256([]byte(attribute))
	z := new(big.Int).SetBytes(h[:])
	z.Mod(z, bn256.Order)
	//Map z onto G1 group
	g := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	hx := new(bn256.G1).ScalarMult(g, z)
	return hx
}

// The HashToG2 function maps an attribute x to a point on the G2 group
func HashToG2(attribute string) *bn256.G2 {
	h := sha256.Sum256([]byte(attribute))
	z := new(big.Int).SetBytes(h[:])
	z.Mod(z, bn256.Order)

	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	hx := new(bn256.G2).ScalarMult(g2, z)
	return hx
}
