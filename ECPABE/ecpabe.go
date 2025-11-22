package ecpabe

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/AUKUS561/PVOABE/LSSS"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/sample"
)

type ECPABE struct {
	P *big.Int
}

func NewECPABE() *ECPABE {
	return &ECPABE{
		P: bn256.Order,
	}
}

type MK struct {
	Galpha *bn256.G1 //g^alpha
	//Galpha2 *bn256.G2
	beta *big.Int //β
}

type PK struct {
	G    *bn256.G1
	G2   *bn256.G2
	HG2  *bn256.G2 //h = g^β
	Base *bn256.GT //e(g,g)^alpha
}

func (ecpabe *ECPABE) Setup() (*MK, *PK) {
	//α, β ∈ Zp
	sampler := sample.NewUniformRange(big.NewInt(1), ecpabe.P)
	alpha, _ := sampler.Sample()
	beta, _ := sampler.Sample()

	g := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	hG2 := new(bn256.G2).ScalarMult(g2, beta)    //h = g^β
	galpha := new(bn256.G1).ScalarMult(g, alpha) //g^alpha
	//galpha2 := new(bn256.G2).ScalarMult(g2, alpha)

	egg := bn256.Pair(g, g2)
	base := new(bn256.GT).ScalarMult(egg, alpha)
	return &MK{
			Galpha: galpha,
			//Galpha2: galpha2,
			beta: beta,
		}, &PK{
			G:    g,
			G2:   g2,
			HG2:  hG2,
			Base: base,
		}
}

// EKi = si，DKi = zi
type EncKey = *big.Int
type DecKey = *big.Int

type UPi struct {
	UP1 map[string]*bn256.G1 //UPi,u,1 = g^{1/H2(u‖si)}
	UP2 map[string]*bn256.G1 //UPi,u,2 = H1(u)^{1/H2(u‖si)}
}

type TKi struct {
	Attrs []string             // Si
	D     *bn256.G1            // Di
	Dj    map[string]*bn256.G2 // j -> D{i,j}
	Djp   map[string]*bn256.G2 // j -> D'{i,j}
}

// KeyGen(U, MK, Si)->(EKi, DKi, UPi, TKi )
func (ecpabe *ECPABE) KeyGen(U []string, MK *MK, Si []string) (EncKey, DecKey *big.Int, up *UPi, tk *TKi, err error) {
	//1. si, zi ∈ Z_p as EKi, DKi
	sampler := sample.NewUniformRange(big.NewInt(1), ecpabe.P)
	si, _ := sampler.Sample()
	zi, _ := sampler.Sample()
	EKi := si
	DKi := zi
	//2. For each attribute u in the universal set U, calculate UPi
	up = &UPi{
		UP1: make(map[string]*bn256.G1),
		UP2: make(map[string]*bn256.G1),
	}
	g := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	for _, u := range U {
		buf := append([]byte(u), si.Bytes()...)
		h2 := H2(buf, ecpabe.P)
		invH2 := new(big.Int).ModInverse(h2, ecpabe.P)
		// UP{i,u,1} = g^{1 / h2}
		up.UP1[u] = new(bn256.G1).ScalarMult(g, invH2)

		// UP{i,u,2} = H1(u)^{1 / h2}
		Hu := H1(u)
		up.UP2[u] = new(bn256.G1).ScalarMult(Hu, invH2)
	}
	//3. Compute TKi
	tk = &TKi{
		Attrs: append([]string(nil), Si...),
		Dj:    make(map[string]*bn256.G2),
		Djp:   make(map[string]*bn256.G2),
	}
	ri, _ := sampler.Sample()
	ri.Mod(ri, ecpabe.P)
	//Compute Di = (Galpha * g^{ri})^{1/(β zi)}
	gRi := new(bn256.G1).ScalarMult(g, ri)
	num := new(bn256.G1).Add(MK.Galpha, gRi) // num = g^{α + ri}
	den := new(big.Int).Mul(MK.beta, zi)     // β * z_i
	den.Mod(den, ecpabe.P)
	invDen := new(big.Int).ModInverse(den, ecpabe.P) //1/(β zi)
	tk.D = new(bn256.G1).ScalarMult(num, invDen)

	invZi := new(big.Int).ModInverse(zi, ecpabe.P) //1/zi
	for _, j := range Si {
		rij, _ := sampler.Sample()
		rij.Mod(rij, ecpabe.P)

		//RiOverZi = ri / zi
		RiOverZi := new(big.Int).Mul(ri, invZi)
		RiOverZi.Mod(RiOverZi, ecpabe.P)

		//RijoverZi = r{i,j} / zi
		RijOverZi := new(big.Int).Mul(rij, invZi)
		RijOverZi.Mod(RijOverZi, ecpabe.P)

		// g^{ri / zi}
		gRiOverZi := new(bn256.G2).ScalarMult(g2, RiOverZi)

		// H1(j)^{r{i,j} / zi}
		Hj := H1toG2(j)
		HjRijOverZi := new(bn256.G2).ScalarMult(Hj, RijOverZi)

		// D{i,j} = g^{ri / zi} * H1(j)^{r{i,j} / zi}
		Dij := new(bn256.G2).Add(gRiOverZi, HjRijOverZi)

		// D'{i,j} = g^{r{i,j} / zi}
		Dpij := new(bn256.G2).ScalarMult(g2, RijOverZi)

		tk.Dj[j] = Dij
		tk.Djp[j] = Dpij
	}
	return EKi, DKi, up, tk, nil
}

type PreCT struct {
	MSP  *abe.MSP // (M, ρ)
	Mes  *bn256.GT
	C    *bn256.GT
	Com  *bn256.G2        // h^s
	Cpre map[int]*big.Int //Ci^pre = H2(ρ(i)||sB) * λi
}

// Generate an access structure
func GeneratePolicy(attrCount int) string {

	attrs := make([]string, attrCount)
	for i := 0; i < attrCount; i++ {
		attrs[i] = "Attr" + strconv.Itoa(i+1)
	}

	randInt := func(n int) int {
		r, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
		return int(r.Int64())
	}

	for i := attrCount - 1; i > 0; i-- {
		j := randInt(i + 1)
		attrs[i], attrs[j] = attrs[j], attrs[i]
	}

	var build func([]string) string
	build = func(list []string) string {

		if len(list) == 1 {
			return list[0]
		}

		op := "AND"
		if randInt(2) == 0 {
			op = "OR"
		}

		split := randInt(len(list)-1) + 1 // [1, len-1]
		left := build(list[:split])
		right := build(list[split:])

		return "(" + left + " " + op + " " + right + ")"
	}

	policy := build(attrs)

	if len(policy) > 2 && policy[0] == '(' && policy[len(policy)-1] == ')' {
		policy = policy[1 : len(policy)-1]
	}

	return policy
}

func (ecpabe *ECPABE) Encrypt(pk *PK, EKb *big.Int, attrNum int) (*PreCT, error) {
	sampler := sample.NewUniform(ecpabe.P)
	_, keyGt, err := bn256.RandomGT(rand.Reader)
	policy := GeneratePolicy(attrNum)
	//policy := "Attr2 OR (Attr1 AND Attr3)"
	msp, _ := abe.BooleanToMSP(policy, false) //根据访问控制策略构建msp矩阵
	// s ∈ Zp
	s, _ := sampler.Sample()

	C := new(bn256.GT).Add(keyGt, new(bn256.GT).ScalarMult(pk.Base, s))

	//Compute C = h^s
	Com := new(bn256.G2).ScalarMult(pk.HG2, s)

	//LSSS.Share -> λi = Mi · v，v[0] = s
	lambdaMap, err := LSSS.Share(msp, s, ecpabe.P)
	if err != nil {
		return nil, err
	}

	//For each row i，Compute Ci^pre = H2(ρ(i) || sB) * λi (mod p)
	Cpre := make(map[int]*big.Int)

	for i, lambdaI := range lambdaMap {
		// ρ(i)->attr
		attr := msp.RowToAttrib[i]

		//Compute h2 = H2( attr || sB )
		buf := append([]byte(attr), EKb.Bytes()...)
		h2 := H2(buf, ecpabe.P)

		// Ci^pre = h2 * λi  (mod p)
		cpre := new(big.Int).Mul(h2, lambdaI)
		cpre.Mod(cpre, ecpabe.P)

		Cpre[i] = cpre
	}

	preCT := &PreCT{
		MSP:  msp,
		Mes:  keyGt,
		C:    C,
		Com:  Com,
		Cpre: Cpre,
	}
	return preCT, nil
}

type CipherText struct {
	MSP *abe.MSP // (M, ρ)
	C   *bn256.GT
	Com *bn256.G2         // C = h^s
	C1  map[int]*bn256.G1 //Ci  = g^{λi}
	C2  map[int]*bn256.G1 //Ci' = H1(ρ(i))^{λi}
}

func (ecpabe *ECPABE) OutEncrypt(pk *PK, upB *UPi, preCT *PreCT) (*CipherText, error) {
	C1 := make(map[int]*bn256.G1)
	C2 := make(map[int]*bn256.G1)

	for i, cpre := range preCT.Cpre {
		// ρ(i)->attr
		attr := preCT.MSP.RowToAttrib[i]

		//Get UP{B, attr,1} 和 UP{B, attr,2}
		up1, ok1 := upB.UP1[attr]
		up2, ok2 := upB.UP2[attr]
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("OutEncrypt: UPB missing for attribute %s", attr)
		}

		//Compute：
		//Ci  = UP{B,attr,1}^{Ci^pre} = g^{λi}
		//Ci' = UP{B,attr,2}^{Ci^pre} = H1(attr)^{λi}
		C1[i] = new(bn256.G1).ScalarMult(up1, cpre)
		C2[i] = new(bn256.G1).ScalarMult(up2, cpre)
	}

	ct := &CipherText{
		MSP: preCT.MSP,
		C:   preCT.C,
		Com: preCT.Com,
		C1:  C1,
		C2:  C2,
	}
	return ct, nil
}

func (ecpabe *ECPABE) OutDecrypt(pk *PK, ct *CipherText, tkA *TKi) (*bn256.GT, error) {
	if ct == nil || tkA == nil {
		return nil, errors.New("OutDecrypt: ciphertext or transform key is nil")
	}

	//Create a set SA containing the attributes possessed by A for easier judgment
	attrSet := make(map[string]bool)
	for _, a := range tkA.Attrs {
		attrSet[a] = true
	}

	//For each row i satisfy ρ(i) ∈ SA ,Compute shares = e(Ci, D{A,i}) / e(C'i, D'{A,i}) ∈ GT
	shares := make(map[int]*bn256.GT)

	// -1 mod p：x^{-1} = x^{p-1}
	negOne := new(big.Int).Sub(ecpabe.P, big.NewInt(1))

	for i, attr := range ct.MSP.RowToAttrib {
		//ρ(i) ∈ SA
		if !attrSet[attr] {
			continue
		}

		//CT -> Ci, C'i
		Ci, ok1 := ct.C1[i]
		CiPrime, ok2 := ct.C2[i]
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("OutDecrypt: missing ciphertext components for row %d (attr %s)", i, attr)
		}

		//TKA -> D{A,i}, D'{A,i}
		Dij, ok3 := tkA.Dj[attr]
		Dpij, ok4 := tkA.Djp[attr]
		if !ok3 || !ok4 {
			return nil, fmt.Errorf("OutDecrypt: missing transform key components for attribute %s", attr)
		}

		// num = e(Ci, D{A,i})
		num := bn256.Pair(Ci, Dij)

		// den = e(C'i, D'{A,i})
		den := bn256.Pair(CiPrime, Dpij)

		// den^{-1} = den^{p-1}
		//invDen := new(bn256.GT).ScalarMult(den, negOne)

		// sharei = num * den^{-1}
		share := new(bn256.GT).Add(num, new(bn256.GT).Neg(den))

		shares[i] = share
	}

	if len(shares) == 0 {
		return nil, errors.New("OutDecrypt: no overlapping attributes between TKA and ciphertext")
	}

	//LSSS.Recon -> A = Prodi (shares)^{wi}
	A, err := LSSS.Recon(ct.MSP, shares, ecpabe.P)
	if err != nil {
		return nil, fmt.Errorf("OutDecrypt: LSSS.Recon failed: %w", err)
	}

	//Compute e(C, DA) / A
	eCD := bn256.Pair(tkA.D, ct.Com)

	// A^{-1} = A^{p-1}
	invA := new(bn256.GT).ScalarMult(A, negOne)

	// transCT = e(C, D_A) * A^{-1} = e(g,g)^{α·s/z_A}
	transCT := new(bn256.GT).Add(eCD, invA)

	return transCT, nil
}

// Decrypt(PK, transCT, DKA)->key
func (ecpabe *ECPABE) Decrypt(ct *CipherText, transCT *bn256.GT, DKA *big.Int) (*bn256.GT, error) {
	if transCT == nil || DKA == nil {
		return nil, errors.New("Decrypt: transCT or DKA is nil")
	}

	exp := new(big.Int).Mod(DKA, ecpabe.P)

	// Key = transCT^{DKA} = e(g,g)^{α·s}
	Key := new(bn256.GT).ScalarMult(transCT, exp)
	keyGT := new(bn256.GT).Add(ct.C, new(bn256.GT).Neg(Key))

	return keyGT, nil
}

//——————————————————————————————————————Auxiliary Functions————————————————————————————————————————————//

// H1:H1(u) = g^{hash(u)}
func H1(attr string) *bn256.G1 {
	h := sha256.Sum256([]byte(attr))
	exp := new(big.Int).SetBytes(h[:])
	exp.Mod(exp, bn256.Order)

	g := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	return new(bn256.G1).ScalarMult(g, exp)
}

func H1toG2(attr string) *bn256.G2 {
	h := sha256.Sum256([]byte(attr))
	exp := new(big.Int).SetBytes(h[:])
	exp.Mod(exp, bn256.Order)

	g := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	return new(bn256.G2).ScalarMult(g, exp)
}

// H2:[]byte -> Zp
func H2(msg []byte, p *big.Int) *big.Int {
	h := sha256.Sum256(msg)
	x := new(big.Int).SetBytes(h[:])
	x.Mod(x, p)
	if x.Sign() == 0 {
		x.SetInt64(1)
	}
	return x
}
