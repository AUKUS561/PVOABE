package VOABE

import (
	"crypto/aes"
	cbc "crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"math/big"
	"sort"
	"strconv"

	"github.com/AUKUS561/PVOABE/LSSS"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/sample"
)

type VOABE struct {
	P *big.Int
}

func NewVOABE() *VOABE {
	return &VOABE{
		P: bn256.Order,
	}
}

type pk struct {
	Order *big.Int  //order
	G     *bn256.G1 //g
	G2    *bn256.G2 //g in G2 only for pairing
	H     *bn256.G1 //h
	W     *bn256.G1 //w
	WG2   *bn256.G2 //w
	Base  *bn256.GT //e(g,g)^alpha
	Base1 *bn256.GT //e(g,g)^alpha1
	Ga    *bn256.G1 //g^a
	//Ga2   *bn256.G2            //only for pairing
	Gb   *bn256.G1            //g^b
	G2b  *bn256.G2            //g2^b
	Hx   map[string]*bn256.G1 //Hx
	HxG2 map[string]*bn256.G2 //Hx
}

type msk struct {
	//msk = (α, α1, α2, b)
	alpha, alpha1, alpha2, b *big.Int
}

// SetUp->pk,msk
func (voabe *VOABE) SetUp(U []string) (*pk, *msk) {
	//α, α1, α2, a, b ∈ Z∗p
	sampler := sample.NewUniformRange(big.NewInt(1), voabe.P)
	alpha, _ := sampler.Sample()
	alpha1, _ := sampler.Sample()
	//alpha2 := new(big.Int).Sub(alpha, alpha1) //alpha=alpha1+alpha2
	alpha2 := new(big.Int).Sub(alpha, alpha1)
	alpha2.Mod(alpha2, voabe.P)
	a, _ := sampler.Sample()
	b, _ := sampler.Sample()

	g := new(bn256.G1).ScalarBaseMult(big.NewInt(1))   //g
	h := new(bn256.G1).ScalarBaseMult(big.NewInt(2))   //h
	w := new(bn256.G1).ScalarBaseMult(big.NewInt(3))   //w
	wG2 := new(bn256.G2).ScalarBaseMult(big.NewInt(3)) //wG2

	//g1:e(g,g)^alpha->e(g,g1)^alpha,only for pairing
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	pair := bn256.Pair(g, g2)
	base := new(bn256.GT).ScalarMult(pair, alpha)
	base1 := new(bn256.GT).ScalarMult(pair, alpha1)
	//g^a
	ga := new(bn256.G1).ScalarMult(g, a)
	//ga2 := new(bn256.G2).ScalarMult(g2, a)
	//g^b
	gb := new(bn256.G1).ScalarMult(g, b)
	g2b := new(bn256.G2).ScalarMult(g2, b)
	//Hx as a map which attribute as index and G1 elements as value
	// Hx: map attribute name -> G1 element
	hx := make(map[string]*bn256.G1)
	hxG2 := make(map[string]*bn256.G2)

	for i := 0; i < len(U); i++ {
		attr := U[i]
		ri, _ := sampler.Sample()
		//x := HashToG1(attr)
		//hx[attr] = x
		hx[attr] = new(bn256.G1).ScalarBaseMult(ri)
		hxG2[attr] = new(bn256.G2).ScalarBaseMult(ri)
	}
	return &pk{
			Order: voabe.P,
			G:     g,
			G2:    g2,
			H:     h,
			W:     w,
			WG2:   wG2,
			Base:  base,
			Base1: base1,
			Ga:    ga,
			//Ga2:   ga2,
			Gb:   gb,
			G2b:  g2b,
			Hx:   hx,
			HxG2: hxG2,
		}, &msk{
			alpha: alpha, alpha1: alpha1, alpha2: alpha2, b: b,
		}
}

func (voabe *VOABE) KeyGenPV(pk *pk, msk *msk) (pkPV *bn256.G1, pkPVG2 *bn256.G2, skPV *big.Int) {
	//c ∈ Z∗p
	sampler := sample.NewUniformRange(big.NewInt(1), voabe.P)
	c, _ := sampler.Sample()
	//pkPV=g^c
	pkPV = new(bn256.G1).ScalarMult(pk.G, c)
	pkPVG2 = new(bn256.G2).ScalarMult(pk.G2, c)
	//skPV=c
	return pkPV, pkPVG2, c
}

type SKcs struct {
	Ku *bn256.G1
	//Ku2  *bn256.G2 //Only for pairing
	//Lu   *bn256.G1
	Lu2 *bn256.G2 //Only for paring
	Ru  *bn256.G1
	//Ru2 *bn256.G2 //Only for pairing
	//Kux  map[string]*bn256.G1
	Kux2 map[string]*bn256.G2 //Only for pairing
}

type Sku struct {
	Sku *bn256.G1
	//Sku2 *bn256.G2 //Only for pairing
}

// string -> big.Int
func HashToBigInt(attribute string) *big.Int {
	h := sha256.Sum256([]byte(attribute))
	z := new(big.Int).SetBytes(h[:])
	return z
}

func (voabe *VOABE) KeyGenU(pk *pk, msk *msk, IDu string, Su []string) (*SKcs, *Sku) {
	// Su: "Doctor Nurse" split with blank
	//attrs := strings.Split(Su, " ")

	sampler := sample.NewUniformRange(big.NewInt(1), voabe.P)

	// tu ∈ Zp
	t, _ := sampler.Sample()

	// compute 1 / (b + H(IDu)) mod p
	hID := HashToBigInt(IDu)
	denom := new(big.Int).Add(msk.b, hID)
	denom.Mod(denom, voabe.P)
	invDenom := new(big.Int).ModInverse(denom, voabe.P) // 1/(b+H(IDu))

	// Ku = g^{α1} g^{a tu} w^{1/(b+H(IDu))}
	Ku := new(bn256.G1).ScalarMult(pk.G, msk.alpha1) // g^{α1}
	tmp := new(bn256.G1).ScalarMult(pk.Ga, t)        // g^{a tu}
	Ku.Add(Ku, tmp)
	tmpW := new(bn256.G1).ScalarMult(pk.W, invDenom) // w^{1/(b+H(IDu))}
	Ku.Add(Ku, tmpW)

	// Ku2 = g2^{α1} g2^{a tu} w2^{1/(b+H(IDu))}
	// Ku2 := new(bn256.G2).ScalarMult(pk.G2, msk.alpha1)
	// tmp2 := new(bn256.G2).ScalarMult(pk.Ga2, t)
	// Ku2.Add(Ku2, tmp2)
	// tmpW2 := new(bn256.G2).ScalarMult(pk.G2, invDenom)
	// Ku2.Add(Ku2, tmpW2)

	// Lu = g^{tu}
	//Lu := new(bn256.G1).ScalarMult(pk.G, t)
	Lu2 := new(bn256.G2).ScalarMult(pk.G2, t)

	// Ru = g^{1/(b+H(IDu))}
	Ru := new(bn256.G1).ScalarMult(pk.G, invDenom)
	//Ru2 := new(bn256.G2).ScalarMult(pk.G2, invDenom)

	// K{u,x} = hx^{tu}  for x ∈ Su
	//Kux := make(map[string]*bn256.G1)
	Kux2 := make(map[string]*bn256.G2)
	for _, attr := range Su {
		hx, ok := pk.Hx[attr]
		if !ok || hx == nil {
			log.Fatalf("Fail to match hx with attribute %s", attr)
		}
		// K_{u,x} in G1
		//Kux[attr] = new(bn256.G1).ScalarMult(hx, t)

		// K_{u,x} in G2 = (hash(attr)·G2)^t
		// exp := HashToBigInt(attr)
		// exp.Mod(exp, voabe.P)
		// hx2 := new(bn256.G2).ScalarMult(pk.G2, exp)
		// Kux2[attr] = new(bn256.G2).ScalarMult(hx2, t) // hx^{t} in G2
		Kux2[attr] = new(bn256.G2).ScalarMult(pk.HxG2[attr], t)
	}
	// sku = g^{α2} g^{a tu}
	b1 := new(bn256.G1).ScalarMult(pk.G, msk.alpha2)
	b2 := new(bn256.G1).ScalarMult(pk.Ga, t)
	SkUser := new(bn256.G1).Add(b1, b2)

	// sku(G2)
	// b1_2 := new(bn256.G2).ScalarMult(pk.G2, msk.alpha2)
	// b2_2 := new(bn256.G2).ScalarMult(pk.Ga2, t)
	//SkUserG2 := new(bn256.G2).Add(b1_2, b2_2)

	csKey := &SKcs{
		Ku: Ku,
		//Ku2:  Ku2,
		//Lu:   Lu,
		Lu2: Lu2,
		Ru:  Ru,
		//Ru2: Ru2,
		//Kux:  Kux,
		Kux2: Kux2,
	}

	userKey := &Sku{
		Sku: SkUser,
		//Sku2: SkUserG2,
	}

	return csKey, userKey
}

// Intermediate ciphertexts
type Cph struct {
	//CR      []byte           // CR = Enc{KR}(R)
	C        *bn256.GT        // C  ∈ GT
	CPrime2  *bn256.G2        // C' ∈ G2
	CSecond2 *bn256.G2        // C'' ∈ G2
	Lambdas  map[int]*big.Int // {λi}
	MSP      *abe.MSP         // access structure
}

func GeneratePolicy(attrCount int) ([]string, string) {

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

	return attrs, policy
}

// EncDo encrypt the record R by access structure Γ and send the intermediate ciphertexts to CS
func (voave *VOABE) EncDo(pk *pk, pkPV *bn256.G1, pkPVG2 *bn256.G2, attrNum int) (*Cph, []string) {
	//Generate symmetric key KR
	sampler := sample.NewUniformRange(big.NewInt(1), voave.P)
	k, _ := sampler.Sample()
	KR := new(bn256.GT).ScalarMult(pk.Base, k) //Base = e(g,g)^alpha

	//λi = Mi · v
	s, _ := sampler.Sample()

	policySet, policy := GeneratePolicy(attrNum)
	//fmt.Printf("Policy=%v\n", policy)
	msp, _ := abe.BooleanToMSP(policy, false) //根据访问控制策略构建msp矩阵
	Lambdai, _ := LSSS.Share(msp, s, voave.P)

	//Compute C, C', C''
	//Cpart1 = e(g,g)^{αs} = Base^s
	C1 := new(bn256.GT).ScalarMult(pk.Base, s)

	//Cpart2 = e(g, pkPV)^s
	b := bn256.Pair(pkPV, pk.G2)
	C2 := new(bn256.GT).ScalarMult(b, s)

	//C = KR * e(g,g)^{α s} * e(g,pkPV)^s
	C := new(bn256.GT).Add(KR, C1)
	C.Add(C, C2)

	//C' = g^s
	CPrime2 := new(bn256.G2).ScalarMult(pk.G2, s)

	//C'' = w^s pkPV^s
	ws := new(bn256.G2).ScalarMult(pk.WG2, s)
	pvs := new(bn256.G2).ScalarMult(pkPVG2, s)
	CSecond2 := new(bn256.G2).Add(ws, pvs)

	return &Cph{
		//CR:      CR,
		C:        C,
		CPrime2:  CPrime2,
		CSecond2: CSecond2,
		Lambdas:  Lambdai,
		MSP:      msp,
	}, policySet
}

// Final ciphertext
type CPh struct {
	*Cph
	C0 *bn256.G1 // C0 = g^{a r},It is only filled after Sanitize.
	Ci map[int]*bn256.G1
	Di map[int]*bn256.G1
}

func (voabe *VOABE) EncCS(pk *pk, cph *Cph, pkPV *bn256.G1) *CPh {
	sampler := sample.NewUniformRange(big.NewInt(1), voabe.P)

	CiMap := make(map[int]*bn256.G1)
	DiMap := make(map[int]*bn256.G1)
	for i, lambda := range cph.Lambdas {
		//ri ∈ Z*_p
		ri, _ := sampler.Sample()

		// D_i = g^{ri}
		Di := new(bn256.G1).ScalarMult(pk.G, ri)
		DiMap[i] = Di

		// Ci = g^{a λi} h^{- ri * H(ρ(i))} pkPV^{-r_i}

		// term1 = (g^a)^{λ_i} = g^{a λ_i}
		term1 := new(bn256.G1).ScalarMult(pk.Ga, lambda)

		// Take the attribute name corresponding to this line ρ(i)
		if i < 0 || i >= len(cph.MSP.RowToAttrib) {
			log.Fatalf("MSP.RowToAttrib index %d out of range", i)
		}
		attr := cph.MSP.RowToAttrib[i]
		hx, ok := pk.Hx[attr]
		if !ok || hx == nil {
			log.Fatalf("no hx for attribute %s", attr)
		}

		riNeg := new(big.Int).Sub(voabe.P, ri)
		riNeg.Mod(riNeg, voabe.P)

		term2 := new(bn256.G1).ScalarMult(hx, riNeg)

		// term3 = pkPV^{- ri}
		term3 := new(bn256.G1).ScalarMult(pkPV, riNeg)

		Ci := new(bn256.G1).Add(term1, term2)
		Ci.Add(Ci, term3)

		CiMap[i] = Ci
	}

	return &CPh{
		Cph: cph,
		C0:  nil,
		Ci:  CiMap, // {Ci}
		Di:  DiMap, // {Di}
	}

}

// CS generate proof
type Proof struct {
	KDoPrime *bn256.G1 // K'DO
	//LDoPrime     *bn256.G1 // L'DO
	LDoPrime2 *bn256.G2 //Only for pairing
	RDoPrime  *bn256.G1 // R'DO
	//RDoPrime2    *bn256.G2 //Only for pairing
	ProdKDoPrime *bn256.G2 // ∏{x∈S*DO} K'{DO,x}
	A1           *bn256.G2 // A1
	A2           *bn256.G2 // A2
	A3           *bn256.G2 // A3
	A4           *bn256.G2 // A4
	A5           *bn256.GT // A5
	//A6           *bn256.G2 // A6
	A6_2 *bn256.G2 //Only for pairing

	SDoStar []string // S*_DO：PV send the sub attribute set to CS
}

// HashCphToScalar achieve hash(cph)
func HashCphToScalar(cph *CPh, p *big.Int) *big.Int {
	h := sha256.New()

	//Put CR, C, C', C'' to hash
	//h.Write(cph.CR)
	h.Write(cph.C.Marshal())
	h.Write(cph.CPrime2.Marshal())
	h.Write(cph.CSecond2.Marshal())
	if cph.C0 != nil {
		h.Write(cph.C0.Marshal())
	}

	var idxs []int
	for i := range cph.Ci {
		idxs = append(idxs, i)
	}
	sort.Ints(idxs)

	for _, i := range idxs {
		h.Write(cph.Ci[i].Marshal())
		h.Write(cph.Di[i].Marshal())
	}

	sum := h.Sum(nil)
	z := new(big.Int).SetBytes(sum)
	z.Mod(z, p)
	return z
}

// CS generate proof for PV
func (voabe *VOABE) GenProofForPV(pk *pk, skDOcs *SKcs, cph *CPh, IDDO string, SDoStar []string) (*Proof, error) {
	sampler := sample.NewUniformRange(big.NewInt(1), voabe.P)

	//t, y, z ∈ Zp
	t, _ := sampler.Sample()
	y, _ := sampler.Sample()
	z, _ := sampler.Sample()

	//K'DO = KDO · (g^a)^t
	gat := new(bn256.G1).ScalarMult(pk.Ga, t)
	KDoPrime := new(bn256.G1).Add(skDOcs.Ku, gat)

	//L'DO = LDO · g^t
	//gt := new(bn256.G1).ScalarMult(pk.G, t)
	gt2 := new(bn256.G2).ScalarMult(pk.G2, t)
	//LDoPrime := new(bn256.G1).Add(skDOcs.Lu, gt)
	LDoPrime2 := new(bn256.G2).Add(skDOcs.Lu2, gt2)

	//∏_{x∈S*_DO} K'_{DO,x} = ∏ (K_{DO,x} · h_x^t)
	// Initialize the product as the group identity: g^0
	prodK := new(bn256.G2).ScalarMult(pk.G2, big.NewInt(0))
	first := true

	for i := 0; i < len(SDoStar); i++ {
		attr := SDoStar[i]

		Kux2, ok := skDOcs.Kux2[attr]
		if !ok || Kux2 == nil {
			return nil, fmt.Errorf("Kux for attr %s not found in skDOcs", attr)
		}

		hxG2, ok := pk.HxG2[attr]
		if !ok || hxG2 == nil {
			return nil, fmt.Errorf("hx for attr %s not found in pk.Hx", attr)
		}
		// hx^t
		hxtG2 := new(bn256.G2).ScalarMult(hxG2, t)
		// K'{DO,x} = K{DO,x} · hx^t
		KDoPrimeX := new(bn256.G2).Add(Kux2, hxtG2)

		if first {
			prodK.Set(KDoPrimeX)
			first = false
		} else {
			prodK.Add(prodK, KDoPrimeX)
		}
	}

	//R'DO = RDO^z
	RDoPrime := new(bn256.G1).ScalarMult(skDOcs.Ru, z)
	//RDoPrime2 := new(bn256.G2).ScalarMult(skDOcs.Ru2, z)

	//Prepare 1/z
	invZ := new(big.Int).ModInverse(z, voabe.P)
	if invZ == nil {
		return nil, fmt.Errorf("z has no inverse mod p")
	}

	//Compute H(cph)、H(ID_DO)
	Hcph := HashCphToScalar(cph, voabe.P) // H(cph)
	HID := HashToBigInt(IDDO)
	HID.Mod(HID, voabe.P)
	HIDOverZ := new(big.Int).Mul(HID, invZ) //H(IDDO)/z
	HIDOverZ.Mod(HIDOverZ, voabe.P)

	//A1 = (L'DO)^{H(cph)} w^y
	LDoPrimeExp := new(bn256.G2).ScalarMult(LDoPrime2, Hcph)
	wy := new(bn256.G2).ScalarMult(pk.WG2, y)
	A1 := new(bn256.G2).Add(LDoPrimeExp, wy)

	//A2 = g^y
	A2 := new(bn256.G2).ScalarMult(pk.G2, y)

	//A3 = w^{1/z}
	A3 := new(bn256.G2).ScalarMult(pk.WG2, invZ)

	//A4 = g^{b/z} g^{H(ID_DO)/z}
	gbOverZ := new(bn256.G2).ScalarMult(pk.G2b, invZ) // (g^b)^{1/z} = g^{b/z}
	gHIDOverZ := new(bn256.G2).ScalarMult(pk.G2, HIDOverZ)
	A4 := new(bn256.G2).Add(gbOverZ, gHIDOverZ)

	//A5 = e(g,g)^{H(ID_DO)/z}
	egg := bn256.Pair(pk.G, pk.G2) // e(g,g)
	A5 := new(bn256.GT).ScalarMult(egg, HIDOverZ)

	//A6 = g^{1/z}
	//A6 := new(bn256.G1).ScalarMult(pk.G, invZ)
	A6_2 := new(bn256.G2).ScalarMult(pk.G2, invZ)

	proof := &Proof{
		KDoPrime: KDoPrime,
		//LDoPrime:     LDoPrime,
		LDoPrime2: LDoPrime2,
		RDoPrime:  RDoPrime,
		//RDoPrime2:    RDoPrime2,
		ProdKDoPrime: prodK,
		A1:           A1,
		A2:           A2,
		A3:           A3,
		A4:           A4,
		A5:           A5,
		//A6:           A6,
		A6_2:    A6_2,
		SDoStar: SDoStar,
	}

	return proof, nil
}

func (voabe *VOABE) VerifyProofSymmetric(pk *pk, cph *CPh, proof *Proof, IDDO string) bool {
	Hcph := HashCphToScalar(cph, voabe.P)
	HID := HashToBigInt(IDDO)
	HID.Mod(HID, voabe.P)

	//six pairing check
	//1. e(K'_DO, g) == e(g,g)^α1 · e(L'DO, g^a) · e(R'DO, A3)
	left1 := bn256.Pair(proof.KDoPrime, pk.G2)

	right1 := new(bn256.GT).Set(pk.Base1) // e(g,g)^α1
	//multiply e(L'DO, g^a)
	termL := bn256.Pair(pk.Ga, proof.LDoPrime2)
	right1.Add(right1, termL)
	//multiply e(R'DO, A3)
	termR := bn256.Pair(proof.RDoPrime, proof.A3)
	right1.Add(right1, termR)

	if left1.String() != right1.String() {
		fmt.Printf("Eq1 is false!\n")
		return false
	}

	//2. e(A3, g) == e(w, A6)
	left2 := bn256.Pair(pk.G, proof.A3)
	right2 := bn256.Pair(pk.W, proof.A6_2)
	if left2.String() != right2.String() {
		fmt.Printf("Eq2 is false!\n")
		return false
	}

	//3. e(A4, g) == e(g^b, A6) · A5
	left3 := bn256.Pair(pk.G, proof.A4)

	right3 := bn256.Pair(pk.Gb, proof.A6_2)
	right3.Add(right3, proof.A5) //Add A5
	if left3.String() != right3.String() {
		fmt.Printf("Eq3 is false!\n")
		return false
	}

	//4. e(R'DO, A4) == e(g,g)
	egg := bn256.Pair(pk.G, pk.G2) // e(g,g)
	left4 := bn256.Pair(proof.RDoPrime, proof.A4)
	if left4.String() != egg.String() {
		fmt.Printf("Eq4 is false!\n")
		return false
	}

	//5. e(∏K'{DO,x}, g) == e(∏hx, L'DO)
	// Compute ∏ hx
	prodHx := new(bn256.G1).ScalarMult(pk.G, big.NewInt(0))
	first := true
	for i := 0; i < len(proof.SDoStar); i++ {
		attr := proof.SDoStar[i]
		hx, ok := pk.Hx[attr]
		if !ok || hx == nil {
			// att dont match
			return false
		}
		if first {
			prodHx.Set(hx)
			first = false
		} else {
			prodHx.Add(prodHx, hx)
		}
	}

	left5 := bn256.Pair(pk.G, proof.ProdKDoPrime)
	right5 := bn256.Pair(prodHx, proof.LDoPrime2)
	if left5.String() != right5.String() {
		fmt.Printf("Eq5 is false!\n")
		return false
	}

	// 6. e(A1, g) == e(L'DO, g)^{H(cph)} · e(A2, w)
	left6 := bn256.Pair(pk.G, proof.A1)

	// e(L'DO, g)^{H(cph)}
	baseLg := bn256.Pair(pk.G, proof.LDoPrime2)
	termLg := new(bn256.GT).ScalarMult(baseLg, Hcph)

	// e(A2, w)
	termAw := bn256.Pair(pk.W, proof.A2)

	right6 := new(bn256.GT).Add(termLg, termAw)

	if left6.String() != right6.String() {
		fmt.Printf("Eq6 is false!\n")
		return false
	}

	return true
}

// Sanitize: PV sanitize the final ciphertext with its own secret key skPV = c
// Output: updated cph (with C0 and re-randomize all components)
func (voabe *VOABE) Sanitize(pk *pk, skPV *big.Int, cph *CPh) *CPh {

	sampler := sample.NewUniformRange(big.NewInt(1), voabe.P)
	r, err := sampler.Sample()
	if err != nil {
		log.Printf("Warning: sanitize randomness sampling failed, using 0")
		r = big.NewInt(0)
	}
	// rNeg = -r mod p
	rNeg := new(big.Int).Neg(r)
	rNeg.Mod(rNeg, voabe.P)

	cNeg := new(big.Int).Sub(voabe.P, skPV)
	cNeg.Mod(cNeg, voabe.P)

	// Compute C0 = g^{a r} = (g^a)^r
	C0 := new(bn256.G1).ScalarMult(pk.Ga, r)

	//Update Cnew = C · e(g, C')^{-c} · e(g,g)^{α r}
	pairGCPrime := bn256.Pair(pk.G, cph.CPrime2)                //e(g, C')
	termPairNegC := new(bn256.GT).ScalarMult(pairGCPrime, cNeg) // e(g, C')^{-c}
	termAlphaR := new(bn256.GT).ScalarMult(pk.Base, r)          // e(g,g)^{α r}

	Cnew := new(bn256.GT).Add(cph.C, termPairNegC)
	Cnew.Add(Cnew, termAlphaR)

	//Compute (C')^{-c} for  C'' （before update C'）
	termCPrimeNegC := new(bn256.G2).ScalarMult(cph.CPrime2, cNeg) // (C')^{-c}

	//C'new = C' * g^r = g^s * g^r = g^{s+r}
	gr := new(bn256.G1).ScalarMult(pk.G, r)
	grG2 := new(bn256.G2).ScalarMult(pk.G2, r)
	CPrimeNew := new(bn256.G2).Add(cph.CPrime2, grG2)

	//Update C'' = C'' · (C')^{-c} · w^{r}
	wr := new(bn256.G2).ScalarMult(pk.WG2, r)
	CSecondNew := new(bn256.G2).Add(cph.CSecond2, termCPrimeNegC)
	CSecondNew.Add(CSecondNew, wr)

	//Update Ci, Di
	CiNewMap := make(map[int]*bn256.G1, len(cph.Ci))
	DiNewMap := make(map[int]*bn256.G1, len(cph.Di))

	for i, Ci := range cph.Ci {
		Di, ok := cph.Di[i]
		if !ok {
			log.Fatalf("missing Di for index %d", i)
		}

		// Di^c
		termDic := new(bn256.G1).ScalarMult(Di, skPV)

		// Find the attribute name ρ(i) corresponding to this row, and then take h{ρ(i)}
		if i < 0 || i >= len(cph.MSP.RowToAttrib) {
			log.Fatalf("MSP.RowToAttrib index %d out of range", i)
		}
		attr := cph.MSP.RowToAttrib[i]
		hx, ok := pk.Hx[attr]
		if !ok || hx == nil {
			log.Fatalf("no hx for attribute %s", attr)
		}

		// h{ρ(i)}^{-r}
		termHxr := new(bn256.G1).ScalarMult(hx, rNeg)

		// Ci = Ci · Di^c · h{ρ(i)}^{-r}
		CiNew := new(bn256.G1).Add(Ci, termDic)
		CiNew.Add(CiNew, termHxr)

		// Di = Di · g^{r}
		DiNew := new(bn256.G1).Add(Di, gr)

		CiNewMap[i] = CiNew
		DiNewMap[i] = DiNew
	}

	//Write back to the original cph structure
	cph.C0 = C0
	cph.C = Cnew
	cph.CPrime2 = CPrimeNew
	cph.CSecond2 = CSecondNew
	cph.Ci = CiNewMap
	cph.Di = DiNewMap

	return cph
}

// DecCS:CS uses skCS to outsource decryption of the sanitize ciphertext cph
func (voabe *VOABE) DecCS(pk *pk, cph *CPh, skCS *SKcs, SDU []string) (*bn256.GT, error) {

	wMap, err := LSSS.ReconstructCoefficients(cph.MSP, SDU, voabe.P)
	if err != nil {
		return nil, fmt.Errorf("DecCS: reconstruct coefficients failed: %v", err)
	}
	if len(wMap) == 0 {
		return nil, fmt.Errorf("DecCS: SDU does not satisfy Γ (empty wMap)")
	}

	//Compute term1 = e(C', KDU) = Pair(CPrime, Ku2)
	term1 := bn256.Pair(skCS.Ku, cph.CPrime2)

	//Compute term2 = e(RDU, C'')-> Pair(C'', Ru2)
	term2 := bn256.Pair(skCS.Ru, cph.CSecond2)
	//term2^{-1} = term2^{p-1}
	//minusOne := new(big.Int).Sub(voabe.P, big.NewInt(1))
	//term2Inv := new(bn256.GT).ScalarMult(term2, minusOne)
	term2Inv := new(bn256.GT).Neg(term2)

	// tmp = e(C',KDU) * e(RDU,C'')^{-1}
	tmp := new(bn256.GT).Add(term1, term2Inv)

	//Calculate the product part:
	//prod = ∏{i∈I} [ e(Ci,LDU) e(Di,KDU,ρ(i)) ]^{wi} * e(LDU, C0)
	//First, initialize prod to GT unit element (use e(g,g)^0)
	egg := bn256.Pair(pk.G, pk.G2)
	prod := new(bn256.GT).ScalarMult(egg, big.NewInt(0))
	first := true
	for i, wi := range wMap {

		// e(Ci, LDU) → Pair(Ci, Lu2)
		eCiL := bn256.Pair(cph.Ci[i], skCS.Lu2)

		if i < 0 || i >= len(cph.MSP.RowToAttrib) {
			return nil, fmt.Errorf("DecCS: MSP.RowToAttrib index %d out of range", i)
		}

		attr := cph.MSP.RowToAttrib[i]
		kux2, ok := skCS.Kux2[attr]
		if !ok || kux2 == nil {
			return nil, fmt.Errorf("DecCS: no Kux2 for attribute %s", attr)
		}

		eDiK := bn256.Pair(cph.Di[i], kux2)
		// Add：e(Ci,LDU) * e(Di,KDU,ρ(i))
		tmpPair := new(bn256.GT).Add(eCiL, eDiK)
		// (...) ^wi
		tmpPairW := new(bn256.GT).ScalarMult(tmpPair, wi)

		if first {
			prod.Set(tmpPairW)
			first = false
		} else {
			prod.Add(prod, tmpPairW)
		}
	}

	//e(LDU, C0) → Pair(C0, Lu2)
	eLC0 := bn256.Pair(cph.C0, skCS.Lu2)
	prod.Add(prod, eLC0)

	//(...)^-2
	two := big.NewInt(2)
	prodSquared := new(bn256.GT).ScalarMult(prod, two)

	prodSquaredInv := new(bn256.GT).Neg(prodSquared)

	// φDU = tmp + (-2 * prod)  = term1 * term2^{-1} / (prod^2)
	phiDU := new(bn256.GT).Add(tmp, prodSquaredInv)
	return phiDU, nil
}

// DecDU: DU uses φDU and its own key skDU to recover KR from cph and decrypt it
func (voabe *VOABE) DecDU(phiDU *bn256.GT, cph *CPh, skDU *Sku) (*bn256.GT, error) {
	if phiDU == nil || cph == nil || skDU == nil || skDU.Sku == nil {
		return nil, fmt.Errorf("DecDU: nil input")
	}

	//Compute e(skDU, C')->Pair(CPrime, Sku2)
	eSkCPrime := bn256.Pair(skDU.Sku, cph.CPrime2)

	//Calculate the denominator denom = φDU · e(skDU, C')
	denom := new(bn256.GT).Add(phiDU, eSkCPrime)

	//Compute denom^{-1} = denom^{p-1}
	// minusOne := new(big.Int).Sub(voabe.P, big.NewInt(1))
	// denomInv := new(bn256.GT).ScalarMult(denom, minusOne)
	denomInv := new(bn256.GT).Neg(denom)
	//KR = C / (φDU · e(skDU, C')) = C * (φDU · e(skDU,C'))^{-1}
	KR := new(bn256.GT).Add(cph.C, denomInv)

	//Use KR as the symmetric key to decrypt CR
	// plaintext, err := SymDec(KR, cph.CR)
	// if err != nil {
	// 	return nil, fmt.Errorf("DecDU: symmetric decryption failed: %v", err)
	// }

	return KR, nil
}

//——————————————————————————————————————Auxiliary Functions————————————————————————————————————————————//

// The HashToG1 function maps an attribute x to a point on the G1 group
func HashToG1(attribute string) *bn256.G1 {
	//Hash the attributes and convert them into a large integer z
	h := sha256.Sum256([]byte(attribute))
	z := new(big.Int).SetBytes(h[:])
	//Map z onto G1 group
	g := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	hx := new(bn256.G1).ScalarMult(g, z)
	return hx
}

// symmetric encryption--AES-CBC，Ciphertext：IV || C
func SymEnc(key *bn256.GT, plaintext []byte) ([]byte, error) {
	// Generate AES key
	keyCBC := sha256.Sum256(key.Marshal())

	c, err := aes.NewCipher(keyCBC[:])
	if err != nil {
		return nil, err
	}

	blockSize := c.BlockSize()

	// Generate random IV
	iv := make([]byte, blockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// PKCS7 padding
	padLen := blockSize - (len(plaintext) % blockSize)
	msgPad := make([]byte, len(plaintext)+padLen)
	copy(msgPad, plaintext)
	for i := len(plaintext); i < len(msgPad); i++ {
		msgPad[i] = byte(padLen)
	}

	ciphertext := make([]byte, blockSize+len(msgPad))
	copy(ciphertext[:blockSize], iv)

	encrypter := cbc.NewCBCEncrypter(c, iv)
	encrypter.CryptBlocks(ciphertext[blockSize:], msgPad)

	return ciphertext, nil
}

// SymDec uses the same method as SymEnc to derive AES key decryption from GT element key.
func SymDec(key *bn256.GT, ciphertext []byte) ([]byte, error) {
	keyCBC := sha256.Sum256(key.Marshal())

	c, err := aes.NewCipher(keyCBC[:])
	if err != nil {
		return nil, err
	}

	blockSize := c.BlockSize()
	if len(ciphertext) < blockSize || len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("SymDec: invalid ciphertext length")
	}

	iv := ciphertext[:blockSize]
	enc := ciphertext[blockSize:]

	decrypter := cbc.NewCBCDecrypter(c, iv)
	msgPad := make([]byte, len(enc))
	decrypter.CryptBlocks(msgPad, enc)

	if len(msgPad) == 0 {
		return nil, fmt.Errorf("SymDec: empty plaintext after decrypt")
	}

	// PKCS7
	padLen := int(msgPad[len(msgPad)-1])
	if padLen <= 0 || padLen > blockSize || padLen > len(msgPad) {
		return nil, fmt.Errorf("SymDec: invalid padding")
	}
	for i := len(msgPad) - padLen; i < len(msgPad); i++ {
		if msgPad[i] != byte(padLen) {
			return nil, fmt.Errorf("SymDec: invalid padding bytes")
		}
	}

	return msgPad[:len(msgPad)-padLen], nil
}
