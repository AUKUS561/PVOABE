package ecpabe

import (
	"crypto/aes"
	cbc "crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"

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
	Galpha  *bn256.G1 //g^alpha
	Galpha2 *bn256.G2
	beta    *big.Int //β
}

type PK struct {
	G    *bn256.G1
	G2   *bn256.G2
	H    *bn256.G1 //h = g^β
	Base *bn256.GT //e(g,g)^alpha
}

func (ecpabe *ECPABE) Setup() (*MK, *PK) {
	//α, β ∈ Zp
	sampler := sample.NewUniformRange(big.NewInt(1), ecpabe.P)
	alpha, _ := sampler.Sample()
	beta, _ := sampler.Sample()

	g := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	h := new(bn256.G1).ScalarMult(g, beta)       //h = g^β
	galpha := new(bn256.G1).ScalarMult(g, alpha) //g^alpha
	galpha2 := new(bn256.G2).ScalarMult(g2, alpha)

	egg := bn256.Pair(g, g2)
	base := new(bn256.GT).ScalarMult(egg, alpha)
	return &MK{
			Galpha:  galpha,
			Galpha2: galpha2,
			beta:    beta,
		}, &PK{
			G:    g,
			G2:   g2,
			H:    h,
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
	D     *bn256.G2            // Di
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
	gRi := new(bn256.G2).ScalarMult(g2, ri)
	num := new(bn256.G2).Add(MK.Galpha2, gRi) // num = g^{α + ri}
	den := new(big.Int).Mul(MK.beta, zi)      // β * z_i
	den.Mod(den, ecpabe.P)
	invDen := new(big.Int).ModInverse(den, ecpabe.P) //1/(β zi)
	tk.D = new(bn256.G2).ScalarMult(num, invDen)

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
	MSP  *abe.MSP         // (M, ρ)
	C    *bn256.G1        // h^s
	Cpre map[int]*big.Int //Ci^pre = H2(ρ(i)||sB) * λi
}

func (ecpabe *ECPABE) Encrypt(pk *PK, EKb *big.Int, msp *abe.MSP) (*PreCT, error) {
	sampler := sample.NewUniform(ecpabe.P)

	// s ∈ Zp
	s, _ := sampler.Sample()

	//Compute C = h^s
	C := new(bn256.G1).ScalarMult(pk.H, s)

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
		C:    C,
		Cpre: Cpre,
	}
	return preCT, nil
}

type CipherText struct {
	MSP *abe.MSP          // (M, ρ)
	C   *bn256.G1         // C = h^s
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
		invDen := new(bn256.GT).ScalarMult(den, negOne)

		// sharei = num * den^{-1}
		share := new(bn256.GT).Add(num, invDen)

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
	eCD := bn256.Pair(ct.C, tkA.D)

	// A^{-1} = A^{p-1}
	invA := new(bn256.GT).ScalarMult(A, negOne)

	// transCT = e(C, D_A) * A^{-1} = e(g,g)^{α·s/z_A}
	transCT := new(bn256.GT).Add(eCD, invA)

	return transCT, nil
}

// Decrypt(PK, transCT, DKA)->key
func (ecpabe *ECPABE) Decrypt(transCT *bn256.GT, DKA *big.Int) (*bn256.GT, error) {
	if transCT == nil || DKA == nil {
		return nil, errors.New("Decrypt: transCT or DKA is nil")
	}

	exp := new(big.Int).Mod(DKA, ecpabe.P)

	// Key = transCT^{DKA} = e(g,g)^{α·s}
	Key := new(bn256.GT).ScalarMult(transCT, exp)

	return Key, nil
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
