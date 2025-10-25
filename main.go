package main

import (
	"crypto/aes"
	cbc "crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"

	"github.com/AUKUS561/PVOABE/DLEQ"
	"github.com/AUKUS561/PVOABE/PVGSS"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
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

func (pvoabe *PVOABE) KeyGen(pk *PublicKey, mk *big.Int, su string) (*PVGSS.OSK, *bn256.G1, error) {
	OSK, _ := PVGSS.NewPVGSS().KeyGen(pk.PP, su)
	//DSK=g^alpha h^t
	g1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	part1 := new(bn256.G1).ScalarMult(g1, mk)
	DSK := new(bn256.G1).Add(part1, OSK.Ht)
	return OSK, DSK, nil
}

type CipherText struct {
	C      *bn256.GT
	Cprime *bn256.G2
	B      *bn256.G1
	Msp    *abe.MSP
	symEnc []byte
	iv     []byte
}

func (pvoabe *PVOABE) Enc(pk *PublicKey, msg string) (*CipherText, error) {

	//s<-Zp,计算B,C',指定访问控制策略，并生成msp矩阵
	sampler := sample.NewUniformRange(big.NewInt(1), pk.PP.Order)
	s, _ := sampler.Sample()
	B := new(bn256.G1).ScalarMult(pk.PP.Pk, s)      //B=pk^s
	Cprime := new(bn256.G2).ScalarBaseMult(s)       //C'
	abeTerm := new(bn256.GT).ScalarMult(pk.Base, s) //e(g,g)^alpha s
	policy := "教授 OR (海南大学 AND 博士)"
	msp, _ := abe.BooleanToMSP(policy, false)

	_, keyGt, err := bn256.RandomGT(rand.Reader)
	if err != nil {
		return nil, err
	}

	keyCBC := sha256.Sum256([]byte(keyGt.String()))

	c, err := aes.NewCipher(keyCBC[:])
	if err != nil {
		return nil, err
	}

	iv := make([]byte, c.BlockSize())
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}
	encrypterCBC := cbc.NewCBCEncrypter(c, iv)

	msgByte := []byte(msg)

	// message is padded according to pkcs7 standard
	padLen := c.BlockSize() - (len(msgByte) % c.BlockSize())
	msgPad := make([]byte, len(msgByte)+padLen)
	copy(msgPad, msgByte)
	for i := len(msgByte); i < len(msgPad); i++ {
		msgPad[i] = byte(padLen)
	}

	symEnc := make([]byte, len(msgPad))
	encrypterCBC.CryptBlocks(symEnc, msgPad)
	C := new(bn256.GT).Add(keyGt, abeTerm) //C = keyGt · e(h, g)αs

	return &CipherText{
		C:      C,
		Cprime: Cprime,
		B:      B,
		Msp:    msp,
		symEnc: symEnc,
		iv:     iv,
	}, nil
}

func (pvoabe *PVOABE) OEnc(pk *PublicKey, B *bn256.G1, msp *abe.MSP) (map[int]*PVGSS.CipherText, error) {
	ct := make(map[int]*PVGSS.CipherText)
	ct, err := PVGSS.NewPVGSS().Share(pk.PP, B, msp)
	if err != nil {
		return nil, err
	}
	return ct, nil
}

func (pvoabe *PVOABE) OEncVer(pk *PublicKey, ct map[int]*PVGSS.CipherText, Cprime *bn256.G2, msp *abe.MSP) bool {
	return PVGSS.NewPVGSS().SVerify(pk.PP, ct, Cprime, msp)
}

func (pvoabe *PVOABE) ODec(pk *PublicKey, ct map[int]*PVGSS.CipherText, msp *abe.MSP, OSK *PVGSS.OSK, sk *PVGSS.SecretKey) (*bn256.GT, *DLEQ.Prfs, error) {
	R, Proof, err := PVGSS.NewPVGSS().Recon(pk.PP, ct, msp, OSK, sk)
	if err != nil {
		return nil, nil, err
	}
	return R, Proof, nil
}

func (pvoabe *PVOABE) ODecVer(pk *PublicKey, ct map[int]*PVGSS.CipherText, msp *abe.MSP, OSK *PVGSS.OSK, R *bn256.GT, Proof *DLEQ.Prfs) bool {
	return PVGSS.NewPVGSS().DVerify(pk.PP, ct, msp, OSK, R, Proof)
}

func (pvoabe *PVOABE) Dec(CT *CipherText, DSK *bn256.G1, R *bn256.GT) (string, error) {
	if CT.C == nil || DSK == nil || R == nil {
		return "", fmt.Errorf("nil input")
	}

	// 详细调试信息
	fmt.Printf("=== Detailed Decryption Analysis ===\n")

	// 计算 e(DSK, C')
	pairDSKCprime := bn256.Pair(DSK, CT.Cprime)
	T := new(bn256.GT).Set(pairDSKCprime)

	// 计算 R 的逆元
	RInv := new(bn256.GT).Neg(R)

	// T = e(DSK, C') * R^(-1) = e(g,g)^(αs)
	T = new(bn256.GT).Add(T, RInv)

	// 现在计算 keyGT = C / T = C * T^(-1)
	TInv := new(bn256.GT).Neg(T) // T 的逆元
	keyGt := new(bn256.GT).Add(CT.C, TInv)

	// 2) 从 keyGt 导出 AES key（与Encrypt 中一致）
	keyCBC := sha256.Sum256([]byte(keyGt.String()))
	c, err := aes.NewCipher(keyCBC[:])
	if err != nil {
		return "", err
	}

	// 3) 解密 AES-CBC 得到明文并去 PKCS7 填充
	if len(CT.iv) != c.BlockSize() {
		return "", fmt.Errorf("invalid IV length")
	}
	if len(CT.symEnc)%c.BlockSize() != 0 {
		return "", fmt.Errorf("invalid symEnc length")
	}

	msgPad := make([]byte, len(CT.symEnc))
	decrypter := cbc.NewCBCDecrypter(c, CT.iv)
	decrypter.CryptBlocks(msgPad, CT.symEnc)

	// unpad PKCS7
	padLen := int(msgPad[len(msgPad)-1])
	if padLen <= 0 || padLen > c.BlockSize() {
		return "", fmt.Errorf("invalid padding")
	}
	if len(msgPad)-padLen < 0 {
		return "", fmt.Errorf("invalid padding/length")
	}
	msg := msgPad[:len(msgPad)-padLen]

	return string(msg), nil
}
