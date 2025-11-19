package ecpabe

import (
	"bytes"
	"math/big"
	"strconv"
	"testing"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
)

// Use MK and CT compute KeyRef = e(g, g2)^{α·s}
// 这里利用 C = h^s = g^{β s}，已知 β，可以求出 g^s，再与 g2^α 配对。
func computeReferenceKey(t *testing.T, e *ECPABE, mk *MK, ct *CipherText) *bn256.GT {
	// g^s = C^{1/β}
	invBeta := new(big.Int).ModInverse(mk.beta, e.P)
	if invBeta == nil {
		t.Fatal("computeReferenceKey: beta has no inverse")
	}
	gToS := new(bn256.G1).ScalarMult(ct.C, invBeta) // g^{s}

	// KeyRef = e(g^s, g2^α) = e(g, g2)^{α·s}
	keyRef := bn256.Pair(gToS, mk.Galpha2)
	return keyRef
}

// 测试：全流程得到的 Key 应等于 reference Key
func TestECPABE_FullFlow_SatisfiedPolicy(t *testing.T) {
	e := NewECPABE()
	mk, pk := e.Setup()

	// 系统属性全集 U，要覆盖策略中会用到的所有属性
	var U []string
	for i := 1; i <= 100; i++ {
		U = append(U, "Attr"+strconv.Itoa(i)) // Attr1, Attr2, ..., Attr100
	}

	// 访问策略
	policy := "Attr1 OR (Attr2 AND Attr3)"
	msp, err := abe.BooleanToMSP(policy, false)
	if err != nil {
		t.Fatalf("BooleanToMSP failed: %v", err)
	}

	// Bob 作为DO，给他一个属性集
	var SB []string
	for i := 1; i <= 10; i++ {
		SB = append(SB, "Attr"+strconv.Itoa(i)) // A1, A2, ..., A10
	}
	EKb, _, UPb, _, err := e.KeyGen(U, mk, SB)
	if err != nil {
		t.Fatalf("KeyGen for Bob failed: %v", err)
	}

	// Alice 的属性
	var SA []string
	for i := 1; i <= 10; i++ {
		SA = append(SA, "Attr"+strconv.Itoa(i)) // A1, A2, ..., A10
	}
	_, DKa, _, TKbA, err := e.KeyGen(U, mk, SA)
	if err != nil {
		t.Fatalf("KeyGen for Alice failed: %v", err)
	}

	//Bob 本地加密：得到 preCT
	preCT, err := e.Encrypt(pk, EKb, msp)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	//OutEncrypt：得到完整 CT
	ct, err := e.OutEncrypt(pk, UPb, preCT)
	if err != nil {
		t.Fatalf("OutEncrypt failed: %v", err)
	}

	//OutDecrypt：根据 Alice 的 TK，得到 transCT
	transCT, err := e.OutDecrypt(pk, ct, TKbA)
	if err != nil {
		t.Fatalf("OutDecrypt failed for satisfied policy: %v", err)
	}

	//Alice 本地 Decrypt：得到 KeyDec
	keyDec, err := e.Decrypt(transCT, DKa)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	//用 MK + CT 计算 KeyRef = e(g,g2)^{α·s}
	keyRef := computeReferenceKey(t, e, mk, ct)

	//比较两个 GT 元素是否相同（用序列化）
	if !bytes.Equal(keyDec.Marshal(), keyRef.Marshal()) {
		t.Fatalf("decryption key mismatch:\n got  %x\n want %x",
			keyDec.Marshal(), keyRef.Marshal())
	}
}
