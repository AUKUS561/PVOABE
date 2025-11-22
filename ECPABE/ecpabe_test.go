package ecpabe

import (
	"bytes"
	"fmt"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/fentec-project/bn256"
)

// 测试：全流程得到的 Key 应等于 reference Key
func TestECPABE_FullFlow_SatisfiedPolicy(t *testing.T) {
	n := 1000
	attrNum := 25
	var err error

	e := NewECPABE()
	mk, pk := e.Setup()

	// 系统属性全集 U，要覆盖策略中会用到的所有属性
	var U []string
	for i := 1; i <= 50; i++ {
		U = append(U, "Attr"+strconv.Itoa(i)) // Attr1, Attr2, ..., Attr100
	}

	// 访问策略
	// policy := "Attr1 OR (Attr2 AND Attr3)"
	// msp, err := abe.BooleanToMSP(policy, false)
	// if err != nil {
	// 	t.Fatalf("BooleanToMSP failed: %v", err)
	// }

	// Bob 作为DO，给他一个属性集
	var SB []string
	for i := 1; i <= attrNum; i++ {
		SB = append(SB, "Attr"+strconv.Itoa(i)) // A1, A2, ..., A10
	}
	var EKb *big.Int
	var UPb *UPi
	starttime := time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		EKb, _, UPb, _, err = e.KeyGen(U, mk, SB)
	}
	endtime := time.Now().UnixMilli()
	fmt.Printf("KeyGen algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))
	if err != nil {
		t.Fatalf("KeyGen for Bob failed: %v", err)
	}

	// Alice 的属性
	var SA []string
	for i := 1; i <= attrNum; i++ {
		SA = append(SA, "Attr"+strconv.Itoa(i)) // A1, A2, ..., A10
	}
	_, DKa, _, TKbA, err := e.KeyGen(U, mk, SA)
	if err != nil {
		t.Fatalf("KeyGen for Alice failed: %v", err)
	}

	//Bob 本地加密：得到 preCT
	var preCT *PreCT
	starttime = time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		preCT, err = e.Encrypt(pk, EKb, attrNum)
	}
	endtime = time.Now().UnixMilli()
	fmt.Printf("DOEnc algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	//OutEncrypt：得到完整 CT
	var ct *CipherText
	starttime = time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		ct, err = e.OutEncrypt(pk, UPb, preCT)
	}
	endtime = time.Now().UnixMilli()
	fmt.Printf("OutEnc algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))
	if err != nil {
		t.Fatalf("OutEncrypt failed: %v", err)
	}

	//OutDecrypt：根据 Alice 的 TK，得到 transCT
	var transCT *bn256.GT
	starttime = time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		transCT, err = e.OutDecrypt(pk, ct, TKbA)
	}
	endtime = time.Now().UnixMilli()
	fmt.Printf("OutDec algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))
	if err != nil {
		t.Fatalf("OutDecrypt failed for satisfied policy: %v", err)
	}

	//Alice 本地 Decrypt：得到 KeyDec
	var keyDec *bn256.GT
	starttime = time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		keyDec, err = e.Decrypt(ct, transCT, DKa)
	}
	endtime = time.Now().UnixMilli()
	fmt.Printf("DUDec algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	//比较两个 GT 元素是否相同（用序列化）
	if !bytes.Equal(preCT.Mes.Marshal(), keyDec.Marshal()) {
		t.Fatalf("decryption key mismatch:\n got  %x\n want %x",
			preCT.Mes.Marshal(), keyDec.Marshal())
	}
}
