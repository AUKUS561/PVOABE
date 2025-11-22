package VOABE

import (
	"fmt"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/fentec-project/bn256"
	"github.com/stretchr/testify/require"
)

func TestVOABE_FullFlowWithPolicy(t *testing.T) {
	// 1. 初始化方案
	voabe := NewVOABE()
	attrNum := 25
	n := 1000
	var err error

	// 系统属性全集 U，要覆盖策略中会用到的所有属性
	var U []string
	for i := 1; i <= 100; i++ {
		U = append(U, "Attr"+strconv.Itoa(i)) // Attr1, Attr2, ..., Attr100
	}
	pk, msk := voabe.SetUp(U)
	require.NotNil(t, pk, "pk should not be nil")
	require.NotNil(t, msk, "msk should not be nil")

	// 2. 生成 PV 的密钥对 (pkPV, skPV)
	var skPV *big.Int
	var pkPV *bn256.G1
	var pkPVG2 *bn256.G2
	starttime := time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		pkPV, pkPVG2, skPV = voabe.KeyGenPV(pk, msk)
	}
	endtime := time.Now().UnixMilli()
	fmt.Printf("KeyGen_PV algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))
	require.NotNil(t, pkPV, "pkPV should not be nil")
	require.NotNil(t, skPV, "skPV should not be nil")

	// 3. 生成 DO 的密钥（给 CS 部分 & 给 DO 自己部分）
	//DO 的身份和属性（这里让 DO 拥有所有策略里的属性）
	IDDO := "DO-001"
	var SDO []string
	for i := 1; i <= attrNum; i++ {
		SDO = append(SDO, "Attr"+strconv.Itoa(i)) // A1, A2, ..., A10
	}
	var skDOcs *SKcs
	starttime = time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		skDOcs, _ = voabe.KeyGenU(pk, msk, IDDO, SDO)
	}
	endtime = time.Now().UnixMilli()
	fmt.Printf("KeyGen_DO algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))
	require.NotNil(t, skDOcs, "skDOcs should not be nil")

	// 4. 生成 DU 的密钥（外包解密所需）
	//DU 的属性集要满足访问策略
	IDDU := "DU-001"
	var SDU []string
	for i := 1; i <= attrNum; i++ {
		SDU = append(SDU, "Attr"+strconv.Itoa(i)) // A1, A2, ..., A10
	}
	fmt.Printf("User attribute set:%v\n", SDU)
	var skDUcs *SKcs
	var skDU *Sku
	starttime = time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		skDUcs, skDU = voabe.KeyGenU(pk, msk, IDDU, SDU)
	}
	endtime = time.Now().UnixMilli()
	fmt.Printf("KeyGen_DU algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))
	require.NotNil(t, skDUcs, "skDUcs should not be nil")
	require.NotNil(t, skDU, "skDU should not be nil")

	// 6. DO 按策略加密 KR
	var cphDo *Cph
	var policySet []string
	starttime = time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		cphDo, policySet = voabe.EncDo(pk, pkPV, pkPVG2, attrNum)
	}
	endtime = time.Now().UnixMilli()
	fmt.Printf("DO_Enc algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))
	require.NotNil(t, cphDo, "EncDo ciphertext should not be nil")

	// 7. CS 根据中间密文生成最终密文 cph
	var cph *CPh
	starttime = time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		cph = voabe.EncCS(pk, cphDo, pkPV)
	}
	endtime = time.Now().UnixMilli()
	fmt.Printf("CS_Enc algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))
	require.NotNil(t, cph, "EncCS ciphertext should not be nil")

	// 8. PV 要求 CS 证明它是“按访问控制策略正确生成密文的
	//SDoStar 是 DO 属性的一个子集，用于构造证明里 ∏ hx 部分
	SDoStar := policySet
	var proof *Proof
	starttime = time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		proof, err = voabe.GenProofForPV(pk, skDOcs, cph, IDDO, SDoStar)
	}
	endtime = time.Now().UnixMilli()
	fmt.Printf("CS_Gen_Proof algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))
	require.NoError(t, err, "GenProofForPV should not return an error")
	require.NotNil(t, proof, "proof should not be nil")

	// 9. PV 本地验证证明
	var verifyResult bool
	starttime = time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		verifyResult = voabe.VerifyProofSymmetric(pk, cph, proof, IDDO)
	}
	endtime = time.Now().UnixMilli()
	fmt.Printf("verifyProof algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))
	require.True(t, verifyResult, "proof from CS should be accepted by PV")
	t.Logf("Verify Proof Result : %v", verifyResult)

	// 10. 证明通过后，PV 对密文做 Sanitize，得到最终可给 DU 使用的密文
	var cphSan *CPh
	starttime = time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		cphSan = voabe.Sanitize(pk, skPV, cph)
	}
	endtime = time.Now().UnixMilli()
	fmt.Printf("Sanitize algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))
	require.NotNil(t, cphSan, "Sanitized ciphertext should not be nil")

	// 11. CS 帮 DU 做外包解密：用 DU 的 CS 端密钥 skDUcs 和属性 SDU
	var phiDU *bn256.GT
	starttime = time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		phiDU, err = voabe.DecCS(pk, cphSan, skDUcs, SDU)
	}
	endtime = time.Now().UnixMilli()
	fmt.Printf("Outsourced decryption algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))
	require.NoError(t, err, "DecCS should not return an error")
	require.NotNil(t, phiDU, "phiDU should not be nil")

	// 12. DU 用自己的密钥 skDU 做最终解密
	var decKR *bn256.GT
	starttime = time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		decKR, err = voabe.DecDU(phiDU, cphSan, skDU)
	}
	endtime = time.Now().UnixMilli()
	fmt.Printf("DU decryption algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))
	require.NoError(t, err, "DecDU should not return an error")
	require.NotNil(t, decKR, "KR should not be nil")
	//require.Equal(t, KR, decKR, "decrypted record should equal original R")
	//t.Logf("Decrypted Message: %s", decR)
}
