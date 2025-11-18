package VOABE

import (
	"strconv"
	"testing"

	"github.com/fentec-project/gofe/abe"
	"github.com/stretchr/testify/require"
)

func TestVOABE_FullFlowWithPolicy(t *testing.T) {
	// 1. 初始化方案
	voabe := NewVOABE()

	// 系统属性全集 U，要覆盖策略中会用到的所有属性
	var U []string
	for i := 1; i <= 100; i++ {
		U = append(U, "Attr"+strconv.Itoa(i)) // Attr1, Attr2, ..., Attr100
	}
	pk, msk := voabe.SetUp(U)
	require.NotNil(t, pk, "pk should not be nil")
	require.NotNil(t, msk, "msk should not be nil")

	// 2. 生成 PV 的密钥对 (pkPV, skPV)
	pkPV, skPV := voabe.KeyGenPV(pk, msk)
	require.NotNil(t, pkPV, "pkPV should not be nil")
	require.NotNil(t, skPV, "skPV should not be nil")

	// 3. 生成 DO 的密钥（给 CS 部分 & 给 DO 自己部分）
	//DO 的身份和属性（这里让 DO 拥有所有策略里的属性）
	IDDO := "DO-001"
	var SDO []string
	for i := 1; i <= 10; i++ {
		SDO = append(SDO, "Attr"+strconv.Itoa(i)) // A1, A2, ..., A10
	}
	skDOcs, _ := voabe.KeyGenU(pk, msk, IDDO, SDO)
	require.NotNil(t, skDOcs, "skDOcs should not be nil")

	// 4. 生成 DU 的密钥（外包解密所需）
	//DU 的属性集要满足访问策略
	IDDU := "DU-001"
	var SDU []string
	for i := 1; i <= 10; i++ {
		SDU = append(SDU, "Attr"+strconv.Itoa(i)) // A1, A2, ..., A10
	}
	skDUcs, skDU := voabe.KeyGenU(pk, msk, IDDU, SDU)
	require.NotNil(t, skDUcs, "skDUcs should not be nil")
	require.NotNil(t, skDU, "skDU should not be nil")

	// 5. 用布尔表达式构造访问策略 MSP
	policy := "Attr1 OR (Attr2 AND Attr3)"
	msp, err := abe.BooleanToMSP(policy, false)
	require.NoError(t, err, "BooleanToMSP should not return an error")
	require.NotNil(t, msp, "msp should not be nil")

	// 6. DO 按策略加密 R
	R := []byte("这是voabe的测试明文!!")
	cphDo := voabe.EncDo(pk, pkPV, R, msp)
	require.NotNil(t, cphDo, "EncDo ciphertext should not be nil")

	// 7. CS 根据中间密文生成最终密文 cph
	cph := voabe.EncCS(pk, cphDo, pkPV)
	require.NotNil(t, cph, "EncCS ciphertext should not be nil")

	// 8. PV 要求 CS 证明它是“按访问控制策略正确生成密文的
	//SDoStar 是 DO 属性的一个子集，用于构造证明里 ∏ hx 部分
	SDoStar := []string{"Attr1"}
	proof, err := voabe.GenProofForPV(pk, skDOcs, cph, IDDO, SDoStar)
	require.NoError(t, err, "GenProofForPV should not return an error")
	require.NotNil(t, proof, "proof should not be nil")

	// 9. PV 本地验证证明
	ok := voabe.VerifyProofSymmetric(pk, cph, proof, IDDO)
	require.True(t, ok, "proof from CS should be accepted by PV")
	t.Logf("Verify Proof Result : %v", ok)

	// 10. 证明通过后，PV 对密文做 Sanitize，得到最终可给 DU 使用的密文
	cphSan := voabe.Sanitize(pk, skPV, cph)
	require.NotNil(t, cphSan, "Sanitized ciphertext should not be nil")

	// 11. CS 帮 DU 做外包解密：用 DU 的 CS 端密钥 skDUcs 和属性 SDU
	phiDU, err := voabe.DecCS(pk, cphSan, skDUcs, SDU)
	require.NoError(t, err, "DecCS should not return an error")
	require.NotNil(t, phiDU, "phiDU should not be nil")

	// 12. DU 用自己的密钥 skDU 做最终解密
	decR, err := voabe.DecDU(phiDU, cphSan, skDU)
	require.NoError(t, err, "DecDU should not return an error")
	require.Equal(t, string(R), string(decR), "decrypted record should equal original R")
	t.Logf("Decrypted Message: %s", decR)
}
