package feabse

import (
	"math/big"
	"strconv"
	"testing"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/sample"
)

// 判断两个 GT 元素是否相等
func gtEqual(a, b *bn256.GT) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.String() == b.String()
}

func TestFEABSE_FullFlow(t *testing.T) {
	// 1. 定义属性全集 U
	var U []string
	for i := 1; i <= 100; i++ {
		U = append(U, "Attr"+strconv.Itoa(i)) // Attr1, Attr2, ..., Attr100
	}

	// 2. 初始化方案，运行 Setup
	scheme := NewFEABSE()
	mpk, msk := scheme.Setup(U)

	// 3. 构造访问策略并转成 MSP
	policy := "(Attr5 OR (Attr1 AND Attr2)) AND (Attr4 OR Attr3)"
	msp, err := abe.BooleanToMSP(policy, false)
	if err != nil {
		t.Fatalf("BooleanToMSP failed: %v", err)
	}

	// 4. 选择一个属性集合 SID，满足该策略
	var SID []string
	for i := 1; i <= 5; i++ {
		SID = append(SID, "Attr"+strconv.Itoa(i)) // A1, A2, ..., A5
	}

	// 5. 生成用户密钥 SKdu
	sk := scheme.KeyGen(mpk, msk, SID)

	// 6. 生成转换密钥 TK
	tk := scheme.TKGen(mpk, sk)

	// 7. OfflineEnc：离线阶段只和 MPK 有关
	ic := scheme.OfflineEnc(mpk)

	// 8. 生成一个随机的对称封装密钥 Kθ
	sampler := sample.NewUniformRange(big.NewInt(1), scheme.P)
	kScalar, err := sampler.Sample()
	if err != nil {
		t.Fatalf("sample scalar for Kθ failed: %v", err)
	}
	// Kθ = EGG^kScalar
	Ktheta := new(bn256.GT).ScalarMult(mpk.EGG, kScalar)

	// 9. OnlineEnc：在线阶段给定 IC、访问结构 MSP、Kθ，加密得到 CT
	ct, err := scheme.OnlineEnc(mpk, ic, Ktheta, msp)
	if err != nil {
		t.Fatalf("OnlineEnc failed: %v", err)
	}

	// 10. TCTGen：服务器根据 CT2、SID、TK 生成变换密文 TCT
	TCT, err := scheme.TCTGen(mpk, ct, SID, tk)
	if err != nil {
		t.Fatalf("TCTGen failed: %v", err)
	}

	// 11. Dec：DU 用 (CT2, TCT, SKdu, TK) 恢复出 Kθ'
	KthetaRec := scheme.Dec(ct, TCT, sk, tk)

	// 12. 校验恢复出的 Kθ' 是否等于原始 Kθ
	if !gtEqual(Ktheta, KthetaRec) {
		t.Fatalf("decryption failed: Kθ mismatch\noriginal: %v\nrecovered: %v",
			Ktheta, KthetaRec)
	}
}
