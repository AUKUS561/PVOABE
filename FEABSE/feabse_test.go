package feabse

import (
	"fmt"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/fentec-project/bn256"
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
	n := 1000
	attrNum := 5
	// 1. 定义属性全集 U
	var U []string
	for i := 1; i <= 100; i++ {
		U = append(U, "Attr"+strconv.Itoa(i)) // Attr1, Attr2, ..., Attr100
	}

	// 2. 初始化方案，运行 Setup
	scheme := NewFEABSE()
	mpk, msk := scheme.Setup(U)

	// 4. 选择一个属性集合 SID，满足该策略
	var SID []string
	for i := 1; i <= 5; i++ {
		SID = append(SID, "Attr"+strconv.Itoa(i)) // A1, A2, ..., A5
	}

	// 5. 生成用户密钥 SKdu
	var sk *SKdu
	starttime := time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		sk = scheme.KeyGen(mpk, msk, SID)
	}
	endtime := time.Now().UnixMilli()
	fmt.Printf("KeyGen algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))

	// 7. OfflineEnc：离线阶段只和 MPK 有关
	var ic *IC
	starttime = time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		ic = scheme.OfflineEnc(mpk)
	}
	endtime = time.Now().UnixMilli()
	fmt.Printf("Offline encryption algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))

	// 8. 生成一个随机的对称封装密钥 Kθ
	sampler := sample.NewUniformRange(big.NewInt(1), scheme.P)
	kScalar, err := sampler.Sample()
	if err != nil {
		t.Fatalf("sample scalar for Kθ failed: %v", err)
	}
	// Kθ = EGG^kScalar
	Ktheta := new(bn256.GT).ScalarMult(mpk.EGG, kScalar)

	// 9. OnlineEnc：在线阶段给定 IC、访问结构 MSP、Kθ，加密得到 CT
	var ct *CT
	starttime = time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		ct, err = scheme.OnlineEnc(mpk, ic, Ktheta, attrNum)
	}
	endtime = time.Now().UnixMilli()
	fmt.Printf("Online encryption algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))
	if err != nil {
		t.Fatalf("OnlineEnc failed: %v", err)
	}

	// 6. 生成转换密钥 TK
	var tk *TK
	starttime = time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		tk = scheme.TKGen(mpk, sk)
	}
	endtime = time.Now().UnixMilli()
	fmt.Printf("TransKey algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))

	// 10. TCTGen：服务器根据 CT2、SID、TK 生成变换密文 TCT
	var TCT *bn256.GT
	starttime = time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		TCT, err = scheme.TCTGen(mpk, ct, SID, tk)
	}
	endtime = time.Now().UnixMilli()
	fmt.Printf("Outsourced encryption algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))
	if err != nil {
		t.Fatalf("TCTGen failed: %v", err)
	}

	// 11. Dec：DU 用 (CT2, TCT, SKdu, TK) 恢复出 Kθ'
	var KthetaRec *bn256.GT
	starttime = time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		KthetaRec = scheme.Dec(ct, TCT, sk, tk)
	}
	endtime = time.Now().UnixMilli()
	fmt.Printf("Outsourced encryption algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))

	// 12. 校验恢复出的 Kθ' 是否等于原始 Kθ
	if !gtEqual(Ktheta, KthetaRec) {
		t.Fatalf("decryption failed: Kθ mismatch\noriginal: %v\nrecovered: %v",
			Ktheta, KthetaRec)
	}
}
