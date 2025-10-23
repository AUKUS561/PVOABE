package LSSS

import (
	"math/big"
	"testing"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLSSSCompleteFlow(t *testing.T) {
	// 1. 首先测试 BooleanToMSP：创建一个简单的访问策略
	policy := "博士 OR (海南大学 AND 硕士)"
	msp, err := abe.BooleanToMSP(policy, false)
	require.NoError(t, err, "创建MSP时出错")
	require.NotNil(t, msp, "MSP不应为nil")

	p := bn256.Order // 使用bn256曲线的阶作为域的阶

	// 2. 测试 LSSSShare：生成秘密份额
	secret := big.NewInt(1) // 要共享的秘密
	lambda, err := Share(msp, secret, p)
	require.NoError(t, err, "生成份额时出错")
	require.NotNil(t, lambda, "份额结果不应为nil")

	// 打印生成的份额
	t.Log("生成的份额 λi:")
	for i, lambda := range lambda {
		t.Logf("λ_%d = %s", i, lambda.String())
	}

	// 3. 准备用于重构的GT元素份额
	// 模拟将λi映射到GT群元素的过程
	shares := make(map[int]*bn256.GT)
	g := new(bn256.GT).ScalarBaseMult(big.NewInt(1)) // 生成GT群的生成元

	// 选择满足策略的属性集合的份额
	// 这里我们选择 海南大学 和 博士 (后两行的份额)
	for i := 1; i <= 2; i++ {
		if lambdaI, exists := lambda[i]; exists {
			shares[i] = new(bn256.GT).ScalarMult(g, lambdaI)
		}
	}

	// 4. 测试 LSSSRecon：重构秘密
	reconstructed, err := Recon(msp, shares, p)
	require.NoError(t, err, "重构秘密时出错")
	require.NotNil(t, reconstructed, "重构结果不应为nil")

	// 5. 验证结果
	expected := new(bn256.GT).ScalarMult(g, secret)
	assert.True(t, reconstructed.String() == expected.String(),
		"重构的秘密与原始秘密不匹配")
}
