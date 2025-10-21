package main

import (
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPVGSSSetup(t *testing.T) {
	pvgss := NewPVGSS()
	attrs := "清华 北大 博士 硕士 教授"

	pk, sk, err := pvgss.PVGSSSetup(attrs)
	require.NoError(t, err)
	require.NotNil(t, pk)
	require.NotNil(t, sk)

	// 打印 PK 和 SK 中的所有参数，便于调试
	t.Logf("PK.Order = %s", pk.Order.String())
	if sk.A != nil {
		t.Logf("SK.A = %s", sk.A.String())
	} else {
		t.Logf("SK.A = <nil>")
	}

	// 打印 G/H/Pk (指针值或可打印表示)
	t.Logf("PK.G = %v", pk.G)
	t.Logf("PK.H = %v", pk.H)
	t.Logf("PK.Pk = %v", pk.Pk)

	// 打印每个属性对应的 hx 和 pkx
	t.Logf("属性数量 = %d", len(pk.HXs))
	for attr, hx := range pk.HXs {
		pkx := pk.PkXs[attr]
		t.Logf("attr=%s, hx=%v, pkx=%v", attr, hx, pkx)
	}

	// 属性数量应与 PK 映射长度一致
	numAttrs := len(strings.Split(attrs, " "))
	require.Equal(t, numAttrs, len(pk.HXs))
	require.Equal(t, numAttrs, len(pk.PkXs))

	// Order 应当为正数
	require.NotNil(t, pk.Order)
	require.True(t, pk.Order.Cmp(big.NewInt(0)) > 0)
}
