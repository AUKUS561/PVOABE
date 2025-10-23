package main

import (
	"math/big"
	"strings"
	"testing"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/require"
)

func TestSetup(t *testing.T) {
	pvgss := NewPVGSS()
	attrs := "清华 北大 海南大学 博士 硕士 教授"

	pp, sk, err := pvgss.Setup(attrs)
	require.NoError(t, err)
	require.NotNil(t, pp)
	require.NotNil(t, sk)

	// 打印 PP 和 SK 中的所有参数，便于调试
	t.Logf("PP.Order = %s", pp.Order.String())
	if sk.A != nil {
		t.Logf("SK.A = %s", sk.A.String())
	} else {
		t.Logf("SK.A = <nil>")
	}

	// 打印 G/H/Pk (指针值或可打印表示)
	t.Logf("PP.G = %v", pp.G)
	t.Logf("PP.H = %v", pp.H)
	t.Logf("PP.Pk = %v", pp.Pk)

	// 打印每个属性对应的 hx 和 pkx
	t.Logf("属性数量 = %d", len(pp.HXs))
	for attr, hx := range pp.HXs {
		pkx := pp.PkXs[attr]
		t.Logf("attr=%s, hx=%v, pkx=%v", attr, hx, pkx)
	}

	// 属性数量应与 PK 映射长度一致
	numAttrs := len(strings.Split(attrs, " "))
	require.Equal(t, numAttrs, len(pp.HXs))
	require.Equal(t, numAttrs, len(pp.PkXs))

	// Order 应当为正数
	require.NotNil(t, pp.Order)
	require.True(t, pp.Order.Cmp(big.NewInt(0)) > 0)
}

func TestKeyGen(t *testing.T) {
	//先生成PP
	pvgss := NewPVGSS()
	attrs := "清华 北大 海南大学 硕士 博士 教授"
	pp, _, err := pvgss.Setup(attrs)
	require.NoError(t, err)
	require.NotNil(t, pp)
	//选择用户属性集Su
	userAttrs := "清华 博士"
	osk, err := pvgss.KeyGen(pp, userAttrs)
	require.NoError(t, err)
	require.NotNil(t, osk)
	// 打印 OSK 的所有参数
	t.Logf("OSK.L = %v", osk.L)
	t.Logf("OSK.KXs count = %d", len(osk.KXs))
	for attr, kx := range osk.KXs {
		t.Logf("KX attr=%s, kx=%v", attr, kx)
	}
}

func TestShare(t *testing.T) {
	//Setup
	pvgss := NewPVGSS()
	attrs := "清华 北大 海南大学 硕士 博士 教授"
	pp, _, err := pvgss.Setup(attrs)
	require.NoError(t, err)
	require.NotNil(t, pp)
	//s<-Zp
	sampler := sample.NewUniformRange(big.NewInt(1), pp.Order)
	s, _ := sampler.Sample()
	B := new(bn256.G1).ScalarMult(pp.Pk, s) //B=pk^s
	policy := "教授 AND (海南大学 OR 博士)"
	msp, _ := abe.BooleanToMSP(policy, false)
	shareResult, err := pvgss.Share(pp, B, msp)
	if err != nil {
		t.Errorf("fail to generate shares:%v", err)
		return
	}
	for i, v := range shareResult {
		t.Logf("C_%d=%v", i, v.Ci)
		t.Logf("C_%d'=%v", i, v.CiPrime)
	}
}

func TestSVerify(t *testing.T) {
	//Setup
	pvgss := NewPVGSS()
	attrs := "清华 北大 海南大学 硕士 博士 教授"
	pp, _, err := pvgss.Setup(attrs)
	require.NoError(t, err)
	require.NotNil(t, pp)
	//s<-Zp
	sampler := sample.NewUniformRange(big.NewInt(1), pp.Order)
	s, _ := sampler.Sample()
	B := new(bn256.G1).ScalarMult(pp.Pk, s)   //B=pk^s
	Cprime := new(bn256.G2).ScalarBaseMult(s) //C'
	policy := "教授 AND (海南大学 OR 博士)"
	msp, _ := abe.BooleanToMSP(policy, false)
	shareResult, err := pvgss.Share(pp, B, msp)
	if err != nil {
		t.Errorf("fail to generate shares:%v", err)
		return
	}

	result := pvgss.SVerify(pp, shareResult, Cprime, msp)
	t.Logf("SVerify Result: %v", result)
	require.True(t, result, "SVerify should return true for valid inputs")

}

func TestAll(t *testing.T) {
	//Setup
	pvgss := NewPVGSS()
	attrs := "清华 北大 海南大学 硕士 博士 教授"
	pp, sk, err := pvgss.Setup(attrs)
	require.NoError(t, err)
	require.NotNil(t, pp)
	require.NotNil(t, sk)

	//选择用户属性集Su
	userAttrs := "海南大学 博士"
	//KeyGen
	osk, err := pvgss.KeyGen(pp, userAttrs)
	require.NoError(t, err)
	require.NotNil(t, osk)
	// 打印 OSK 的所有参数
	t.Logf("OSK.L = %v", osk.L)
	t.Logf("OSK.KXs count = %d", len(osk.KXs))
	for attr, kx := range osk.KXs {
		t.Logf("KX attr=%s, kx=%v", attr, kx)
	}

	//s<-Zp
	sampler := sample.NewUniformRange(big.NewInt(1), pp.Order)
	s, _ := sampler.Sample()
	B := new(bn256.G1).ScalarMult(pp.Pk, s)   //B=pk^s
	Cprime := new(bn256.G2).ScalarBaseMult(s) //C'
	policy := "教授 OR (海南大学 AND 博士)"
	msp, _ := abe.BooleanToMSP(policy, false)
	//Share
	shareResult, err := pvgss.Share(pp, B, msp)
	if err != nil {
		t.Errorf("fail to generate shares")
		return
	}
	//Sverify
	result := pvgss.SVerify(pp, shareResult, Cprime, msp)
	t.Logf("SVerify Result: %v", result)
	require.True(t, result, "SVerify should return true for valid inputs")
	//Recon
	R, proof, err := pvgss.Recon(pp, shareResult, msp, osk, sk)
	if err != nil {
		t.Errorf("fail to recon")
		return
	}
	//DVerify
	finalResult := pvgss.DVerify(pp, shareResult, msp, osk, R, proof)
	t.Logf("final result :%v", finalResult)
}
