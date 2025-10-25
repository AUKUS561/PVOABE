package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMainFlow(t *testing.T) {
	// 初始化 PVOABE 实例
	pvoabe := NewPVOABE()

	// 测试 Setup
	alpha, pk, sk, err := pvoabe.Setup()
	require.NoError(t, err, "Setup should not return an error")
	require.NotNil(t, alpha, "Alpha should not be nil")
	require.NotNil(t, pk, "PublicKey should not be nil")
	require.NotNil(t, sk, "SecretKey should not be nil")

	// 测试 KeyGen
	userAttrs := "海南大学 博士"
	osk, dsk, err := pvoabe.KeyGen(pk, alpha, userAttrs)
	require.NoError(t, err, "KeyGen should not return an error")
	require.NotNil(t, osk, "OSK should not be nil")
	require.NotNil(t, dsk, "DSK should not be nil")

	// 测试 Encrypt
	message := "Hello, PVOABE!"
	ct, err := pvoabe.Encrypt(pk, message)
	require.NotNil(t, ct, "Ciphertext should not be nil")

	//测试OEnc
	shares, err := pvoabe.OEnc(pk, ct.B, ct.Msp)

	//测试OEncVer
	t.Logf("OEncVer Result : %v", pvoabe.OEncVer(pk, shares, ct.Cprime, ct.Msp))

	//测试ODec
	R, Proof, err := pvoabe.ODec(pk, shares, ct.Msp, osk, sk)
	t.Logf("R from ODec: %v", R)

	//测试ODecVer
	t.Logf("ODecVer Result : %v", pvoabe.ODecVer(pk, shares, ct.Msp, osk, R, Proof))

	//测试解密
	decryptedMessage, err := pvoabe.Dec(ct, dsk, R)
	require.NoError(t, err, "Decrypt should not return an error")
	require.Equal(t, message, decryptedMessage, "Decrypted message should match the original message")

	t.Logf("Decrypted Message: %s", decryptedMessage)
}
