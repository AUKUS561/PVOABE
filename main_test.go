package main

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/AUKUS561/PVOABE/DLEQ"
	"github.com/AUKUS561/PVOABE/PVGSS"
	"github.com/fentec-project/bn256"
	"github.com/stretchr/testify/require"
)

func TestMainFlow(t *testing.T) {
	n := 1000
	attrNum := 3

	// 初始化 PVOABE
	pvoabe := NewPVOABE()

	// 测试 Setup
	alpha, pk, sk, err := pvoabe.Setup()
	require.NoError(t, err, "Setup should not return an error")
	require.NotNil(t, alpha, "Alpha should not be nil")
	require.NotNil(t, pk, "PublicKey should not be nil")
	require.NotNil(t, sk, "SecretKey should not be nil")

	// 测试 KeyGen
	//userAttrs := "海南大学 博士"
	var userAttrs []string
	for i := 1; i <= attrNum; i++ {
		userAttrs = append(userAttrs, "Attr"+strconv.Itoa(i)) // A1, A2, ..., A100
	}
	var osk *PVGSS.OSK
	var dsk *bn256.G1
	starttime := time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		osk, dsk, err = pvoabe.KeyGen(pk, alpha, userAttrs)
	}
	endtime := time.Now().UnixMilli()
	fmt.Printf("KeyGen algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))
	require.NoError(t, err, "KeyGen should not return an error")
	require.NotNil(t, osk, "OSK should not be nil")
	require.NotNil(t, dsk, "DSK should not be nil")

	// 测试 Encrypt
	//message := "Hello, PVOABE!" //生成要加密的msg
	var ct *CipherText
	var keyGT *bn256.GT
	starttime = time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		ct, keyGT, err = pvoabe.Enc(pk, attrNum)
	}
	endtime = time.Now().UnixMilli()
	fmt.Printf("Enc algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))
	require.NoError(t, err, "Enc should not return an error")
	require.NotNil(t, ct, "Ciphertext should not be nil")

	//测试OEnc
	var shares map[int]*PVGSS.CipherText
	starttime = time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		shares, err = pvoabe.OEnc(pk, ct.B, ct.Msp)
	}
	endtime = time.Now().UnixMilli()
	fmt.Printf("OEnc algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))
	require.NoError(t, err, "OEnc should not return an error")

	//测试OEncVer
	var resultOEnc bool
	starttime = time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		resultOEnc = pvoabe.OEncVer(pk, shares, ct.Cprime, ct.Msp)
	}
	endtime = time.Now().UnixMilli()
	fmt.Printf("OEncVer algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))
	t.Logf("OEncVer Result : %v", resultOEnc)

	//测试ODec
	var R *bn256.GT
	var Proof *DLEQ.Prfs
	starttime = time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		R, Proof, err = pvoabe.ODec(pk, shares, ct.Msp, osk, sk)
	}
	endtime = time.Now().UnixMilli()
	fmt.Printf("ODec algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))
	require.NoError(t, err, "ODec should not return an error")

	//测试ODecVer
	var resultODec bool
	starttime = time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		resultODec = pvoabe.ODecVer(pk, shares, ct.Msp, osk, R, Proof)
	}
	endtime = time.Now().UnixMilli()
	fmt.Printf("ODecVer algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))
	t.Logf("ODecVer Result : %v", resultODec)

	//测试解密
	var decryptedMessage *bn256.GT
	starttime = time.Now().UnixMilli()
	for i := 0; i < int(n); i++ {
		decryptedMessage, err = pvoabe.Dec(ct, dsk, R)
	}
	endtime = time.Now().UnixMilli()
	fmt.Printf("Dec algorithm is %.4f ms\n", float64(endtime-starttime)/float64(n))

	require.NoError(t, err, "Decrypt should not return an error")
	require.Equal(t, keyGT, decryptedMessage, "Decrypted message should match the original message")
	t.Logf("Decrypted Message: %s", decryptedMessage)
}
