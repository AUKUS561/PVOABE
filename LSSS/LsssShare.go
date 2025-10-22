package LSSS

import (
	"math/big"

	"github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
)

// LSSSShare 执行 λ = M * v
func Share(msp *abe.MSP, S *big.Int, p *big.Int) (map[int]*big.Int, error) {
	sampler := sample.NewUniform(p)
	// random vector v with S as first element
	v, err := data.NewRandomVector(msp.Mat.Cols(), sampler)
	if err != nil {
		return nil, err
	}
	v[0] = new(big.Int).Set(S)

	// 计算 λ = M * v
	lambdaI, err := msp.Mat.MulVec(v)
	if err != nil {
		return nil, err
	}

	// 将 data.Vector 转换为 map[int]*big.Int，并做模p处理
	lambdaMap := make(map[int]*big.Int)
	for i, val := range lambdaI {
		lambdaMap[i] = new(big.Int).Mod(val, p)
	}

	return lambdaMap, nil
}
