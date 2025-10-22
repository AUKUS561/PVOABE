package LSSS

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/data"
)

/*
LSSSRecon 实现秘密份额的重构。

	它适用于任何基于 LSSS 的 ABE 方案，如 Waters 2011

输入:

	msp: 包含 LSSS 矩阵 M 和行属性映射的 MSP 结构体
	shares: map[int]*bn256.GT，包含满足策略的属性行索引 i 及其对应的 GT 份额 Ai
	p: 域的素数阶。

输出: 重构后的 GT 群元素
*/
func Recon(msp *abe.MSP, shares map[int]*bn256.GT, p *big.Int) (*bn256.GT, error) {
	if len(shares) == 0 {
		return nil, errors.New("no attributes satisfy the policy for reconstruction")
	}
	// 1. 识别满足策略的行 I 并构建子矩阵 MI
	// 从 shares 中提取出对应的 LSSS 矩阵行，构成子矩阵 MI
	// SubMatrix初始化MI
	SubMatrix := make(data.Matrix, 0, len(shares))
	// indices 存储原始 LSSS 矩阵的行索引，以便与 shares 对应
	indices := make([]int, 0, len(shares))

	for i := range shares {
		// 确保行 i 存在于 MSP 矩阵中
		if i < 0 || i >= len(msp.Mat) {
			return nil, fmt.Errorf("invalid row index %d found in shares", i)
		}
		//按share中的行构建出子矩阵
		SubMatrix = append(SubMatrix, msp.Mat[i])
		indices = append(indices, i)
	}

	// 2. 准备高斯消元的目标向量(1, 0, ..., 0)
	//目标向量的长度是 LSSS 矩阵的列数n
	numCols := len(msp.Mat[0])
	targetVector := make(data.Vector, numCols)
	targetVector[0] = big.NewInt(1)
	for i := 1; i < numCols; i++ {
		targetVector[i] = big.NewInt(0)
	}

	// 3. 求重构系数的向量WI
	// 求 w * MI = vT (其中 vT 是目标向量的转置(1, 0, ..., 0))
	// Solver需要MI的转置(SubMatrix.Transpose())
	WI, err := data.GaussianEliminationSolver(SubMatrix.Transpose(), targetVector, p)
	if err != nil {
		return nil, fmt.Errorf("LSSS system is not solvable: %w", err)
	}

	// 4. 对 GT 份额进行线性组合: Result = Prod_{i in I} (Ai)^{wi}
	reconstructedGT := new(bn256.GT).ScalarBaseMult(big.NewInt(0)) //GT群的单位元 1_GT

	for k, wi := range WI {
		//从WI中提出需要的wi
		//从shares中提出需要的shareI
		originalRowIndex := indices[k]
		shareI := shares[originalRowIndex]

		// wi 可能是负数，需要处理模 p 的指数
		// 确保 wi 在 [0, P-1] 范围内
		exponent := new(big.Int).Mod(wi, p)

		// bn256.GT 的 ScalarMult 实现幂运算
		// term = (Ai)^{wi}
		term := new(bn256.GT).ScalarMult(shareI, exponent)

		// reconstructedGT = reconstructedGT * term
		reconstructedGT.Add(reconstructedGT, term)
	}

	return reconstructedGT, nil
}
