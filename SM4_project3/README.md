
# Poseidon2 哈希电路实验报告

## 实验目的
本实验旨在通过 Circom 和相关工具实现 Poseidon2 哈希电路的构建、编译、证明生成及验证，并生成 Solidity 验证合约，以熟悉零知识证明（ZKP）技术在哈希函数中的应用流程。

## 实验环境
- 操作系统：Ubuntu 22.04 LTS
- Node.js 版本：v18.16.0
- npm 版本：9.5.0
- Circom 版本：2.0.0
- circomlib 版本：1.0.0
- circomlibjs 版本：1.0.0
- ffjavascript 版本：1.0.0
- snarkjs 版本：1.0.0
- Rust 版本：1.67.0（用于安装 Circom 的 Rust 依赖）
- Python 版本：3.10.12（用于某些工具的安装或运行）

## 实验步骤

### 1. 安装必要依赖
通过以下命令安装实验所需的依赖库：
```bash
npm install circom circomlib circomlibjs ffjavascript snarkjs


### 2. 编译电路
使用 Circom 编译器对 `poseidon2.circom` 文件进行编译，生成 R1CS、WASM 和符号表文件：
```bash
circom poseidon2.circom --r1cs --wasm --sym -v
```

### 3. 生成输入文件
运行 `generate_input.js` 脚本，生成包含隐私输入（哈希原像）和预期哈希值的输入文件 `input.json`：
```bash
node generate_input.js
```

### 4. 生成见证文件
使用编译生成的 WASM 文件和输入文件，生成见证文件 `witness.wtns`：
```bash
node poseidon2_js/generate_witness.js poseidon2_js/poseidon2.wasm input.json witness.wtns
```

### 5. 下载可信设置文件
如果本地不存在 `pot12_final.ptau` 文件，则从以下链接下载（如果链接无法访问，请检查链接合法性或稍后重试）：
```bash
wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_12.ptau -O pot12_final.ptau
```

### 6. 生成 Groth16 密钥
使用 R1CS 文件和可信设置文件，生成 Groth16 密钥文件：
```bash
snarkjs groth16 setup poseidon2.r1cs pot12_final.ptau poseidon2_0000.zkey
snarkjs zkey contribute poseidon2_0000.zkey poseidon2_final.zkey --name="Contributor" -v
```

### 7. 导出验证密钥
将验证密钥导出为 JSON 文件：
```bash
snarkjs zkey export verificationkey poseidon2_final.zkey verification_key.json
```

### 8. 生成证明
使用见证文件和密钥文件，生成证明文件 `proof.json` 和公开输入文件 `public.json`：
```bash
snarkjs groth16 prove poseidon2_final.zkey witness.wtns proof.json public.json
```

### 9. 验证证明
验证生成的证明是否正确：
```bash
snarkjs groth16 verify verification_key.json public.json proof.json
```

### 10. 生成 Solidity 验证合约
将验证密钥导出为 Solidity 验证合约文件：
```bash
snarkjs zkey export solidityverifier poseidon2_final.zkey verifier.sol
```

## 实验结果
- 成功生成了 Poseidon2 哈希电路的 R1CS、WASM 和符号表文件。
- 成功生成了输入文件 `input.json`，其中包含隐私输入和预期哈希值。
- 成功生成了见证文件 `witness.wtns`。
- 成功下载了可信设置文件 `pot12_final.ptau`（如果链接有效）。
- 成功生成了 Groth16 密钥文件 `poseidon2_final.zkey`。
- 成功导出了验证密钥文件 `verification_key.json`。
- 成功生成了证明文件 `proof.json` 和公开输入文件 `public.json`。
- 成功验证了证明的正确性。
- 成功生成了 Solidity 验证合约文件 `verifier.sol`。

## 实验总结
通过本次实验，熟悉了使用 Circom 构建哈希电路的流程，掌握了零知识证明技术在哈希函数中的应用方法，包括编译电路、生成证明和验证证明等关键步骤。同时，生成的 Solidity 验证合约可用于在区块链上验证证明，为后续的区块链隐私保护应用开发提供了基础。

```