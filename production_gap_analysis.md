# Aetheris (AET) 生产级递归证明实现差距分析

本报告评估了当前 `aetheris-recursive` 模块与生产级（Mainnet-ready）实现之间的技术差距，并提出了实施路径。

## 1. 核心技术差距

### 1.1 密码学后端与累积器 (Accumulator)
- **现状**: 目前使用 Mock 数据结构表示累积器（`lhs`, `rhs` 为随机场元素）。
- **差距**: 生产环境需要集成真正的 **Halo2 Accumulation Scheme**。
  - **IPA (Inner Product Argument)**: Aetheris 当前采用 BN254/Grumpkin 曲线对（非 Pasta），需要实现基于 IPA 的延迟开启逻辑。
  - **Circuit-in-Circuit Verification**: 需要在电路中实现 Pallas 曲线上的 Vesta 验证逻辑（或反之），这涉及复杂的椭圆曲线点运算电路（Fp-in-Fq）。

### 1.2 Poseidon 哈希函数实现
- **现状**: 使用 `PoseidonChip` 的 Mock 实现，哈希结果固定为 `ZERO` 或随机值。
- **差距**: 生产级实现需要：
  - **常量定义**: 引入标准的 Poseidon Round Constants 和 MDS 矩阵。
  - **S-Box 约束**: 在电路中强制执行 $x^5$ 或 $x^{\alpha}$ 的非线性转换约束。
  - **性能优化**: 针对不同输入长度（Rate）进行定制化。

### 1.3 证明生成性能 (Proving Time)
- **现状**: 目前仅在 `k=8` 的小规模电路下通过 `MockProver` 验证。
- **差距**: 
  - **证明时长**: 递归证明的生成通常耗时数秒至数十秒。
  - **内存消耗**: 需要针对移动端进行内存优化（如使用 GPU 加速或 WASM 优化）。

### 1.4 分布式聚合协议 (Gossip-Aggregation Protocol)
- **现状**: 逻辑仅存在于单机 `RecursiveManager`。
- **差距**: 
  - **P2P 传播**: 需要设计抗 DoS 的证明传播机制。
  - **激励机制**: 如何奖励参与聚合的节点（非垄断性激励）。
  - **并发冲突**: 多个节点同时生成不同路径的聚合证明时，网络如何收敛到主链。

## 2. 生产级路线图 (Roadmap)

### 阶段 1: 密码学基础加固 (短期)
- [x] 实现 Poseidon 自定义哈希 chip（round constants 和 MDS 矩阵为自生成非标准版本，需替换为审计库）。
- [x] 在 BN254/Grumpkin（非 Pasta）曲线上实现 ECC 电路基础（点加、倍点、标量乘法）。
- [x] 实现基础的 IPA 累积逻辑（含承诺折叠和 MSM 验证）。
- [x] 实现 `RangeCheckChip` 及其 Lookup Table 优化。
- [x] 实现真正的 IPA 证明反序列化逻辑（32-byte field elements）。

### 阶段 2: 递归协议完善 (中期)
- [x] 实现 **Cycle of Curves** 基础的非原生域运算逻辑（Fp-in-Fq）。
- [x] 实现电路内的公钥哈希（Public Input Hashing）和累加器状态绑定。
- [x] 完善 Poseidon Partial Round 门逻辑，支持完整的 MDS 矩阵混合。
- [x] 优化分布式聚合的 P2P 模拟器，测试网络收敛速度。
- [x] 优化电路层级的“原子平等”约束，平衡安全性与证明效率。

### 阶段 3: 安全加固与审计 (Production Ready)
- [x] **ECC On-Curve 校验**: 对所有 IPA 证明点强制执行 $y^2 = x^3 + 5$ 校验。
- [x] **NUMS 生成器**: 使用可审计的 NUMS 点替换 IPA 中的硬编码 H 生成器。
- [x] **FFI 内存安全**: 使用 `Arc<RwLock>` 重构 FFI 句柄，防止多线程竞争和内存泄漏。
- [x] **非原生算术约束审计**: 实现进位 (0/1) 和商 (Range Check) 的严格约束。
- [x] **MSM 算法优化**: 实现 2-bit 窗口化标量乘法，显著减少电路约束数量和证明生成时间。

### 阶段 4: 性能极限优化与网络集成
- [ ] **MSM 查找表优化**: 将 MSM 中的标量乘法进一步分解为查找表操作以提升性能。
- [ ] **GPU 加速集成**: 在聚合器节点中引入 GPU 加速 MSM/NTT 运算。
- [ ] **libp2p 真实网络层**: 替换模拟的 `P2PRecursiveManager`，实现真实的 Gossipsub 传播。

## 3. 安全性风险评估
- **递归深度攻击**: 极深的递归可能导致数值溢出或验证时间呈指数增长，已通过 `depth` 约束缓解。
- **累积器伪造**: 若 IPA 开启证明存在漏洞，可能导致假证明被聚合。
- **DoS 攻击**: 恶意节点发送大量非法证明占用聚合算力，需要 P2P 层级的过滤机制。
