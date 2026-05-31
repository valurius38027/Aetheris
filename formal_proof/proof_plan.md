# Aetheris 形式化证明重构计划 (Audit-driven Refactoring)

> **审计状态**: 核心理论缺陷已识别
> **重构目标**: 从“协议逻辑描述”转向“安全性数学证明”，消除逻辑自杀与黑盒公理。

## 1. 深度审计识别的缺陷修复路线 (Remediation Roadmap)

### 第一阶段：逻辑纠偏 (Logic Correction)
- [x] **任务 1.1**: 重构 `Aetheris_Privacy.v`。废除基于“存在性矛盾”的错误定义，引入**基于模拟器的不可区分性 (Indistinguishability)**。已完成隐私定理证明。
- [x] **任务 1.2**: 修正 `Aetheris_VDF.v`。将 `vdf_sequentiality` 从 Axiom 降级为 Theorem，引入具体的串行运算代价模型并证明发行时间限制。

### 第二阶段：消除黑盒 (White-boxing Primitives)
- [x] **任务 2.1**: 创建 `Aetheris_ZK_Circuit.v`。不再直接 Parameterize 提取器，建模 ZK 证明的知识完备性与平衡约束。
- [x] **任务 2.2**: 补完 `Aetheris_Tree.v`。实现具体的 **Merkle 路径校验逻辑**，引入哈希函数的抗碰撞假设并证明路径唯一性。

### 第三阶段：完整归纳链 (Full Inductive Chain)
- [x] **任务 3.1**: 彻底重写 `Aetheris_Integrity.v`。消除所有 `Admitted`，利用归纳法证明从创世状态开始，全局链的每一笔交易均保持平衡。
- [x] **任务 3.2**: 创建 `Aetheris_Consensus.v`。建模**数学仲裁 (Mathematical Arbitration)**，证明只要提议集合一致，全网在无投票情况下必然达成确定性收敛。

---

### 第四阶段：集体递归与聚合验证 (Recursive Aggregation)
- [ ] **任务 4.1**: 创建 `Aetheris_Recursive_Aggregation.v`。建模 Halo2 Accumulation Scheme 的代数结构，证明聚合操作的结合律与正确性。
- [ ] **任务 4.2**: 定义**归纳完备性 (Inductive Soundness)** 定理。证明只要初始状态合法且递归步有效，则任意深度的区块状态均满足守恒律。
- [ ] **任务 4.3**: 建模**原子平等性 (Atomic Equality)**。证明生成原子证明的计算开销 $E_{at}$ 存在上界，确保低功耗设备的准入主权。


### 2026-02-12 21:00 (Consensus Alignment)
- **状态**: 移除人为引入的 aBFT 投票构造，回归白皮书的纯数学仲裁。
- **动作**: 
    - 删除了代码中的投票步骤，实现了 `MathematicalArbitrator`。
    - 编写了 `Aetheris_Consensus.v` 并证明了胜者的存在性与确定性收敛。
    - 确保代码、证明、白皮书三者在共识逻辑上完全对齐。

### 2026-02-12 19:46 (Audit Acknowledgement)
- **状态**: 确认审计报告中的“语义自杀”与“循环论证”问题。
- **动作**: 启动全量重构。首要目标是修正隐私定义。

### 2026-02-12 20:15 (Refactoring Completion)
- **状态**: 深度审计发现的 5 大核心缺陷已全部修复。
- **动作**: 
    - 修正了 `Aetheris_Privacy.v` 的隐私定义。
    - 降级了 `Aetheris_VDF.v` 的公理为代数模型。
    - 建立了 `Aetheris_ZK_Circuit.v` 的 R1CS 约束模型。
    - 补完 `Aetheris_Tree.v` 的 Merkle 路径证明。
    - 彻底消除了 `Aetheris_Integrity.v` 中的 `Admitted`。
    - 所有文件均通过 `coqc` 编译。
