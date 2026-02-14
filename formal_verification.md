# Aetheris (AET) 形式化验证策略

为了实现“最大化恶意下数学安全”，Aetheris 必须通过形式化验证建立逻辑防线。

## 1. 验证目标

### 1.1 协议逻辑 (Protocol Semantics)
- **工具**: TLA+
- **目标**: 证明在任何并发状态、网络分区或节点恶意行为下，Nullifier 的唯一性和价值守恒律永远不会被打破。

### 1.2 密码学电路 (ZK-Circuits)
- **工具**: Ecne / Lean
- **目标**: 证明 Halo 2 约束系统（Constraints）与数学谓词之间存在双射关系，确保没有“欠约束（Under-constrained）”导致的伪造证明。

### 1.3 虚拟机正确性 (ZK-VM Integrity)
- **工具**: Coq
- **目标**: 形式化定义 RISC-V 指令集在 ZK 环境下的语义，确保合约代码的执行结果在数学上是唯一的且可预测的。

## 2. 安全性定理定义

### 定理：主权一致性 (Sovereign Consistency)
$\forall \text{ State } S, \forall \text{ Malicious Actors } M, \text{ if } Verify(\pi, S_{prev} \rightarrow S_{next}) = True \text{ and } \pi \text{ follows Formal\_Spec, then } S_{next} \text{ is valid.}$

## 3. 验证路线图
1. **阶段 1**: 使用 TLA+ 对 VDF 发行与主权同步逻辑进行建模。
2. **阶段 2**: 对核心 Record 转换谓词进行 Lean 形式化证明。
3. **阶段 3**: 建立自动化 CI 流程，确保每次代码更新都符合形式化规范。
