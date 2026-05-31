# Aetheris (AET) 数学规格说明书

本文件详细说明 Aetheris 协议的核心数学构造，旨在实现无需可信设置的极致隐私与安全性。

## 1. 可验证延迟函数 (VDF)

为了实现公平的时间发行，Aetheris 采用 **Wesolowski VDF**，运行在 **虚二次域类群 (Class Groups of Imaginary Quadratic Fields)** 上。

### 1.1 类群选择
选择类群而非 RSA 群是为了消除 **可信设置 (Trusted Setup)**。
- **判别式 (Discriminant)**: $\Delta = -D$，其中 $D$ 是一个由创世哈希派生的巨大质数。
- **群元素**: 由形式为 $(a, b, c)$ 的二元二次型 $ax^2 + bxy + cy^2$ 表示。

### 1.2 计算逻辑
- **输入**: $x \in G, T$ (时间参数/难度)。
- **输出**: $y = x^{2^T}$。
- **证明 $\pi$**: 为了证明 $y$ 的正确性，证明者计算 $\pi = x^{\lfloor 2^T / l \rfloor}$，其中 $l = Hash(x, y)$ 是一个大质数。
- **验证**: 校验 $y = \pi^l \cdot x^{2^T \pmod l}$ 是否成立。

### 1.3 难度自平衡 (Difficulty Self-Balancing)

VDF 的难度参数 $T$（迭代次数）必须在出块速率偏离目标时自动调整，以抵消硬件单核性能代际提升的影响。

**重定向公式**（确定性，基于链上时间戳）：

$$T_{n+1} = \text{clamp}\left(T_n \times \frac{T_{target} \times N}{\sum_{i=n-N}^{n-1} (t_i - t_{i-1})}, \quad \frac{T_n}{M}, \quad T_n \times M\right)$$

参数：
- $T_n$ = 当前难度
- $T_{target}$ = 目标出块时间（协议常数，10 秒）
- $N$ = 重定向窗口（协议常数，10 个区块）
- $t_i$ = 区块 $i$ 的时间戳
- $M$ = 最大调整倍数（协议常数，4）

**密码学自强制执行**：

难度重定向不是"节点自觉遵守的规则"，而是通过以下密码学约束自动强制：

1. VDF 验证方程使用 $2^T \bmod l$，其中 $T$ 来自区块头。若 $T$ 不等于预期值，证明不通过。
2. 每个节点独立计算高度 $h$ 处的预期难度 $T_h = retarget(chain_{<h})$，拒绝不匹配的区块。
3. 不诚实的时间戳要么违反因果序（小于父时间戳），要么自我惩罚（提前时间戳抬高难度）。

**攻击者的两难困境**：
- 若攻击者用低于预期的 $T$ 出块：VDF 证明被拒。
- 若攻击者用高于预期的 $T$ 出块：需要更多计算，自我减速。
- 若攻击者用正确的 $T$ 但伪造时间戳来操纵重定向：误差 ≤ 2 小时漂移 / ($T_{target} \times N$) ≈ 2%。

### 1.4 安全参数参考值

| 参数 | 值 | 说明 |
|------|-----|------|
| $T_{genesis}$ | 1,600,000 | 初始难度（2026 年参考值） |
| $T_{target}$ | 10 秒 | 目标出块时间 |
| $N$ | 10 | 重定向窗口 |
| $M$ | 4 | 最大调整倍数（±4x 每窗口） |

## 2. 状态表示与记录模型 (Record Model)

Aetheris 采用 **Record** 作为基本状态单元，以支持复杂的智能合约逻辑。

### 2.1 记录 (Record) 结构
一个 Record $R$ 定义为：
$$R = \{Owner, Data, Nonce, salt\}$$
- **Commitment**: $C = Poseidon(R)$ 存储在全局状态树中。
- **Data**: 可以是资产数量、合约状态变量或代码哈希。

### 2.2 状态树与递归
Aetheris 使用基于 Poseidon 哈希的 Merkle Tree，并结合 Halo 2 的递归特性，支持在 ZK 电路内的高速存在性验证。

## 3. 密码学原语 (Cryptographic Primitives)

### 3.1 椭圆曲线循环 (Cycle of Curves)
为了支持高效的递归 ZK 证明，Aetheris 采用 **Pasta 曲线对** (Pallas 和 Vesta)：
- **Pallas**: $y^2 = x^3 + 5$，标量场阶等于 Vesta 的基场阶。
- **Vesta**: $y^2 = x^3 + 5$，标量场阶等于 Pallas 的基场阶。

### 3.2 零知识虚拟机 (ZK-VM)
Aetheris 采用基于 RISC-V 架构的 ZK-VM，支持通用计算的证明生成。

## 4. 交易与合约数学谓词

Aetheris 支持主权零知识合约 (Sovereign ZK-Contracts)，其执行遵循 ZK-VM 规范。一笔有效的合约交易必须满足谓词 $\mathcal{P}_{contract}$：

1.  **代码一致性**: 证明 $H(Code) = Program\_Root$，确保执行的是预定义的合约逻辑。
2.  **状态转换证明**: 证明 $\pi_{vm}$ 满足 $VM.Execute(Code, State_{in}, Private\_Input) \rightarrow State_{out}$。
3.  **所有权证明**: $VerifySig(owner\_pk, msg, proof)$。
4.  **非双花证明**: 每个消耗的状态 Record 必须产生唯一的 $Nullifier = H(sk, Record\_ID)$。
5.  **价值守恒与范围证明**: 确保合约执行过程中没有凭空产生资产，且所有输出金额非负。

## 4. 极致隐私：零知识 Nullifier 与全同态状态更新

为了实现不可追查性，Nullifier 的生成必须满足：
- **唯一性**: 给定相同的 UTXO，生成的 Nullifier 必须相同。
- **不可关联性**: 在不知道私钥 $sk$ 的情况下，无法关联 Nullifier 与 UTXO 承诺 $C$。
- **数学表达式**: $N = g^{1/(sk + \rho)} \pmod P$ (或简单的 ZK-friendly 哈希)。

## 5. 网络层与主权同步 (Network & Sovereign Sync)

### 5.1 Sphinx 路由元数据消除
每一层数据包采用固定长度 $L$，并使用嵌套加密。节点 $i$ 仅能解开其对应的剥离层以获取下一跳地址 $i+1$，数学上保证了路径的不可追溯性。

### 5.2 主权同步算法
由于不依赖全局共识，客户端通过 **可验证扫描 (Verifiable Scanning)** 获取与其相关的 Record：
1. **暗池扫描**: 客户端下载包含新 Record 承诺的 VDF 块。
2. **视图密钥验证**: 使用 `view_key` 尝试解密 Record 头部。
3. **证明检索**: 若匹配，客户端向网络请求该 Record 的存在性 ZK 证明。

## 6. 容错界限与安全性定理

### 6.1 日蚀抵抗定理 (Eclipse Resistance Theorems)

Aetheris 的安全性不依赖"诚实多数"假设。以下定理证明即使在完全网络隔离的极端条件下，协议仍提供可量化的数学保证。

**定理 6.1（主权完整性）**：设节点 $V$ 被攻击者完全日蚀，仅接收攻击者提供的链 $C_{adv}$。若 $C_{adv}$ 包含任意非法状态转换（如伪造交易、双花、价值不守恒），则 $V$ 的本地验证必将拒绝 $C_{adv}$。

*证明*：每个区块包含 VDF 证明 $\pi_{vdf}$ 和 ZK 聚合证明 $\Pi_n$。$V$ 独立验证：
1. Wesolowski VDF 验证：$y \stackrel{?}{=} \pi^l \cdot x^{2^T \bmod l}$，此验证纯本地，零外部输入。
2. ZK 聚合证明验证：$\text{Verify}(\Pi_n, \text{State}_n)$，由 Halo2 的可靠性保证。
3. Nullifier 唯一性检查：每个 Nullifier 在本地状态树中唯一。
4. 创世锚定：链的根哈希必须等于本地存储的创世哈希。
上述验证均不依赖网络输入。因此任何非法状态转换都将在至少一项检查中被捕获。$\square$

**定理 6.2（日蚀可检测性）**：设 $V$ 自创世以来已计算 $n$ 个 VDF 迭代（输出序列 $y_0, y_1, ..., y_{n-1}$），但仅收到 $m < n$ 个对应区块。则 $V$ 数学上确定自己被日蚀攻击。

*证明*：VDF 序列是确定性的——给定创世种子 $S$ 和时间参数 $T$，序列 $y_i = f^{(i)}(S)$ 是唯一的。由于区块提议必须包含对应的 VDF 结果 $y_i$（否则 VDF 验证失败），$n > m$ 意味着至少有 $n-m$ 个区块被网络扣留。此结论非概率估计，而是 $n \neq m$ 的布尔推导。$\square$

**定理 6.3（有限损害）**：日蚀攻击者对 $V$ 造成的损害在数学上有上界：
1. 不能窃取 $V$ 的资金：需 $V$ 的 ZK 密钥签署交易。
2. 不能对诚实网络双花：Nullifier 唯一性由全局 ZK 证明强制执行。
3. 不能造成永久分叉：$V$ 重新连接后通过 VDF 重算恢复规范链。
4. 假链维护代价：攻击者每单位时间仅能产生一步 VDF 迭代，受单核 CPU 速度限制，无法并行加速。

**定理 6.4（可恢复性）**：设 $V$ 在时刻 $t_0$ 被日蚀，在时刻 $t_1 > t_0$ 重新获得与诚实网络 $H$ 的连接。则 $V$ 可在无信任假设下确定规范链。

*证明*：$V$ 在日蚀期间持续本地计算 VDF 序列 $y_{n_0}, ..., y_{n_1}$。重新连接后，$V$ 从 $H$ 接收候选链 $C_H$。$V$ 通过以下步骤独立验证 $C_H$：
1. 检查 $C_H$ 的 VDF 证明序列是否匹配本地计算的 $y_{n_0}, ..., y_{n_1}$。
2. 验证每个区块的 ZK 聚合证明和 Nullifier 唯一性。
3. 选择满足条件且 VDF 长度最长的链。
此过程不依赖对 $H$ 的信任——数学正确性由 VDF 和 ZK 证明的确定性保证。$\square$

**定理 6.5（活性下界）**：设攻击者对 $V$ 的日蚀持续时间为 $\Delta t$。$V$ 在 $\Delta t$ 期间无法向诚实网络提交交易。此延迟是信息论必然——节点无法知道其未接收到的数据。但 $V$ 在此期间的资金安全性和状态完整性由定理 6.1 保证，且 $\Delta t$ 结束后 $V$ 可通过定理 6.4 恢复。

### 6.2 信息论边界

日蚀攻击的最优策略是垄断目标节点的所有网络路径。此攻击的信息论代价受限于以下因素：
- **网络多样性**：每个诚实对等节点提供一条独立路径。使 $V$ 连接 $k$ 个诚实节点需要攻击者控制 $k$ 条独立路径。
- **覆盖流量**：即使 $V$ 无交易，恒定速率覆盖流量使攻击者无法通过流量模式判断何时切断连接。
- **VDF 时间锚**：$V$ 的本地 VDF 计算提供独立于网络的时间参考，使攻击者无法伪造时间线。

### 6.3 与非理性攻击者的关系

Aetheris 不假设攻击者追求经济利益最大化。定理 6.1-6.5 的证明仅依赖密码学假设（VDF 的序贯性、ZK 证明的可靠性、哈希函数的抗碰撞性），不涉及经济理性假设。

---

## 7. 集体递归证明与流式聚合 (Gossip-Aggregation)

为了实现原子化的平等并消除算力门槛，Aetheris 采用基于 **Halo2 Accumulation Scheme** 的集体递归证明方案。

### 7.1 原子证明 (Atomic Proof)
每一笔交易 $tx_i$ 必须附带一个本地生成的证明 $\pi_i$：
$$\pi_i = \text{Halo2.Prove}(\text{Circuit}_{tx}, \text{Witness}_i, \text{PublicInputs}_i)$$
其中 $\text{Circuit}_{tx}$ 验证资产平衡、签名及 Nullifier 的合法性。

### 7.2 流式聚合函数 (Aggregation Function)
当节点收到两个证明 $\pi_a$ 和 $\pi_b$ 时，执行聚合操作 $\Phi$：
$$\pi_{a+b} = \Phi(\pi_a, \pi_b, \text{Acc}_n)$$
- **Accumulation Scheme**: 采用基于 IPA (Inner Product Argument) 的累积器，使得合并两个证明的开销 $O(\log N)$ 远小于生成证明。
- **结合律保证**: $\Phi(\pi_1, \Phi(\pi_2, \pi_3)) \equiv \Phi(\Phi(\pi_1, \pi_2), \pi_3)$。这确保了全网节点以任意顺序传播和聚合证明，最终结果在数学上是等价的。

### 7.3 区块递归链 (Recursive Chaining)
区块 $B_n$ 的完整性证明 $\Pi_n$ 定义为：
$$\Pi_n = \text{Halo2.Prove}(\text{Circuit}_{block}, \{\Pi_{n-1}, \pi_{\text{aggregated\_txs}}\})$$
- **基础步 (Base Case)**: $\Pi_0$ 为创世块证明。
- **归纳步 (Inductive Step)**: 每一个新区块都通过电路内验证（In-circuit Verification）嵌套了前一个区块的证明 $\Pi_{n-1}$。

## 8. 形式化安全性定义

### 8.1 归纳完备性 (Inductive Soundness)
若 $\text{Verify}(\Pi_n, \text{State}_n) = \text{True}$，则存在一个合法的状态转换序列，使得从 $\text{State}_0$ 经过 $n$ 个区块达到 $\text{State}_n$，且所有交易均满足 $\mathcal{P}_{contract}$。

### 8.2 算力门槛消除定理 (Anti-Monopoly Theorem)
定义生成原子证明的算力成本为 $E_{at}$，聚合成本为 $E_{agg}$，产块成本为 $E_{blk}$。
Aetheris 确保：
1. $E_{at} < \text{Consumer\_Hardware\_Bound}$ (手机级算力即可)。
2. $E_{agg} \approx O(\log (\text{Txs}))$。
3. 通过流式聚合，封块节点的实时计算压力 $E_{blk} \approx E_{agg}$，从而消除高性能矿机的垄断优势。
