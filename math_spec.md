# Aetheris (AET) 数学规格说明书

本文件详细说明 Aetheris 协议的核心数学构造，旨在实现无需可信设置的极致隐私与安全性。

## 1. 可验证延迟函数 (VDF)

为了实现公平的时间发行，Aetheris 采用 **Wesolowski VDF**，运行在 **虚二次域类群 (Class Groups of Imaginary Quadratic Fields)** 上。

### 1.1 类群选择
选择类群而非 RSA 群是为了消除 **可信设置 (Trusted Setup)**。
- **判别式 (Discriminant)**: $\Delta = -D$，其中 $D$ 是一个由创世哈希派生的巨大质数。
- **群元素**: 由形式为 $(a, b, c)$ 的二元二次型 $ax^2 + bxy + cy^2$ 表示。

### 1.2 计算逻辑
- **输入**: $x \in G, T$ (时间参数)。
- **输出**: $y = x^{2^T}$。
- **证明 $\pi$**: 为了证明 $y$ 的正确性，证明者计算 $\pi = x^{\lfloor 2^T / l \rfloor}$，其中 $l = Hash(x, y)$ 是一个大质数。
- **验证**: 校验 $y = \pi^l \cdot x^{2^T \pmod l}$ 是否成立。

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

---

## 6. 发行函数 (Issuance Function)

第 $n$ 次发行的奖励 $R_n$ 计算如下：
$$R_n = R_{initial} \cdot (1 - \lambda)^{n \cdot \text{epoch}}$$
其中 $\lambda$ 是衰减系数，所有参数均锚定在创世交易中。
