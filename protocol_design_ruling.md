# Aetheris 协议设计终裁

> 本文件综合 `whitepaper.md`、`math_spec.md`、`formal_verification.md`、`README.md`、`implementation_roadmap.md` 五份规格文档，
> 消除所有内部矛盾，划定核心协议边界 vs 未来愿景，形成一份无冲突、自洽的最终协议设计。

**日期**: 2026-06-02
**状态**: 定稿

---

## 1. 核心架构决策

### 1.1 曲线体系：Pasta 曲线对 (Pallas + Vesta)

| 维度 | 决策 | 理由 |
|------|------|------|
| 曲线 | **Pallas** ($y^2 = x^3 + 5$) + **Vesta** ($y^2 = x^3 + 5$) | 完美 2-cycle，原生支持 Halo2 递归积累 |
| 外电路 | Pallas（交易值守恒电路） | 标量场 = Vesta 基场 |
| 递归电路 | Vesta（递归积累电路） | 标量场 = Pallas 基场 |
| 曲线方程 | $y^2 = x^3 + 5$（统一） | Zcash Orchard 标准，代码与文档一致 |

**裁决依据**：
- `math_spec §3.1` 明确指定 Pasta 曲线对。BN254/Grumpkin 是实现偏差，不是设计意图。
- Pasta 的场对 $(F_p, F_q)$ 满足 $p = q_{inner}$ 且 $q = p_{inner}$，使递归电路在原生域上运行，**完全消除 NonNativeChip 需求**。
- 当前 `aetheris-recursive` 中 ~2500 行的 NonNativeChip + EccChip 可被 <500 行的原生递归积累电路替代。

**迁移路径**：Phase 1 中完成 aetheris-zkp + aetheris-recursive 从 BN254 → Pasta 迁移。

---

### 1.2 递归证明：Halo2 IPA 积累方案（非 Merkle 哈希）

| 维度 | 决策 | 理由 |
|------|------|------|
| 聚合方式 | **Halo2 Accumulation Scheme (IPA-based)** | `math_spec §7.2` 原始设计 |
| 区块链 | **区块内递归**: $\Pi_n = \text{Prove}(\text{Circuit}_{block}, \{\Pi_{n-1}, \pi_{txs}\})$ | `math_spec §7.3` 递归链 |
| 非选用 | Merkle 哈希链（当前实现） | 不提供压缩收益，不满足 §7.3 的归纳完备性 |

**裁决依据**：
- `math_spec §7` 的积累方案 + 递归链在数学上是自洽的，且与 Halo2 的设计目标一致。
- 当前 `aggregate_proofs` 的 Merkle 哈希方案是过渡实现，不可作为最终协议。
- IPA 积累器提供 $O(\log N)$ 合并和 $O(1)$ 验证，是 §8 中"算力门槛消除"的前提。

---

### 1.3 核心协议 vs 未来愿景边界

| 组件 | 裁决 | 文档来源 | 纳入理由 / 排除理由 |
|------|------|----------|---------------------|
| 类群 VDF Cl(D), \|D\|=2048 | **核心** | math_spec §1 | 数学正确，已实现，零信任假设 |
| 难度自平衡 (M=4, N=10, T=10s) | **核心** | math_spec §1.3 | 与 VDF 一体，§4.2 密码学自强制执行 |
| Pasta 曲线对 | **核心** | math_spec §3.1 | §7 递归积累的前提，消除 NonNativeChip |
| 屏蔽交易电路 (Halo2) | **核心** | math_spec §4.5, whitepaper §3.1 | 隐私基础 |
| Record 模型 + Poseidon 状态树 | **核心** | math_spec §2 | 交易语义唯一载体 |
| Nullifier (Poseidon 唯一性) | **核心** | math_spec §4 | 防双花，主权验证前提 |
| 递归积累 (Halo2 IPA) | **核心** | math_spec §7.2 | 区块链缩，§8 算力门槛消除 |
| 区块递归链 | **核心** | math_spec §7.3 | 归纳完备性 |
| 数学仲裁 (min_by_key) | **核心** | whitepaper §4 | 无 BFT/PoS/PoW 的共识 |
| 主权验证 + 日蚀抵抗定理 | **核心** | whitepaper §2, math_spec §6 | 整体设计哲学 |
| **ZK-VM (RISC-V) + 智能合约** | **降级 → future** | math_spec §3.2, whitepaper §3.2 | 小团队不可并行实现；不会使核心协议不安全 |
| **FHE 全同态加密** | **降级 → future** | whitepaper §3.2 | 研究前沿，非主网必需 |
| **后量子格密码** | **降级 → future** | whitepaper §6.2 | 与当前 Pasta/ZK 体系不直接兼容 |
| **形式化验证 Coq/TLA+/Lean** | **降级 → future** | formal_verification.md | Phase E 已正确规划为 2-3 月后；当前不构成协议安全依赖 |

**裁决原则**：
1. **优先级**：核心协议必须能在 Mainnet MVP 之前独立完成并安全运行。
2. **正交性**：被降级的组件与核心协议解耦——即使不存在，协议安全模型不崩溃。
3. **一致性**：被降级组件的移除不应在文档中留下伪影（不虚假声称已实现）。

---

## 2. 协议架构

### 2.1 依赖图（无环）

```
┌────────────────────────────────────────────────────────────┐
│  第零层: VDF 时间链                                        │
│  ┌─────────────────────────────────────────────────┐       │
│  │ 类群 Cl(D) → 合成/规约 → Wesolowski 证明        │       │
│  │ → 难度自平衡 (M=4, T_target=10s)               │       │
│  └─────────────────────────────────────────────────┘       │
│                           │                                  │
│                           ▼                                  │
│  第一层: Pasta 曲线对                                      │
│  ┌─────────────────────────────────────────────────┐       │
│  │ Pallas (外电路) ←──→ Vesta (递归电路)            │       │
│  │ 场: Fp, Fq 完美 2-cycle                          │       │
│  └─────────────────────────────────────────────────┘       │
│                           │                                  │
└───────────────────────────┼──────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────────┐
│  第二层: 屏蔽交易 + Record 状态树                          │
│  ┌─────────────────────────────────────────────────┐       │
│  │ Record → Poseidon → Commitment → Merkle Tree     │       │
│  │ Nullifier = Poseidon(sk, record_id)             │       │
│  │ Circuit: value_conservation + membership +       │       │
│  │          nullifier_correctness + range_check     │       │
│  └─────────────────────────────────────────────────┘       │
│                           │                                  │
│                           ▼                                  │
│  第三层: 递归积累 (Halo2 IPA)                              │
│  ┌─────────────────────────────────────────────────┐       │
│  │ π_{a+b} = Φ(π_a, π_b, Acc_n)                   │       │
│  │ Π_n = Prove(Circuit, {Π_{n-1}, π_txs})         │       │
│  │ 验证: O(1), 合并: O(log N)                     │       │
│  └─────────────────────────────────────────────────┘       │
│                           │                                  │
│                           ▼                                  │
│  第四层: 数学仲裁 + 主权验证                                │
│  ┌─────────────────────────────────────────────────┐       │
│  │ winner = min_by_key(Π_n, key = blake3)          │       │
│  │ 日蚀抵抗: 完整性/检测性/恢复性/有限损害          │       │
│  └─────────────────────────────────────────────────┘       │
└────────────────────────────────────────────────────────────┘
```

### 2.2 各层内部约束

#### 第零层：VDF 时间链

| 参数 | 值 | 来源 |
|------|-----|------|
| 群 | Cl(D), 虚二次域类群 | math_spec §1.1 |
| \|D\| | 2048 bit | math_spec §1.6 |
| D 形式 | D ≡ 1 (mod 4), 基本判别式 | math_spec §1.1.1 |
| 哈希到形式 | blake3 + k-search | math_spec §1.1.4 |
| VDF 协议 | Wesolowski | math_spec §1.2 |
| 证明 | $\pi = x^{\lfloor 2^T / l \rfloor}$, $l = \text{HashToPrime}(x, y)$ | math_spec §1.2 |
| 验证 | $y \stackrel{?}{=} \pi^l \cdot x^{2^T \bmod l}$ | math_spec §1.2 |
| 难度重定向 | $T_{n+1} = clamp(T_n \times T_{target} \times N / \Delta t, T_n/M, T_n \times M)$ | math_spec §1.3 |
| M | 4 | math_spec §1.4 |
| N | 10 | math_spec §1.4 |
| $T_{target}$ | 10 秒 | math_spec §1.4 |
| $T_{genesis}$ | 主网上线前硬件实测校准 | math_spec §1.4 |

#### 第一层：Pasta 曲线对

| 曲线 | 外电路 (Pallas) | 递归电路 (Vesta) |
|------|-----------------|-------------------|
| 曲线方程 | $y^2 = x^3 + 5$ | $y^2 = x^3 + 5$ |
| 基场 | $\mathbb{F}_p$ | $\mathbb{F}_q$ |
| 标量场 | $\mathbb{F}_q$ ( = Vesta 基场) | $\mathbb{F}_p$ ( = Pallas 基场) |
| 对标量场大小 | ~254 bit | ~254 bit |

#### 第二层：屏蔽交易电路

```
Circuit_inputs:
  - input_records: 最多 MAX_INPUTS 个 Record (金额 + 盲化 + record_id)
  - output_records: 最多 MAX_OUTPUTS 个 Record
  - public_amount: i64 (coinbase 正 / consume 负 / 普通 0)

Circuit_constraints:
  1. amount ∈ [0, 2^64)                         ← range proof (running-sum)
  2. sum(input_amounts) + public_in = sum(output_amounts) + public_out  ← conservation
  3. output_commitment_i == amount_i·G + blinding_i·H  ← instance binding (C-1)
  4. ∀i: input_commitment_i ∈ MerkleTree(state) ← membership proof (C-2)
  5. ∀i: nullifier_i == Poseidon(sk_i, record_id_i) ← nullifier correctness (C-2)
  6. ∀i: signature_verify(pk_i, tx_data, sig_i)  ← ownership (MOCK-01 待实现)

Public instances:
  [0] = running_sum_final (≡ public_amount in Fr)
  [1..1+MAX_OUTPUTS] = output_commitments (as Fr)
  [1+MAX_OUTPUTS..1+MAX_OUTPUTS+MAX_INPUTS] = merkle_roots (membership proof)
  [1+MAX_OUTPUTS+MAX_INPUTS..] = range_z_final (zeros)
```

##### Merkle 路径验证实现（C-2 最终设计）

**不可使用 `constrain_equal` 做 position_bits 分支选择**：keygen 哑电路与实际电路走不同分支时产生不同的置换等价类，导致 IPA 真实证明验证失败 (`ConstraintSystemFailure`)。

**改为 Gate 输入选择**：每层用 gate 约束选通输入位置，`assign_hash` 永远不传 `first_cell`/`second_cell`（即 `constrain_equal` 零次分支）：

```
Gate mux_inputs (degree 3):
  s_select * (first_input  - (1-bit)·current_val  - bit·sibling_val) = 0
  s_select * (second_input - bit·current_val  - (1-bit)·sibling_val) = 0

其中:
  first_input  = Poseidon state[0] 第一行（assign_hash 的 left 位置）
  second_input = Poseidon state[1] 第一行（assign_hash 的 right 位置）
  bit          = position_bits[i] ∈ {0,1}（由现有 bool_check gate 约束）
```

**效果**：
- 置换标签与 position_bits 完全无关 → depth 缓存 VK/PK 对所有 position 有效
- `assign_hash` 调用不加 `constrain_equal` → 所有 `constrain_equal` 调用固定不变
- 约束 degree 保持 3，与现有 Poseidon 门一致

#### 第三层：递归积累

```
Accumulator:
  Acc = (Q, transcript_state)
  初始化: Q = identity (point at infinity)

Accumulate(π, Acc_old) → Acc_new:
  1. 验证 π 对当前公开输入的可靠性（Halo2 verify）
  2. challenge = Poseidon(transcript_state, π)
  3. Q_new = Q_old + challenge · π_commitment
  4. transcript_state = Poseidon(transcript_state, challenge)

区块递归链 Π_n:
  Π_n = Prove(Circuit_accumulate, {Π_{n-1}, π_aggregated_txs})
  其中 Circuit_accumulate 包含:
    - 加载 Π_{n-1} 的积累点
    - 验证 Π_{n-1} 的公开输入与当前区块头的匹配性
    - 执行 Accumulate(π_txs, Acc_prev) 得到 Acc_new
    - 约束 Acc_new 与 Π_n 的公开输入一致
```

#### 第四层：数学仲裁

```
for each proposal P:
  verify(VDF_proof(P))        ← 第零层
  verify(aggregate_proof(P))  ← 第三层
  check(nullifier_uniqueness(P))  ← 第二层
  check(issuance_rules(P))    ← 共识规则

winner = min_by_key(valid_proposals, key = blake3(prev_block_hash || Π_n.nullifier_root))
```

---

## 3. 文档修正建议

### 3.1 须修改的部分

| 文档 | 位置 | 当前内容 | 修正为 |
|------|------|----------|--------|
| math_spec.md | §3.1 | 曲线选择描述 | 保持 Pasta，但明确与代码偏差待修复 |
| math_spec.md | §3.2 | ZK-VM 作为核心特性 | **降级**: 标记为"未来扩展"，添加脚注"当前 MVP 不包含" |
| math_spec.md | §4 | 智能合约谓词 P_contract | 同理降级，核心协议只保留 §4.5 (价值守恒) |
| whitepaper.md | §3.2 | FHE + ZK-VM 作为 §3 主体 | **降级**: 移至新的"未来扩展"章节或脚注 |
| whitepaper.md | §6.2 | 后量子格密码 | **降级**: 标记为"长期目标"，移除"采用"字样 |
| whitepaper.md | §7 | 结论中的范围表述 | 限定为当前核心协议 + 注明未来扩展 |
| formal_verification.md | 全文 | 以当前进行时描述 | 标记为 Phase E 规划，非已完成 |
| README.md | L19 | "递归证明聚合（Halo2 IPA + 非原生算术）" | 移除"非原生算术"，改为"递归证明聚合（Halo2 IPA 积累方案）" |

### 3.2 保留不变的

| 文档 | 部分 | 理由 |
|------|------|------|
| math_spec.md §1 | VDF + 类群 | 完全正确，与代码一致 |
| math_spec.md §2 | Record 模型 | 需与 Pasta/Poseidon 整合，但概念正确 |
| math_spec.md §6 | 日蚀抵抗定理 | 定理逻辑成立，前提需 C-2 等修复 |
| math_spec.md §7 | 递归积累 + 区块链 | 正确设计，需从 Merkle 哈希迁移到真实积累方案 |
| whitepaper.md §2 | 三公理 | 设计哲学不变 |
| whitepaper.md §4 | PoT + 数学仲裁 | 共识模型不变 |
| implementation_roadmap.md | 剩余 Phase 规划 | 与终裁一致，仅需更新 B-1 (曲线迁移) |

---

## 4. 实现优先级（基于本终裁的重排）

```
P0 — 协议完整性（不修则协议不安全）
  ├─ A-1: 修复 running-sum 跨 range 行约束 (aetheris-zkp running_sum unconstrained)
  ├─ C-2: Input membership + nullifier correctness proof
  ├─ C-5: Block 写入前检查 nullifier (write-ahead→validate-ahead)
  ├─ H-1: state_root 验证 (apply 后校验 block.header.state_root == self.get_state_root())
  └─ A-3: 统一 viewing key 派生 (blake3)

P1 — 曲线迁移 + 递归积累（架构升级）
  ├─ B-1: Pasta 曲线迁移 (aetheris-zkp + aetheris-recursive)
  ├─ B-2: 重构 aetheris-recursive: 移除 NonNativeChip, 实现原生 Halo2 IPA 积累
  └─ B-3: 替换 aggregate_proofs 从 Merkle 哈希到 IPA 积累方案

P2 — 交易/区块完整性
  ├─ H-2: MEMPOOL 类型修复 (WalletTransaction → core::Transaction)
  ├─ L-1: Transaction 类型清理 (拆分或统一)
  ├─ M-1: P2P 入站预验证 (proof + nullifier uniqueness)
  ├─ M-3: Recipient viewing key 修复 (DH-based stealth address)
  ├─ A-7: 钱包加密 (b"AETHSCAN" 占位 → 真实 AES-GCM)
  └─ A-8: 发送/扫描 P2P 集成 (当前都是本地文件操作)

P3 — 网络健壮性
  ├─ C-1: Peer scoring + spam 保护
  ├─ C-2: Gossip 规范对齐
  ├─ C-3: Bootstrap 节点
  └─ C-4: NAT 穿越

P4 — 生产就绪
  ├─ C-6: Arbitration tie-breaker
  ├─ M-2: FFI 文档
  ├─ B-3: sled DB 批量写入
  └─ Phase F: 部署/监控/文档

Future — 不阻塞主网
  ├─ ZK-VM / RISC-V 智能合约 (math_spec §3.2 → 移出核心协议)
  ├─ FHE 全同态加密 (whitepaper §3.2 → 移出核心协议)
  ├─ 后量子格密码 (whitepaper §6.2 → 移出核心协议)
  └─ 形式化验证 Coq/TLA+/Lean (formal_verification.md → Phase E)
```

---



## 5. ZK 后端抽象层设计

### 5.1 动机

核心协议 V1 使用 Halo2 (Pasta 曲线) 作为 ZK 证明后端。为保留未来替换为后量子 ZK 系统的能力（如 STARKs + 格承诺），V1 设计时必须在 `aetheris-zkp` 中插入抽象层，使证明后端成为可替换组件。

### 5.2 抽象接口

```rust
/// ZK 证明后端的统一接口。
/// V1 实现: Halo2 (Pasta)
/// V2+ 可能: STARKs, Lattice-based ZK, 等
pub trait ZkProverSystem {
    /// 全局设置（CRS / 公共参考串）
    type Params;
    /// 证明密钥
    type ProvingKey;
    /// 验证密钥
    type VerifyingKey;

    /// 初始化全局参数（CRS 载入/生成）
    fn ensure_params() -> &'static Self::Params;

    /// 生成证明密钥和验证密钥
    fn ensure_keys() -> (&'static Self::VerifyingKey, &'static Self::ProvingKey);

    /// 值守恒证明（V1 必须）
    fn prove_conservation(
        in_amounts: &[u64],
        out_amounts: &[u64],
        in_blindings: &[[u8; 32]],
        out_blindings: &[[u8; 32]],
        commitments: &[[u8; 32]],
        public_amount: i64,
    ) -> Vec<u8>;

    /// 值守恒验证（V1 必须）
    fn verify_conservation(
        proof: &[u8],
        commitments: &[[u8; 32]],
        public_amount: i64,
    ) -> bool;

    /// 递归积累（V1 为 Halo2 IPA，V2 替换）
    fn aggregate_proofs(
        last_aggregate: &[u8],
        tx_proofs: &[Vec<u8>],
        tx_commitments: &[Vec<[u8; 32]>],
        public_amounts: &[i64],
        height: u64,
        state_root: &[u8; 32],
    ) -> Vec<u8>;

    fn verify_aggregate(
        aggregate: &[u8],
        last_aggregate: &[u8],
        tx_proofs: &[Vec<u8>],
        tx_commitments: &[Vec<[u8; 32]>],
        public_amounts: &[i64],
        height: u64,
        state_root: &[u8; 32],
    ) -> bool;
}
```

### 5.3 依赖关系

```
aetheris-zkp:
  src/
    trait.rs          ← ZkProverSystem trait（纯接口定义，零依赖）
    halo2.rs          ← Halo2 (Pasta) 实现
    lib.rs            ← 当前命名空间重导出 (use Halo2Backend as ZKProofSystem)
```

**过渡策略**：
- V1 编译期：`ZKProofSystem = Halo2Backend`（`lib.rs` 一行重命名）
- V2 迁移：新增 `stark.rs` 或 `lattice.rs`，切换 `lib.rs` 的 `use` 行
- 所有业务代码（state.rs, main.rs, ffi/lib.rs, wallet/*）**只引用 `ZKProofSystem` 和 `create_commitment`**，不直接引用 halo2 类型

### 5.4 不需要抽象的

| 组件 | 原因 |
|------|------|
| `create_commitment` | 这是一个**函数**而非系统——本质是 `Fr::from(amount) + Fr::from(blinding)`，与后端无关 |
| `build_merkle_root` | 纯 blake3 哈希，与 ZK 后端无关 |
| `ensure_params` / `ensure_keys` | 归入 trait 接口内部 |
| 加密：`encrypt_note` / `trial_decrypt` | 非 ZK（AES-GCM 密钥封装，与证明系统解耦） |

### 5.5 影响范围

- `aetheris-zkp/src/lib.rs`：重构为 trait + 实现分离（~200 行变动）
- `aetheris-node/src/state.rs`：无变动（已通过 `aetheris_zkp::ZKProofSystem` 引用）
- `aetheris-ffi/src/lib.rs`：无变动（已通过 `aetheris_zkp::ZKProofSystem` 引用）
- `aetheris-wallet/`：无变动
- `aetheris-recursive/src/lib.rs`：重构为纯原生 Pasta 递归（不再通过 FFI-like 接口与外层通）

---



## 6. 裁决变更记录

| 日期 | 变更 | 原因 |
|------|------|------|
| 2026-06-02 | 初始定稿 | 综合 5 份规格文档 + 5-agent 审计，消除曲线/递归/范围三处矛盾 |

---

**本终裁取代所有先前文档中与之矛盾的陈述。所有实现工作应以本文件为最终依据。**
