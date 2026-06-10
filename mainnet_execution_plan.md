# Aetheris Mainnet 执行方案

> 合并 Stage 27 全代码库审计（86 项发现）+ `protocol_design_ruling.md` 架构决策 + ZK 后端抽象层，
> 形成可逐 commit 落地的执行计划。
>
> **核心原则**:
> 1. Phase 0 不碰 ZK 电路代码（避免在 BN254 上修废弃代码）
> 2. Phase 1 一次性完成 Pasta 迁移 + 所有 ZK 修复（不重复劳动）
> 3. 不声称未实现的功能；每步有明确验证标准
> 4. **P0 安全修复优先于任何架构升级**（终裁 §4）

---

## 总览

```
P0       协议安全    ─→  堵 soundness hole（当前执行）
Phase 0  Node 救命   ─→  链终于能跑
Phase 1  ZK 重写     ─→  Pasta + 真实 IPA + 所有电路修复（一次性）
Phase 2  钱包+隐私   ─→  真正的隐私
Phase 3  网络健壮    ─→  多节点
Phase 4  生产就绪    ─→  文档/清理
```

**当前阶段** = P0 协议安全修复
**MVP 门槛** = P0 + Phase 0 + Phase 1

---

---

## P0 — 协议安全修复（当前执行，所有 Phase 暂停）

> 终裁 §4 定义 P0 为"不修则协议不安全"。以下 5 项必须在 Phase 1 继续前完成。
> B-2（原生 IPA 积累电路）已完成作为架构前提，P0 修复与之正交。
> 严格按 小→中→大 顺序执行，每项有独立测试验证。

### P0.1 🔴 A-1: running_sum z_64 = 0 约束（小型）

| 维度 | 值 |
|------|-----|
| **文件** | `aetheris-zkp/src/halo2_pasta.rs:198-269` |
| **问题** | `ValueConservationCircuit` 的 64 位 range 分解未强制 `z_64 = 0`。证明者可编码任意大金额（`amount > 2^64`），完全破坏 range check。 |
| **修复** | 在 range 循环后新增一行，用 `s_running_sum` 门约束 `z_64 = 0`。或在 `synthesize` 末尾添加新 gate `s_running_sum_final * z_prev = 0`。 |
| **测试** | `test_range_rejects_overflow_amount` — 用 `amount = u64::MAX + 1` 验证 mock prover 拒绝。 |
| **估算** | ~30 行，半天 |

### P0.2 🟡 H-1: state_root 负测试（小型）

| 维度 | 值 |
|------|-----|
| **文件** | `aetheris-node/src/state.rs:373-380` |
| **问题** | 检查逻辑正确，但无负测试——没有测试验证**错误** state_root 会被拒绝。 |
| **修复** | 在 `state.rs` 测试中新增 `test_state_root_mismatch_rejected`：手动篡改 `block.header.state_root` 后调用 `apply_block`，验证返回 `Err`。 |
| **估算** | ~20 行，半天 |

### P0.3 🟡 C-5: nullifier 双花端到端测试（小型）

| 维度 | 值 |
|------|-----|
| **文件** | `aetheris-node/src/state.rs:364-371` |
| **问题** | Nullifier 重复检查逻辑正确，但现有 `test_double_spend_rejected` 绕过 VDF/ZK 验证。 |
| **修复** | 在 `test_double_spend_rejected` 中直接测试 nullifier 集合语义（跳过 VDF/ZK 预检），或构造两个具有相同 nullifier 的区块做端到端测试。 |
| **估算** | ~30 行，半天 |

### P0.4 🟠 A-3: 统一 viewing key 派生（中大型）

| 维度 | 值 |
|------|-----|
| **文件** | `aetheris-ffi/src/lib.rs:1190-1193, 1475-1476, 2109-2110, 2185-2188` |
| **问题** | 3 个子问题：(1) 目标查看密钥从**公开地址**派生（`lib.rs:2185-2188`），完全破坏隐私；(2) nullifier 索引使用 Keccak 而非 blake3（`lib.rs:1506-1510, 2124-2128`）；(3) 缺失 DH 共享密钥建立。 |
| **修复** | **分 3 阶段**：(a) 引入 DH 共享密钥（Curve25519 或类似）用于目标查看密钥派生；(b) 用 blake3 + 域分离替换 Keccak；(c) 统一所有查看密钥派生路径，添加 HKDF 包装。 |
| **测试** | `test_viewing_key_unified` — 同一助记词在所有路径产出相同 vk；`test_target_viewing_key_privacy` — 仅拥有地址的人不能派生目标 vk。 |
| **估算** | ~200 行，2-3 天 |

### P0.5 🔴 C-2: Input membership + nullifier 证明（大型）

| 维度 | 值 |
|------|-----|
| **文件** | `aetheris-zkp/src/membership_circuit.rs`、`aetheris-zkp/src/halo2_pasta.rs` |
| **问题** | 电路中完全没有：(a) Merkle 路径验证（验证 input 存在于承诺树）；(b) Nullifier 派生约束（blake3(sk, record_id)）；(c) 花费密钥与 note 所有权的关联。 |
| **修复** | 在 `Circuit<Fq>` 中新增：(a) Poseidon Merkle 路径验证门；(b) Nullifier 派生约束门；(c) 实例绑定到 public input。 |
| **IPA 回环发现** | 原实现用 `constrain_equal` 做 position_bits 分支选择，导致 IPA 真实证明失败：keygen 哑电路走全 `false` 分支，实际电路走混合分支，两者产生**不同的置换等价类**，验证返回 `ConstraintSystemFailure`。 |
| **根因修复** | 改为 **Gate 输入选择**：每层新增 `mux_inputs` gate 约束 `first_input = (1-bit)*current + bit*sibling` / `second_input = bit*current + (1-bit)*sibling`，`assign_hash` 不再传 `first_cell`/`second_cell`（即不再有 branch-dependent `constrain_equal`）。详见 `protocol_design_ruling.md §2.2` 更新。 |
| **测试** | `test_membership_proof_rejects_fake_input`、`test_nullifier_correctness_mismatch_rejected`；IPA roundtrip: `test_membership_direct_ipa`、`test_exact_membership_structure_ipa` |
| **状态** | ⏳ 实现中——电路 mock prover 已通过，IPA 回环已修复，待接入 `ValueConservationCircuit` |

> **P0 完成标准**: 以下全部通过 ——
> - `cargo test -p aetheris-zkp` 新增测试全部通过（A-1 堵住 + C-2 电路约束活跃）
> - `cargo test -p aetheris-node` 新增测试全部通过（C-5 双花拒绝 + H-1 state_root 拒绝）
> - `cargo test -p aetheris-ffi -- --test-threads=1` 全部通过（A-3 统一 vk 派生）
> - `cargo check --workspace` 零错误零警告

---

## Phase 0 — Node 救命（不碰 ZK 电路代码）

> 这些修复在 `aetheris-node`、`aetheris-core`、`aetheris-ffi`、`aetheris-wallet` 层。
> ZK 电路代码（`aetheris-zkp`、`aetheris-recursive`）一行不动——Phase 1 会被整个换掉。

### 0.1 修复区块哈希断裂
- **来源**: A-3
- **问题**: 挖矿用 `blake3(parent_hash || vdf_result)`，state 用 `blake3(serialized_block)`，链在第一个块后断裂
- **动作**:
  1. `main.rs:571-573`：挖矿产出 block 后 **不生成 hash**，直接序列化
  2. `state.rs:361`：统一用 `blake3(serialized_block)` 作为 block hash
  3. 去掉 `main.rs` 中"手动构造 block hash 的逻辑"——只用 `blake3(serialized_block)`
- **文件**: `aetheris-node/src/main.rs`、`aetheris-node/src/state.rs`
- **验证**: 挖 2 个块，`block.hash == blake3(&serialized)`；链不断裂
- **依赖**: 无

### 0.2 修复 MEMPOOL 类型污染
- **来源**: A-8
- **问题**: MEMPOOL 存 `Vec<WalletTransaction>`，P2P 丢弃 nullifiers/outputs，挖矿重建空 inputs/outputs
- **动作**:
  1. MEMPOOL 改为 `Vec<Transaction>`
  2. P2P 入站解析完整 `Transaction`（含 inputs/nullifiers/outputs）
  3. 挖矿从 MEMPOOL 取 `Transaction` 直接组装
- **文件**: `aetheris-ffi/src/lib.rs`、`aetheris-node/src/main.rs`
- **验证**: P2P 接收→MEMPOOL→挖矿→区块内 tx 数据完整
- **依赖**: 需要先确认 `core::Transaction` 结构（见 0.4）

### 0.3 Block 写入前校验+state_root 验证
- **来源**: C-5, H-1
- **问题**: apply 前不检查；apply 后不验证 state_root
- **动作**: `apply_block` 前检 nullifier 唯一性 + inputs 存在；末尾校验 `state_root`
- **文件**: `aetheris-node/src/state.rs`
- **验证**: 双花 tx 返回 Err；state_root 不匹配拒绝
- **依赖**: 无

### 0.4 Transaction 类型统一
- **来源**: L-1, A-8
- **动作**: `aetheris-core/src/lib.rs` 定义 `struct Transaction { inputs, outputs, proof, public_amount }`；全线统一；消除 `WalletTransaction`
- **文件**: `aetheris-core/src/lib.rs`、`aetheris-ffi/src/lib.rs`、`aetheris-node/src/main.rs`
- **验证**: 编译通过；发送/接收 roundtrip
- **依赖**: 无

### 0.5 MEMPOOL 入站预验证
- **来源**: H-2, M-1
- **动作**: 入站验证 proof → nullifier 唯一性 → inputs 存在
- **文件**: `aetheris-node/src/main.rs:25-37`
- **验证**: 无效 tx 不进入 MEMPOOL
- **依赖**: 0.4

### 0.6 统一 viewing key 派生
- **来源**: B-13
- **动作**: 全部改为 `blake3(spending_key || b"aetheris-viewing-key")`
- **文件**: `aetheris-ffi/src/lib.rs:867, 1104, 2003`
- **验证**: 同一 sk 在所有路径产出相同 vk

### 0.7 修复仲裁/交易/网络层边界
- **来源**: B-8, B-9, C-7
- **动作**: 仲裁器比较完整区块 hash，不排除关键字段
- **文件**: `aetheris-node/src/consensus.rs:51, 62-69`

### 0.8 FFI 边界安全 + 弱随机数
- **来源**: B-11, B-12, C-11
- **动作**: ~12 处 `unsafe CStr::from_ptr` 加 `ffi_try!`；`thread_rng()` → `OsRng`；mixnet_sk 加 Zeroize

---

## Phase 1 — ZK 重写（一次性完成 Pasta + 所有电路修复）

> Phase 0 完成前不要开始 Phase 1。
> 以下所有工作只在 Pasta 代码上进行——**不在 BN254 上修任何东西**。
>
> **关键架构决策**: Pasta 曲线不支持 KZG（需要 `Engine` trait），因此 Phase 1.1 必须从零实现 IPA 承诺方案，
> 再在 IPA 之上搭建电路。这是**唯一路径**——不存在"先用 KZG 后换 IPA"的中间态。
> IPA 承诺方案和 IPA 递归积累是两层不同的概念：前者是单层证明的承诺机制（Phase 1.1），
> 后者是跨区块的递归压缩（Phase 1.4）。

### 1.0 ZK 抽象 trait 初始化
- **来源**: protocol_design_ruling.md §5
- **动作**:
   1. `aetheris-zkp/src/trait_.rs` 定义 `ZkProverSystem`
   2. `aetheris-zkp/src/halo2_bn254.rs` 保留 BN254 实现作参考（不编译）
   3. 新建 `aetheris-zkp/src/halo2_pasta.rs` 写 Pasta + IPA 实现
   4. `lib.rs` 重导出 `pub type ZKProofSystem = Halo2PastaBackend;`
- **验证**: `cargo check -p aetheris-zkp`（BN254 不编译，仅检查模块结构）
- **状态**: ✅已完成

### 1.1 实现 IPA 承诺方案底层

> **核心**: 填补 PSE fork 缺失的 IPA commitment scheme。
> 在 `halo2_backend::poly::ipa/` 层级实现（或等效地在 `aetheris-zkp` 内直接实现），
> 实现 `CommitmentScheme`、`Prover`、`Verifier` trait 的 IPA 变体。
> Pasta 曲线 (Ep/EpAffine/Fq) 已实现 `CurveAffine`，无需 `Engine`。

#### 1.1.0 ParamsIPA + MSMAccumulatorIPA + GuardIPA
- **来源**: 新（PSE fork 无现成 IPA）
- **文件**: `aetheris-zkp/src/ipa/commitment.rs`
- **动作**: ✅已完成（commit `7cb6877`）
    1. `ParamsIPA<C: CurveAffine>` struct: `g: Vec<C>`, `h: C`, `u: C`, `k: u32`
    2. 实现 `Params<C>` trait: `k()`, `n()`, `downsize()`, `commit_lagrange()`, `write()`, `read()`
    3. 实现 `ParamsProver<C>` trait: `new(k)`, `commit()`, `get_g()`
    4. 实现 `ParamsVerifier<C>` trait: `empty_msm()`, `COMMIT_INSTANCE`
    5. `MSMIPA<C>` struct, 实现 `MSM<C>` trait
    6. `GuardIPA<C>` struct, 实现 `Guard<CommitmentSchemeIPA<C>>` trait
    7. `CommitmentSchemeIPA<C>` struct, 实现 `CommitmentScheme` trait
    8. 12 个单元测试（`#[cfg(test)]` 在 `commitment.rs` 内）
- **验证**: ✅ 12 个测试通过

#### 1.1.1 CommitmentSchemeIPA + ProverIPA + VerifierIPA
- **来源**: 新
- **文件**: `aetheris-zkp/src/ipa/prover.rs`, `verifier.rs`
- **动作**: ✅已完成（commit `7cb6877`）
    1. `ProverIPA<'params, C>`: IPA multi-open 证明生成，完全 inner product argument 协议
    2. `VerifierIPA<C>`: 从 transcript 读取 proof，重建 MSM 验证方程
    3. 关联类型完整: `Guard = GuardIPA<C>`, `MSMAccumulator = MSMIPA<C>`
- **验证**: ✅ `cargo check --workspace` 零错误

#### 1.1.1a 🔴 SRS Domain Separation Fix (pre-1.1.2)
- **来源**: Systematic audit 1.2
- **动作**:
    1. `derive_point` 加入 `circuit_id` 或上下文 tag: `hash_to_curve("aetheris-ipa-v1|circuit_id")`
    2. 或 `derive_point` 接受 domain 参数，调用者传入混淆上下文
- **文件**: `aetheris-zkp/src/ipa/commitment.rs:32-39`

#### 1.1.1b 🔴 Blind Commitment Fix (pre-1.1.2)
- **来源**: Systematic audit 1.1
- **决策**: **不实现** blind·H — 遵循 halo2 KZG 架构约定，零知识由上层 multi-open 协议（随机多项式承诺）保证。`h` generator 已预留在 `ParamsIPA` 中，未来如需改回只需加一行 `engine.msm(&[blind], &[self.h])`，向前兼容。
- **文件**: `aetheris-zkp/src/ipa/commitment.rs:182-194, 115-127`

#### 1.1.1c 🟡 Transcript Brand Separation (pre-1.1.2)
- **来源**: Systematic audit 1.4
- **动作**: 用不同的 `IpaChallenge` 品牌区分 IPA 点和轮挑战
- **文件**: `prover.rs:14`, `verifier.rs:14`

#### 1.1.2 验证策略（VerificationStrategy）
- **来源**: 新
- **文件**: `aetheris-zkp/src/ipa/strategy.rs`
- **前置**: 1.1.1a (domain fix) + 1.1.1b (blind fix) + 1.1.1c (brand separation)
- **动作**:
    1. `SingleStrategyIPA<C>`: 实现 `VerificationStrategy`，单 proof 验证
       - 直接使用 `ParamsIPA.g()` 避免 O(n) recompute
       - `GuardIPA::use_challenges()` + `msm_accumulator()` 实现
    2. `AccumulatorStrategyIPA<C>`: 实现 `VerificationStrategy`，累加多个 proof
       - 实现 batch verification: `MSM = P + Σ(x⁻¹·L + x·R) + ...`
       - 在 `GuardIPA` 上实现 `use_challenges()` 和 `msm_accumulator()` 方法
    3. 修复审计项 **4.2**: 策略携带 `&ParamsIPA`，避免 verifier O(n) 重新计算 G_i
- **验证**: `SingleStrategyIPA` 在 roundtrip 中返回 `true`

#### 1.1.3 IPA 模块集成 + 基本测试
- **来源**: 新 + 系统审计 1.3, 2.2, 2.3, 3.3
- **文件**: `aetheris-zkp/src/ipa/` 全模块
- **动作**:
    1. IPA roundtrip 测试：`test_ipa_single_proof_roundtrip`, `test_ipa_multi_proof_roundtrip`, `test_ipa_tampered_proof_rejected`
    2. 🔴 修复 **2.2**: `x_inv = x_val.invert()` — 处理 `x=0` 边界（使用 `Option` 而非 `unwrap()`）
    3. 🟡 修复 **2.3**: `k` 编码 — 接受 scalar (32B) 而非 u32 (4B)，因 Transcript API 无原生 u32 支持。相对 proof 大小（2k·32B + 32B）增加~28B 可忽略。若未来需移出 proof bytes，延迟到 Phase 1.4（IPA 递归积累）时通过 `common_scalar` + VerifierIPA 存储 k 实现。
    4. 🟢 修复 **3.3**: verifier 中所有 `unwrap()` 替换为正确 error 传播
    5. 🟡 修复 **2.1**: `commit_lagrange` / `commit` 加 degree 检查 `poly.len() ≤ 2^k`
    6. 🟡 修复 **5.1**: `COMMIT_INSTANCE` 加文档说明或移除
- **验证**: 所有 IPA 基础测试通过（20/20）；`cargo check -p aetheris-zkp` 零警告

### 1.2 Pasta 电路 + Halo2PastaBackend — 接线层（无新 trait 实现）

> **前置**: 1.1（IPA 承诺方案完整实现 PSE fork 全部 trait）
> **关键发现**（2026-06-02 多 agent 调查）:
> - Phase 1.1 已完整实现 **8 个 PSE fork trait**: `Params<C>`, `ParamsProver<C>`, `ParamsVerifier<C>`, `MSM<C>`, `Guard<Scheme>`, `CommitmentScheme`, `Prover<'_, Scheme>`, `Verifier<'_, Scheme>`
> - PSE fork 的 `create_proof`, `keygen_vk`, `keygen_pk`, `verify_proof_multi` 全部通过 `CommitmentSchemeIPA<EpAffine>` + `ProverIPA`/`VerifierIPA` 接受我们的 IPA 类型
> - `H2cEngine` + `msm_best` 支持任意 `CurveAffine`（Pasta 包含），不需 `Engine` trait
> - **Phase 1.2 不需要实现新 trait** — 仅需编写 `halo2_pasta.rs` 接线代码
> - 电路在 `Fq`（Pallas 标量场 = Vesta 基场）上运行

#### 1.2.0 halo2_pasta.rs 接线（核心）
- **文件**: `aetheris-zkp/src/halo2_pasta.rs`
- **动作**:
    1. 导入 IPA 类型: `CommitmentSchemeIPA<EpAffine>`, `ParamsIPA<EpAffine>`, `ProverIPA`, `VerifierIPA`, `SingleStrategyIPA`
    2. 调用 `create_proof::<CommitmentSchemeIPA<EpAffine>, ProverIPA<'_, EpAffine>, ...>` 泛型参数
    3. 调用 `verify_proof_multi::<CommitmentSchemeIPA<EpAffine>, VerifierIPA<EpAffine>, ..., SingleStrategyIPA<'_, EpAffine>>`
    4. `keygen_vk/ pk` 直接接受 `&ParamsIPA<EpAffine>`（`Params<EpAffine>` trait bound 已满足）
    5. 所有 `Fp`（BN254）替换为 `Fq`（Pasta）
    6. 约束逻辑（running_sum, bit_constraint）保持与 BN254 版一致
- **验证**: 编译通过 + ValueConservationCircuit roundtrip proof 验证

#### 1.2.1 Halo2PastaBackend 实现 + 测试套件
- **来源**: 原 1.2.4
- **文件**: `aetheris-zkp/src/halo2_pasta.rs`
- **动作**:
    1. `Halo2PastaBackend` 实现 `ZkProverSystem` trait
    2. `ensure_params()`: 全局缓存 `OnceLock<ParamsIPA<EpAffine>>`
    3. `ensure_keys()`: 全局缓存 `ProvingKey<EpAffine>` + `VerifyingKey<EpAffine>`
    4. `prove_conservation()`: `create_proof::<CommitmentSchemeIPA<EpAffine>, ...>`
    5. `verify_conservation()`: `verify_proof_multi::<..., SingleStrategyIPA>`
    6. `create_commitment()`: `Fq::from(amount) + Fq::from(blinding)` → `Fq::to_bytes()`
    7. `create_nullifier()`: blake3(sk || commitment_index)
    8. `build_merkle_root()`: blake3 Merkle tree
    9. `aggregate_proofs()`: 先用 Merkle 哈希过渡（IPA 积累在 1.4 升级）
    10. 加密: `encrypt_output`, `encrypt_note`, `trial_decrypt`（保留 AES-GCM + x25519）
- **验证**: `cargo test -p aetheris-zkp` 全部测试通过：
  - 值守恒: `test_conservation_basic`, `rejects_wrong_public_amount`, `public_amount_net_zero`, `negative_public_amount`
  - 加密: `test_encrypt_decrypt_roundtrip`, `wrong_key`, `tampered`
  - Aggregate: `multi_tx_roundtrip`, `rejects_tampered`, `with_commitments_binding`
  - 安全性: `proof_tamper_detection`, `commitment_consistency`

#### 1.2.2 lib.rs 导出 + ZKProofSystem 切换
- **来源**: 原 1.2.5
- **文件**: `aetheris-zkp/src/lib.rs`
- **动作**:
    1. `pub type ZKProofSystem = Halo2PastaBackend;`
    2. 导出 `create_commitment`, `create_nullifier`, `build_merkle_root`
    3. `halo2_bn254.rs` 保留但不编译
- **验证**: `cargo check -p aetheris-zkp` 零错误

> 注: 原 1.2.1 (A-1 running-sum 修复)、1.2.2 (C-2 membership + nullifier)、1.2.3 (generator 派生)
> 已在 BN254 版本中实现，Pasta 移植时仅需替换域类型，约束逻辑不变。

### 1.3 清理 aetheris-recursive
- **来源**: B-1
- **动作**:
   1. 删除 `NonNativeChip`（~1500 行，Pasta 2-cycle 不再需要）
   2. 删除 `KzgChip`（~200 行，无意义空操作）
   3. 删除 `AccumulatorChip`（~200 行，线性组合不是 accumulator）
   4. 删除旧的 `RecursiveAggregationCircuit`（~200 行，不是递归 SNARK）
   5. 修复 `EccChip` identity 点 `(0,0)` 不在曲线上 — 加 `is_identity: bool` 字段 + `EcPoint::identity()` ctor + `assert_on_curve` 跳过 selector + arithmetic (add/double/select_bool/fixed_base window) 传播 is_identity + 新 `test_ecc_identity_propagation` 覆盖 7 个 identity-producing 路径
   6. Poseidon 用 Grain LFSR 生成标准参数 — 自写简化版 `aetheris-recursive/src/grain.rs`（无 `bitvec` 依赖,80-bit LFSR 复现 PSE recurrence,自包含自验证,200+ field elements 在 0.02s 内生成）
- **验证**: `cargo check --workspace` 0 errors, `cargo test -p aetheris-recursive --tests` 16/16 pass
- **已记录但不在 1.3 范围**:
   - **ISSUE-1.3.A `grain.rs` `set_bit` footgun** — `set_bit` 用 `|=` (OR) 而非赋值,在 post-rotation writeback 上误用会导致 LFSR 退化到 all-1s。1.3 中已通过用 explicit assignment (`|=` for set, `&= !mask` for clear) 替代,保留 `set_bit` 仅在 `new()` 初始 state (从 0 开始) 和 rotate 计算 (输出新数组) 安全使用。**Phase 1.5+ 应考虑删除 `set_bit` 或改名为 `set_bit_into_zero_state` 让前置条件显式。**
   - **ISSUE-1.3.B on-curve gate 曲率不匹配** — `EccConfig` 配置的 `on_curve_check` gate 硬编码 `y² = x³ + 3` (Grumpkin),但 `chip.generator()` 返回 Vesta 点 (Vesta 曲线 `y² = x³ + 5`)。任何对 Vesta real 点的 `assert_on_curve` 会触发 gate 失败。1.3 不动这个 (属于 1.4 Pasta 迁移范围),但 `test_ecc_identity_propagation` 已显式仅对 identity 调 `assert_on_curve`,对 Vesta real 点只检查 `is_identity` flag。
- **当前 diff**: -802 net LoC in `aetheris-recursive/src/lib.rs` (2380→1578), +152 new `grain.rs`, +90 new test function. 范围 bounded 到 `aetheris-recursive/` only.

### ⏳ 1.4 B-3: aggregate_proofs IPA 化（P1，P0 后执行）
- **来源**: B-3，终裁 §4 P1
- **当前**: `halo2_pasta.rs:460-495` 仍用 Merkle 哈希 + O(n) 逐 proof replay
- **前置**: P0 全部完成
- **动作**:
   1. 用 `AccumulatorStrategyIPA`（已实现，`aetheris-zkp/src/ipa/strategy.rs:109-144`）批量验证所有 tx proof
   2. 用 `aetheris-recursive/src/accumulator.rs::AccumulatorIPA` 作为状态累加器
   3. 输出不再是 Merkle 根，而是 IPA 批量验证 accumulator 状态
   4. `verify_aggregate` 从 O(n) 逐个 verify → O(1) accumulator MSM check
- **验证**: `aggregate_proofs(10 txs)` 在常数时间验证，非 O(n)；端到端 3+ 层积累链通过

### ⏳ 1.5 集成 IPA 到区块生产（依赖 1.4）
- **来源**: B-3
- **前置**: 1.4
- **动作**: 替换区块生产中的 Merkle 哈希 aggregate 为 IPA accumulator
- **文件**: `aetheris-node/src/state.rs`、`aetheris-node/src/main.rs`
- **验证**: 多区块递归链验证通过

> ⚠️ **P1 — Accumulator 是 trusted-aggregator + O(n) replay,不是 O(1) trustless 递归。**
> 当前实现 (`aetheris-recursive::block_aggregator`) 由单一 prover 在链外累加 `hash(proof || commitments)`;verifier O(n) replay 比对。**未实现 in-circuit IPA verification**;accumulator chain 不是递归 SNARK。
>
> **接受标准 (当前)**: (1) 篡改 proof/commitments/public_amount → 链 replay 拒绝; (2) wire format 稳定 (28B prefix + Pallas Q + transcript + LE u32 depth = 96B); (3) coinbase 排除规则清晰 (validator `filter(|tx| tx.public_amount <= 0)` in `aetheris-node::state.rs`)
>
> **未声称为**: O(1) trustless 递归 (需 IPA verifier gadget + 真正 Halo2 recursive proof wrapper);P2P gossip 累积 state 而非单一 accumulator
>
> **Mainnet 影响**: 启动期假设 validator 节点诚实;若要 trustless → Phase 3+ 重新设计 (a) IPA verifier 电路 (b) accumulator SNARK wrapper (c) P2P 累积协议 (d) 替换 gossip schema

### 1.6 实现真实 VDF prove/verify
- **来源**: B-3（原是 1.5）
- **动作**: 实现 Wesolowski VDF 证明生成和验证（非 blake3 hash）
- **文件**: `aetheris-zkp/src/halo2_pasta.rs`
- **验证**: 新增 VDF 证明验证测试

### 1.7 恢复所有调用方
- **来源**: B-4, B-5, B-6（原是 1.6）
- **动作**: 修复 `ZKProofSystem` API 变更影响的所有调用点（FFI、wallet、node）
- **验证**: `cargo check --workspace` 无警告

### 1.8 Accumulator Happy-Path 集成测试 ✅ DONE
- **来源**: ISSUANCE-1.4.C (Phase 1.4 review deferred)
- **动作**: 5 个 end-to-end tests in `aetheris-recursive/src/block_aggregator.rs::tests` 验证 `accumulate_proof` + `verify_accumulator_chain` 用真实 ZKP proofs (非合成 bytes)
- **文件**: `aetheris-recursive/src/block_aggregator.rs`
- **提交**: `9744659` (source) + `ef7eb01` (docs)
- **验证**: aetheris-recursive 33/33 pass (was 28, +5);workspace 180/180
- **P0 风险**: 见 1.9 — circuit soundness gap 仍存在,此 5 tests 通过仅因 honest prover

### 1.9 P0 — Conservation Circuit Soundness Fix 🔴 **CRITICAL, 立即启动**
- **来源**: 用户审计 2026-06-06;`aetheris-zkp/src/halo2_pasta.rs:219-279`
- **现状问题**:
  1. `ValueConservationCircuit` 不约束 `sum_in - sum_out = public_amount` (仅 prover 端 `if net_value != 0 { Err(Synthesis) }` 预检 line 224-226;恶意 prover 可绕过)
  2. `output_commitments` 字段在 synthesis 完全不用 (`halo2_pasta.rs:145` 存了但 233-278 的 `synthesize` 从未读)
  3. `verify_conservation` 的 `_output_commitments` 参数 unused (`halo2_pasta.rs:380`)
- **后果**: 恶意 prover 直接构造 witness + IPADeserialize,可声称任何 `amounts_in/amounts_out/public_amount` 都通过验证;`make_tx_proof` 诚实并不证明电路在保护
- **修复范围**:
  1. **删除预检** `if net_value != 0 { Err(Synthesis) }` (line 224-226);电路成为唯一 source of truth
  2. **新增 gate** `conservation_running_sum`:advice 列累加 `+amount_in - amount_out`,实例列约束累加终值 = public_amount
  3. **新增 gate** `commitment_binding` + **新 instance column**:`commitment = amount + H(blinding)`;commitments 放 instance column,verifier 可抽
  4. **`prove_conservation` 改造**:commitments 填 instance column;返回 bytes 含 instance 数量
  5. **`verify_conservation` 改造**:从 instance column 抽 commitments,与 `output_commitments` 参数 (改名为非 `_`) 实际比较 (不再只是 hash 进 transcript)
  6. **Wire format**:`halo2_ipa_pasta_v1_` (19B) + shape (4B) + public_amount_instance (32B) + commitments (32B × N) + proof
- **配套更新**:
  - `aetheris-node/src/state.rs` validator:实际 verify commitments
  - `aetheris-ffi/src/lib.rs` 4 个 C-ABI 函数:thread commitments 正确
  - `aetheris-recursive/src/accumulator.rs` + `block_aggregator.rs`:commitments 验证变严肃
  - `aetheris-wallet` send path
  - Phase 1.8 tests `make_tx_proof` helper:新 signature
- **新测试**:
  - `test_conservation_rejects_inconsistent_amounts` (sum_in≠sum_out+public_amount,验证绕过预检后仍能 fail)
  - `test_conservation_rejects_wrong_commitment` (commitment 不匹配 amount/blinding)
  - `test_conservation_rejects_missing_commitment` (空 commitments)
  - 回归:改写 `test_conservation_*` 系列用新 API
- **预估**: 300-500 行,~1 天
- **启动门**: **必须** 在 §1.12 之前完成,否则 trustless 模式基于 broken circuit

### 1.10 Signed Accumulator (trusted 模式 O(1) 优化,~1 周)
- **来源**: P1 改进
- **动作**:
  - `accumulate_proof` 加 ed25519 签名 (prover 私钥签 `blake3(prev_accumulator || proof || commitments || public_amount)`)
  - `verify_accumulator_chain` 优先 O(1) signature check;O(n) replay 降为可选 audit mode
  - Wire format:28B prefix + Q + transcript + ed25519_sig (64B) + depth = 160B
- **未触及**: cryptographic soundness (仍 trusted aggregator)
- **预估**: 200 行

### 1.11 P2P Proof Gossip (P2P 层改进,~2 周)
- **来源**: `AggregateProofGossip` stub in `aetheris-recursive/src/lib.rs:1175`
- **动作**:
  - `AggregateProofGossip` 消息体: `claimed_accumulator (96B) || proof (var) || commitments (32B × N) || signature (64B)`
  - Receivers P2P 层先 verify signature + replay 再 gossip;拒绝伪造;DOS 防护
  - 兼容 §1.10 (有签名) 与无签名模式
- **未触及**: 递归 SNARK (仍 trusted)
- **预估**: 400 行

### 1.11.5 ✅ IPA-PLONK h_eval 约束修复（Stage 40，已完成）
- **来源**: `ISSUE_IPA_PLONK_INTEGRATION.md`
- **诊断**: IFFT DC 伪影在索引 ≥4094 处，`extended_k=13` 解决了问题
- **结果**: `expected_h_eval == transcript_h_eval` = true，约束在 `vanishing/verifier.rs:142-144` 活跃
- **验证**: `cargo test -p aetheris-zkp` 69/69 ✅
- **关闭**: `ISSUE_IPA_PLONK_INTEGRATION.md` 已过时，不再反映实际

### 1.12 ✅ B-2: In-Circuit IPA Verifier Gadget（已完成，commit 59cd2c9）
- **范围**: 原生 Vesta IPA accumulation circuit，完全在 `Circuit<Fq>` 上，消除 NonNativeChip
- **子步骤**: S0-S11（详见 `aetheris-recursive/B-2_plan.md`）
- **产出**:
  - `vesta_ecc.rs` — 原生 Vesta EC ops（on_curve, add, double, select, scalar_mul, constrain_equal）
  - `vesta_fq.rs` — 原生 Fq 算术（add, mul, invert 门）
  - `vesta_range.rs` — 8-bit Fq 范围检查
  - `vesta_transcript.rs` — Vesta Blake2b transcript chip（compress → squeeze → challenge）
  - `vesta_ipa.rs` — IPA folding round（b-vector + offset 点展平）
  - `vesta_accumulate.rs` — 完整 IPA verifier circuit（transcript + folding）
- **验证**: `cargo test -p aetheris-recursive --lib` 155/155 ✅
- **移除**: `ipa_fold.rs`, `ipa_verifier_circuit.rs`, `non_native_mul.rs`（被原生代码取代）
- **保留**: `non_native_fq.rs`（转录 gadget 需要，Phase 6 替换）

### 1.13 Recursive Proof Wrapper (依赖 §1.12, ~1 周)
- **目标**: Halo2 电路 wrapping 整个 accumulator chain → 输出 constant-size proof
- **范围**:
  - 电路内 verify IPA proof (用 §1.12 gadget) + 累加新 tx → 输出新 recursive proof
  - Output: `Vec<u8>` (recursive proof bytes, 固定大小 < 10 KB)
  - 兼容"恒定证明大小" (vs 当前 accumulator 线性增长)
- **预估**: 300-500 行

### 1.14 State Root + FFI Migration (依赖 §1.13, ~3 天)
- **状态根**: `state_root = blake3(recursive_proof_bytes)` (新) vs `blake3(accumulator_state)` (旧)
- **新 C-ABI** (叠加,不破现有):
  - `aetheris_verify_recursive_proof(proof: *const u8, len: usize) -> i32` 
  - `aetheris_get_recursive_state_root(proof: *const u8, len: usize, out: *mut [u8; 32]) -> i32`
- **向后兼容**: 旧 node (无 recursive proof) 仍能 verify accumulator 链 (回退 §1.5-1.8 trusted 模式)

### 1.15 Soft Fork Activation (~1 周)
- **新 Block::header 字段**: `recursive_proof: Option<Vec<u8>>` (None = trusted 模式)
- **共识规则**:
  - block 有 `recursive_proof` → 必须 verify 成功 (用 §1.12+§1.13) 才接受
  - block 无 `recursive_proof` → 接受 (回退 §1.5-1.8 trusted 模式)
  - Mainnet 激活后: **必须** 带 `recursive_proof`
- **Mainnet 启动门** = §1.12-§1.15 全部完成 + 安全审计 + testnet 试运行

### 1.16 Mainnet Launch 🚀
- **触发**: §1.12-§1.15 完成 + Phase 2-4 完成 + 全安全审计
- **启动模式**: trustless O(1) recursive proof (新模式) + trusted accumulator 模式 (emergency fallback,默认禁用)
- **保留代码**: §1.5-§1.8 trusted accumulator 全部保留,作为 fallback 路径 (在 hard fork 撤销前可用)

---

## Phase 2 — 钱包与隐私

### 2.1 屏蔽交易真实加密
- **来源**: A-7
- AES-256-GCM + X25519 ECDH；删除 `b"AETHSCAN"` 占位

### 2.2 钱包 UTXO 加密存储
- **来源**: B-17
- wallet.json utxos 用 spending key 派生密钥 AES 加密

### 2.3 P2P 发送集成
- **来源**: B-15
- `send_tx` → 序列化 `core::Transaction` → P2P broadcast

### 2.4 P2P 扫描集成
- **来源**: B-16
- `scan` → 连节点 → 下载区块 → trial-decrypt

### 2.5 DH-based stealth address
- **来源**: B-18, M-3, C-9
- 真实 ECDH 密钥交换；删除 `Keccak(target + timestamp)`

### 2.6 BIP32 HD wallet + Zeroize
- **来源**: B-14, D-12, D-13
- `m/44'/AET'/0'/0/i`；`Seed`/`mnemonic`/`sk` 用 `Zeroizing<T>`

### 2.7 创世修复
- **来源**: A-9, A-10, C-8, D-8, D-9, D-11
- 盲化因子随机化；真实 trial-decrypt；修复假地址检查

---

## Phase 3 — 网络健壮

| 项 | 来源 | 动作 |
|----|------|------|
| 3.1 Peer scoring | C-1, B-10 | gossipsub 评分 + spam 处罚 |
| 3.2 Gossip 规范 | C-2 | 三级验证管道 |
| 3.3 Bootstrap | C-3 | 种子节点 + DNS 发现 |
| 3.4 NAT 穿越 | C-4 | relay + dcutr |
| 3.5 Loopix 治理 | B-7 | 标记 stub，文档去假 |

---

## Phase 4 — 生产就绪

| 项 | 来源 | 动作 |
|----|------|------|
| 4.1 sled DB 批写 | B-3 | block checkpoint + WAL batch |
| 4.2 文档修正 | E-1~E-11 | 统一 docs 与实际实现 |
| 4.3 死代码/死依赖 | D-2, D-6, D-18 | 清理 |
| 4.4 has_square_factor | D-16 | 扩展到 ≥100 小素数 |
| 4.5 VDF 内存 | D-17 | 流式存储，不保留全部 T+1 中间值 |
| 4.6 仲裁 tie-breaker | C-6 | 平局按 block hash 字典序选最小 |

---

## Future（不阻塞 Mainnet MVP）

| 项目 | 条件 |
|------|------|
| ZK-VM + RISC-V | Phase 0-4 完成 |
| FHE | 研究前沿，无时间表 |
| 后量子格密码 | 通过 ZkProverSystem trait 切换 |
| 形式化验证 | Phase E 规划 |
| 激励模型 | MVP 上线后 |

---

## 依赖图

```
P0 (协议安全 — 当前执行，所有 Phase 暂停)
  P0.1 ──┐  A-1: running_sum z_64=0       ✅
  P0.2 ──┤  H-1: state_root 负测试        ✅
  P0.3 ──┤  C-5: nullifier 端到端测试     ✅
  P0.4 ──┤  A-3: viewing key 统一         ✅
  P0.5 ──┘  C-2: membership+nullifier     ⏳ IPA 回环已修复，Gate 选择待实现
         │  P0 全部完成 → 恢复 Phase 1
         ▼
Phase 0-1 (Node + ZK — 大部分已完成，等待 P0)
  0.1-0.8 ──── Phase 0 全部 ✅完成
  1.0 ──────── ZK trait ✅
  1.1 ──────── IPA 承诺方案 ✅
    ├─1.1.0-1.1.3 (ParamsIPA, ProverIPA, VerifierIPA, 验证策略)
  1.2 ──────── Pasta 电路 ✅ (Halo2PastaBackend)
  1.3 ──────── 清理 aetheris-recursive ✅
  1.6 ──────── VDF 真实实现 ✅
  1.8 ──────── Accumulator 测试 ✅
  1.9 ──────── Conservation soundness fix ✅ (但 A-1 z_64=0 仍需修复 = P0.1)
  1.11.5 ───── IPA-PLONK h_eval ✅
  1.12 ─────── B-2: In-Circuit IPA Verifier ✅
         │  P0 完成后继续
         ▼
Phase 1 剩余 (P0 后执行)
  1.4  B-3 ── aggregate_proofs IPA 化
  1.5  ────── IPA 区块集成
  1.7  ────── 恢复调用方
  1.10 ────── Signed Accumulator
  1.11 ────── P2P Proof Gossip
  1.13-1.16 ─ Recursive Wrapper → Mainnet
         │
         ▼
Phase 2 ──→ Phase 3 ──→ Phase 4
```

---

## 验证门禁

| 门禁 | 范围 | 命令 |
|------|------|------|
| 🔴 编译 | 全部 | `cargo build --workspace` |
| 🟡 ZK 测试 | aetheris-zkp | `cargo test -p aetheris-zkp` |
| 🟡 递归测试 | aetheris-recursive | `cargo test -p aetheris-recursive` |
| 🟡 加密测试 | aetheris-crypto | `cargo test -p aetheris-crypto` |
| 🟢 全测试 | workspace | `cargo test --workspace` |
| 🟢 安全 | 双花/伪造拒绝 | 手动构造无效 tx |

---

## 时间估算

```
已完成 (Prior):
  Phase 0.0-0.8    Node 救命                                                 ✅
  Phase 1.0-1.2    ZK trait + IPA 承诺方案 + Pasta 电路                      ✅
  Phase 1.3        清理 aetheris-recursive                                   ✅
  Phase 1.6        VDF 真实实现                                               ✅
  Phase 1.8        Accumulator 集成测试                                       ✅
  Phase 1.9        Conservation soundness fix (partial)                      ✅
  Phase 1.11.5     IPA-PLONK h_eval 修复                                     ✅
  Phase 1.12       B-2: In-Circuit IPA Verifier (Vesta native)               ✅
  P0.1             A-1 running_sum z_64=0                                    ✅
  P0.2             H-1 state_root 负测试                                     ✅
  P0.3             C-5 nullifier 端到端测试                                  ✅
  P0.4             A-3 viewing key 统一                                      ✅
  ─────────────────────────────────────────────────────────────────

P0 Sprint (当前):
  P0.1  A-1 running_sum z_64=0               ✅ 已完成
  P0.2  H-1 state_root 负测试                ✅ 已完成
  P0.3  C-5 nullifier 端到端测试             ✅ 已完成
  P0.4  A-3 viewing key 统一                 ✅ 已完成
  P0.5  C-2 membership+nullifier              ⏳ Gate 选择待实现（见 §2.2 更新）
  ─────────────────────────────────────────────────────────────────

P0.5 实施子项:
  1.  ✅ MockProver: MembershipCircuit + Poseidon Merkle 路径验证 + Nullifier 派生
  2.  ✅ IPA 回环: 根因分析（permutation label mismatch）+ 初步修复（preserve position_bits in without_witnesses）
  3.  ⏳ Gate 选择重构: 替换 constrain_equal 分支为 mux_inputs gate，使 VK 与 position_bits 无关
  4.  ❌ 集成到 ValueConservationCircuit: 将 MembershipCircuit 作为子模块接入 tx 电路

P0 后继续:
  Phase 1.4  B-3: aggregate_proofs IPA 化    ~1 周
  Phase 1.5  IPA 区块集成                    ~3 天
  Phase 1.7  恢复调用方                      ~2 天
  Phase 1.10 Signed Accumulator              ~1 周
  Phase 1.11 P2P Proof Gossip                ~2 周
  Phase 1.13-1.16 Recursive Wrapper→Mainnet  ~2 周

Full Trustless Mainnet ≈ P0 + Phase 1 剩余 + Phase 2-4 ≈ 2-3 个月
```
