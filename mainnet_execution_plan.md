# Aetheris Mainnet 执行方案

> 合并 Stage 27 全代码库审计（86 项发现）+ `protocol_design_ruling.md` 架构决策 + ZK 后端抽象层，
> 形成可逐 commit 落地的执行计划。
>
> **核心原则**:
> 1. Phase 0 不碰 ZK 电路代码（避免在 BN254 上修废弃代码）
> 2. Phase 1 一次性完成 Pasta 迁移 + 所有 ZK 修复（不重复劳动）
> 3. 不声称未实现的功能；每步有明确验证标准

---

## 总览

```
Phase 0   Node 救命    ─→  链终于能跑（不碰 ZK）
Phase 1   ZK 重写      ─→  Pasta + 真实 IPA + 所有电路修复（一次性）
Phase 2   钱包+隐私    ─→  真正的隐私
Phase 3   网络健壮     ─→  多节点
Phase 4   生产就绪     ─→  文档/清理
```

**MVP 门槛** = Phase 0 + Phase 1

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

### 1.0 ZK 抽象 trait 初始化
- **来源**: protocol_design_ruling.md §5
- **动作**:
  1. `aetheris-zkp/src/trait.rs` 定义 `ZkProverSystem`
  2. 当前 BN254 代码不动（放在 `drop/` 下当参考）
  3. 新建 `aetheris-zkp/src/halo2_pasta.rs` 写 Pasta 实现
  4. `lib.rs` 重导出 `pub type ZKProofSystem = Halo2PastaBackend;`
- **验证**: `cargo build -p aetheris-zkp`

### 1.1 Pasta 曲线迁移 — aetheris-zkp
- **来源**: B-1, A-21
- **动作**:
  1. 替换 Cargo.toml 依赖：`ark_bn254`/`ark_grumpkin` → `pallas`/`vesta`
  2. 重写 `ValueConservationCircuit` 使用 Pasta 域
  3. **一次性实现正确 running-sum 约束**（原 A-1：跨 range 行 `advice[3]` 受约束）
  4. **一次性实现 input membership + nullifier correctness**（原 C-2：Merkle path 证明 + Poseidon nullifier 约束）
  5. Generator 用哈希到曲线安全派生，非硬编码
- **文件**: `aetheris-zkp/src/`（新建 `halo2_pasta.rs`，保留旧 BN254 代码作参考但不编译）
- **验证**: `cargo test -p aetheris-zkp` 全部通过；手动构造无效 proof 被拒绝

### 1.2 Pasta 曲线迁移 — aetheris-recursive
- **来源**: B-1
- **动作**:
  1. 删除 `NonNativeChip`（~1500 行，Pasta 2-cycle 不再需要）
  2. 删除 `KzgChip`（~200 行，无意义空操作）
  3. 删除 `AccumulatorChip`（~200 行，线性组合不是 accumulator）
  4. 删除旧的 `RecursiveAggregationCircuit`（~200 行，不是递归 SNARK）
  5. 修复 `EccChip` identity 点 `(0,0)` 不在曲线上
  6. Poseidon 用 Grain LFSR 生成标准参数
- **验证**: `cargo test -p aetheris-recursive`

### 1.3 实现真实 Halo2 IPA 积累
- **来源**: B-2, A-11 ~ A-15
- **动作**: `<500` 行原生 Pasta 算术替代原来 ~2500 行错误代码
  ```
  struct Accumulator { Q: Point<Pasta>, transcript: [u8; 32] }
  fn accumulate(π, acc_old) → acc_new:
    verify_halo2(π)
    challenge = Poseidon(acc.transcript, π.commitment)
    Q_new = acc.Q + challenge • π.commitment
  ```
- **验证**: 递归积累 3+ 层端到端测试

### 1.4 集成 IPA 积累到区块生产
- **来源**: B-3
- **动作**: 替换区块生产中的 Merkle 哈希 aggregate 为 `ZKProofSystem::aggregate_proofs`
- **文件**: `aetheris-node/src/state.rs`、`aetheris-node/src/main.rs`
- **验证**: 多区块递归链验证通过

### 1.5 实现真实 VDF prove/verify
- **来源**: B-3
- **动作**: 实现 Wesolowski VDF 证明生成和验证（非 blake3 hash）
- **文件**: `aetheris-zkp/src/halo2_pasta.rs`
- **验证**: 新增 VDF 证明验证测试

### 1.6 恢复所有调用方
- **来源**: B-4, B-5, B-6
- **动作**: 修复 `ZKProofSystem` API 变更影响的所有调用点（FFI、wallet、node）
- **验证**: `cargo build --workspace` 无警告

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
Phase 0 (Node 救命，不碰 ZK 代码)
  0.1 ────┐
  0.2 ────┤
  0.3 ────┤
  0.4 ────┤ (0.5 依赖 0.4)
  0.5 ◄──┤
  0.6 ────┤
  0.7 ────┤
  0.8 ────┘
          │  Phase 0 全部完成
          ▼
Phase 1 (一次性 ZK 重写)
  1.0 ────┐
  1.1 ────┤
  1.2 ────┤ (依赖 1.1)
  1.3 ◄──┤ (依赖 1.2)
  1.4 ◄──┤ (依赖 1.3 + 0.1-0.3)
  1.5 ────┤
  1.6 ────┘
          │  Phase 1 全部完成 = MVP
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
Week 1-2:   Phase 0  (8 commits, Node 层修复，不碰 ZK)
Week 3-8:   Phase 1  (6 commits, 最大工作量——Pasta 迁移 + IPA 实现 + 所有电路重写)
Week 9-12:  Phase 2  (7 commits, 钱包隐私)
Week 13-15: Phase 3  (5 commits, 网络)
Week 16-17: Phase 4  (6 commits, 文档/清理)

MVP (Phase 0+1) ≈ 8 周
Full Mainnet (Phase 0-4) ≈ 17 周
```
