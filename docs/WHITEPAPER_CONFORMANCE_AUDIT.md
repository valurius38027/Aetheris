# Aetheris 白皮书合规审计——真实状态记录

> **本文件是唯一事实标准** (Single Source of Truth)。
> 仅以 `whitepaper.md` v1.0 (2026-02-12) 的设计哲学与技术规格为标尺。
> 所有进度文档、计划文档、中间状态报告均**不可信**。
>
> 生成日期: 2026-06-13
> 生成方式: 5 并行子代理全代码库审计 + 人工核验

---

## 目录

1. [设计哲学（三条公理）](#1-设计哲学三条公理)
2. [§3.1 递归 ZK-SNARKs / 屏蔽交易](#31-递归-zk-snarks--屏蔽交易)
3. [§4 PoT 共识 + 数学仲裁](#4-pot-共识--数学仲裁)
4. [§5 经济模型](#5-经济模型)
5. [§6 网络层安全（日蚀抵抗 + Mixnet）](#6-网络层安全)
6. [架构级偏差总结](#7-架构级偏差总结)
7. [子系统可靠度排名](#8-子系统可靠度排名)
8. [测试状态总表](#9-测试状态总表)

---

## 1. 设计哲学（三条公理）

来源: `whitepaper.md §2`

### 公理一：创世锚点 (Genesis Anchor)

> 协议认定创世交易（Genesis Transaction）及其哈希值为绝对可信的数学原点。

| 检查项 | 代码状态 | 证据 |
|--------|---------|------|
| 创世区块生成 | ✅ `create_genesis_block()` 生成空区块（零交易） | `aetheris-core/src/lib.rs:174-199` |
| 创世hash确定性 | ✅ `genesis_identity_hash()` 排除证明/临时密钥/密文 | `aetheris-node/src/state.rs:317-334` |
| 创世hash作为验证起点 | ✅ `restore_from_db()` 从高度 0 重放 | `aetheris-node/src/state.rs:36-73` |
| **创世导入崩溃** | ❌ `aetheris_import_wallet` 访问 `genesis.transactions[0]`，但空创世无交易→越界 panic | `aetheris-ffi/src/lib.rs:1084` |
| **state.rs 拒绝空创世** | ❌ `apply_block` 要求 `transactions.len() == 2`，但空创世长度为 0 | `aetheris-node/src/state.rs:292-294` |

**判定**: ⚠️ 概念正确但代码自相矛盾——创世为空，但验证路径拒绝空创世且导入路径崩溃。

---

### 公理二：形式化安全 (Formalized Security)

> 所有核心协议逻辑、密码学谓词及 ZK-VM 指令集必须经过形式化验证。

| 检查项 | 代码状态 | 证据 |
|--------|---------|------|
| Coq/TLA+/Lean 形式化证明 | ❌ 零形式化文件存在 | `formal_proof/` 目录为 stubs/placeholders |
| ZK 电路约束正确性 | ⚠️ 值守恒/成员/nullifier 有约束，但承诺绑定无线电路 | `aetheris-zkp/src/halo2_pasta.rs:344-356` |
| VDF 数学正确性 | ✅ 类群运算 + Wesolowski 证明公式精确 | `aetheris-crypto/src/vdf.rs`, `classgroup.rs` |

**判定**: ❌ 完全未达到——白皮书自身 §1.3 已将形式化验证降级至 Future Phase E。

---

### 公理三：主权验证 (Sovereign Verification)

> 每个客户端以创世锚点为起点独立验证，不依赖网络多数的"共识"。

| 检查项 | 代码状态 | 证据 |
|--------|---------|------|
| 创世锚点独立验证 | ✅ `restore_from_db()` 从区块 0 重放 | `aetheris-node/src/state.rs:36-73` |
| VDF 链验证 | ✅ 每个区块验证 VDF | `state.rs:363-366` |
| ZK 证明验证 | ✅ 验证递归证明 | `state.rs:372-376` |
| Nullifier 唯一性 | ✅ 拒绝双花 | `state.rs:382-389` |
| **日蚀可检测性** | ❌ 无本地 VDF 迭代计数 vs 收到区块数的比较 | 白皮书 §6.1 要求 |
| **重新连接恢复** | ❌ 无 VDF 重算来恢复规范链 | 白皮书 §6.1 要求 |
| **独立验证器模式** | ❌ 验证逻辑嵌入在全节点中，无可分离的仅验证 CLI | 白皮书 §2 要求 |

**判定**: ⚠️ 基础验证存在，但主权验证的最强形式（日蚀检测、重连恢复、独立验证器）缺失。

---

## 2. §3.1 递归 ZK-SNARKs / 屏蔽交易

### 2.1 递归证明链

白皮书原文:
> 每一笔新的交易证明都会包含前一状态的合法性证明。从而实现资金链切断。客户端只需验证最新的递归证明，即可确认整个账本历史的合法性。

| 子项 | 状态 | 证据 |
|------|------|------|
| 每笔交易证明包含前一个证明 | ❌ **零递归**——每笔交易是独立证明 | `aetheris-zkp/src/halo2_pasta.rs` 全文件 |
| 递归区块链 Π_n = Prove(..., {Π_{n-1}, π_txs}) | ⚠️ 半实现：`prove_block_recursive` 存在，但使用线性组合累加器而非真正的 IPA folding | `aetheris-recursive/src/prove_recursive.rs:447-510` |
| 客户端仅验证最新递归证明 | ✅ 通过 Halo2 证明包装实现 O(1) 验证 | `verify_accumulate_proof` |
| 资金链切断（输入/输出不可关联） | ⚠️ 使用加法承诺 `amount + blind` 而非 Pedersen 承诺，约束不在电路内 | `aetheris-zkp/src/halo2_pasta.rs:159-168` |

**核心架构偏离**:
- `AccumulatorIPA::accumulate` 计算 `Q_new = Q_old + challenge·hash_to_curve(proof_hash)`
- 这是一个 **Schnorr 式线性组合**，**不是 Halo2 IPA accumulation scheme**
- 白皮书 §8 要求的 `π_{a+b} = Φ(π_a, π_b, Acc_n)`、合并 O(log N)、结合律 **全部不存在**
- 详细分析: `aetheris-recursive/src/accumulator.rs:139` 和 `aetheris-recursive/src/circuit_accumulate.rs`

---

### 2.2 值守恒电路 (Value Conservation)

来源: `aetheris-zkp/src/halo2_pasta.rs:213-365` (CombinedConservationCircuit)

| 约束 | 状态 | 实现细节 |
|------|------|---------|
| range_check (64-bit) | ✅ Running-sum 位分解，`b·(1-b)=0` 门 | 每金额 65 行 |
| value_conservation | ✅ `sum_in - sum_out - public_amount = 0` | running_sum 约束 |
| output_commitment 实例绑定 | ⚠️ 仅 `assign_advice_from_instance` 复制约束，**无门约束证明 `commitment == create_commitment(amount, blind)`** | 代码自认: "Circuit constraint for Fq-based Pedersen commitment is deferred (requires ECC gates)" (`combined_circuit.rs:283-286`) |
| 手续费燃烧 (public_amount) | ✅ 正 public_amount 作为手续费，守恒电路中自动约束 | `state.rs:463-513` |

**关键漏洞**: `create_commitment` = `amount + hash_to_field(blinding)`——不是 Pedersen 承诺，不产生 EC 点。
证明生成时的 host-side 检查 (`prove_conservation` lines 418-425) 不由验证者执行——验证者无法检测证明是否使用了不同的盲化因子。

---

### 2.3 成员 + Nullifier 证明

| 子项 | 状态 | 证据 |
|------|------|------|
| Merkle 路径验证 in-circuit | ✅ Gate-based mux（非 branch-dependent constrain_equal） | `aetheris-zkp/src/membership_circuit.rs` |
| Nullifier = Poseidon(sk, index) | ✅ 约束到 instance[1] | `poseidon_fq.rs:201` |
| Poseidon 哈希 | ✅ Native Fq, t=3, r_f=8, r_p=56 | `aetheris-zkp/src/poseidon_fq_chip.rs` |
| 曲线 | ⚠️ 成员用 Pallas (EpAffine)，值守恒用 Vesta (EqAffine)——不统一 | `halo2_pasta.rs` vs `combined_circuit.rs` |
| 证明系统 | ✅ IPA (Inner Product Argument)，非 KZG | `aetheris-zkp/src/ipa/` |

---

### 2.4 密码学原语

| 子项 | 状态 | 证据 |
|------|------|------|
| Pasta 曲线 | ✅ Pallas + Vesta，y²=x³+5 | 已从 BN254/Grumpkin 迁移 |
| NonNativeChip | ✅ 已完全消除 | ~5000 行删除 (git: `0474485`) |
| Poseidon 哈希 | ✅ Native Fq，标准参数 | `poseidon_fq_chip.rs` |
| 承诺方式 | ❌ 加法承诺（非 Pedersen），无线电路约束 | `halo2_pasta.rs:159-168` |

---

## 3. §4 PoT 共识 + 数学仲裁

### 3.1 VDF 时间链

| 子项 | 状态 | 证据 |
|------|------|------|
| 类群 VDF（非 RSA） | ✅ | `aetheris-crypto/src/classgroup.rs` + `vdf.rs` |
| Wesolowski 证明 | ✅ π = x^⌊2^T/l⌋, 验证 y = π^l · x^(2^T mod l) | `vdf.rs:80-94, 119-127` |
| |D| = 2048 bit | ✅ | `vdf.rs:36-39` |
| D ≡ 1 (mod 4) | ✅ | `classgroup.rs:454-463` |
| 无平方因子（基本判别式） | ❌ 仅检查前 20 个素数（≤71），2048-bit 不充分 | `classgroup.rs:474-485` |
| Hash-to-Form 确定性 | ✅ blake3 + k-search | `classgroup.rs:235-299` |
| Hash-to-Form 算法与白皮书一致 | ⚠️ 数学等价但算法不同（代码 fix c=k 而非 spec 的 a=floor(κk)） | `classgroup.rs:277-295` vs `math_spec.md §1.1.4` |
| VDF 测试 | ✅ 41/41 通过 | 26 VDF + 15 classgroup |

---

### 3.2 难度自平衡

| 参数 | 白皮书要求 | 代码值 | 一致 |
|------|-----------|--------|------|
| T_target | 10s | `TARGET_BLOCK_TIME = 10` | ✅ |
| N | 10 | `DIFFICULTY_ADJUSTMENT_INTERVAL = 10` | ✅ |
| M | 4 | 文字 4（硬编码） | ✅ 但非命名常量 |
| T_genesis | 1,600,000 | `VDF_DIFFICULTY = 1_600_000` | ✅ |

**BUG: 两个不等价的难度重定向实现**

1. `consensus.rs:80-97` `calculate_next_difficulty`:
   - 对 actual_time 施加 M=4 限制
   - 对 new_difficulty **无限制**
   - 用于 active mining 路径

2. `vdf.rs:171-188` `VDF::retarget_difficulty`:
   - 对 actual_time 施加 M=4 限制
   - 对 new_difficulty 也施加 M=4 限制 ← 额外限制
   - 用于 replay/validation 路径

**风险**: Active miner 和 validator 在相同链数据上计算出不同难度 → 边缘情况下的共识分裂。

---

### 3.3 数学仲裁

白皮书公式:
```
winner = min_by_key(proposals, key = blake3(prev_block_hash ∥ vdf_result))
```

代码实际 (`consensus.rs:61-65`):
```rust
pub fn get_winner(&self, height: u64) -> Option<BlockProposal> {
    self.proposals.get(&height)?.iter().min_by_key(|p| {
        p.block_hash  // = blake3(bincode::serialize(entire_block))
    }).cloned()
}
```

| 属性 | 白皮书要求 | 实际 | 一致 |
|------|-----------|------|------|
| 排序键 | `blake3(prev_hash ∥ vdf)` | `blake3(全部序列化区块)` | ❌ 偏离 |
| 单调性 | 满足 | min_by_key 保证 | ✅ |
| 序无关性 | 满足 | min_by_key 保证 | ✅ |
| 局部确定性 | 满足 | min_by_key 保证 | ✅ |
| 零投票/轮次 | 无需沟通 | 纯本地决定函数 | ✅ |

**偏差影响**: 虽然三个数学性质都保持，但键公式的具体选择偏离了白皮书。完整区块哈希更难被 grinding，但行为不同。

---

## 4. §5 经济模型

### 4.1 Fair Launch + 线性排放

| 子项 | 状态 | 证据 |
|------|------|------|
| 零预挖 | ✅ 创世无交易 | `create_genesis_block()` 返回 `transactions: vec![]` |
| 零创始人分配 | ✅ 无创世 mint/transfer | 同上 |
| 零基金会资金 | ✅ | 同上 |
| 线性排放公式 | ✅ `reward(h)=max(0,R0×(1-h/N))` | `aetheris-core/src/lib.rs:101-108` |
| R0 = 1 AET (10^8 atoms) | ✅ | `INITIAL_BLOCK_REWARD_ATOMS = 100_000_000` |
| N = 42,000,000 | ✅ | `EMISSION_BLOCKS = 42_000_000` |
| 总供给 ~21M AET | ✅ 数学推导 | 线性排放端到端测试通过 |
| **空创世被 state.rs 拒绝** | ❌ 要求 `transactions.len() == 2` | `state.rs:292-294` |
| **导入空创世崩溃** | ❌ 访问 `genesis.transactions[0]` 越界 | `aetheris-ffi/src/lib.rs:1084` |

---

### 4.2 手续费燃烧

| 子项 | 状态 | 证据 |
|------|------|------|
| 手续费从 coinbase 扣除 | ✅ `coinbase = block_reward.saturating_sub(total_fees)` | `state.rs:463-513` |
| 通过 public_amount 约束 | ✅ 守恒电路自动处理 | `aetheris-core/src/lib.rs:242-259` |
| **MIN_TX_FEE 常数** | ❌ **代码中不存在**——仅在 `math_spec.md` 和 `whitepaper.md` 提及 | 全局搜索 `MIN_TX_FEE` 无 Rust 匹配 |
| **FEE_PER_BYTE 常数** | ❌ **代码中不存在**——同上 | 全局搜索无 Rust 匹配 |
| **手续费计算公式未实现** | ❌ `fee = max(MIN_TX_FEE, tx_size × FEE_PER_BYTE)` 无代码 | 仅文档中存在 |

**判定**: ⚠️ 燃烧机制（coinbase 扣除）存在，但防 spam 的最小手续费和每字节费率全未实现。

---

### 4.3 创世区块

| 子项 | 状态 | 证据 |
|------|------|------|
| 空状态启动 | ✅ `state_root: build_merkle_root(&[])` | `lib.rs:195` |
| 无冻结地址 | ✅ 无 `is_frozen` 逻辑 | 全局搜索 |
| 创世哈希确定性 | ✅ `genesis_identity_hash()` 跨运行确定 | `state.rs:317-334` |
| 第一个矿工获得高度 0 奖励 | ❌ 空创世被 state.rs 拒绝，矿工无法获得奖励 | `state.rs:292-294` |

---

## 5. §6 网络层安全

### 5.1 日蚀抵抗定理

白皮书要求 4 个数学保证：

| 定理 | 要求 | 实现状态 |
|------|------|---------|
| 完整性（不接收非法状态） | ✅ ZK+VDF+Nullifier 验证全部本地计算 | ✅ `state.rs` 全验证路径 |
| 可检测性（VDF 迭代≠区块） | ❌ **无代码比较本地 VDF 计算数与收到区块数** | 缺失 |
| 可恢复性（重连后 VDF 重算） | ❌ **无 VDF 重算恢复机制**——信任本地 DB | 缺失 |
| 有限损害（不窃取、不双花、不分叉） | ✅ Nullifier 唯一性+ZK 密钥保护 | ✅ `state.rs` |

---

### 5.2 Mixnet (Loopix)

| 子项 | 状态 | 证据 |
|------|------|------|
| 洋葱路由 | ⚠️ 自定义 3 跳 AES-GCM+X25519 | `aetheris-node/src/mixnet.rs` |
| 标准 Loopix 泊松过程 | ❌ 不存在 | — |
| Sphinx 数据包格式 | ❌ **完全缺失** | — |
| 覆盖流量 | ⚠️ **单跳路由到"自身"**，非常数速率 | `main.rs:262-291` |
| 覆盖流量恒定速率 | ❌ 随机间隔 2-6s（非常数） | 同上 |

---

## 6. 测试状态总表

| Crate | 测试数 | 通过 | 失败 | 崩溃 | 说明 |
|-------|--------|------|------|------|------|
| aetheris-core | 25 | 25 | 0 | 0 | |
| aetheris-crypto | 41 | 41 | 0 | 0 | VDF + classgroup |
| aetheris-zkp | 129 | 129 | 0 | 0 | 含 IPA、Poseidon、Merkle、值守恒、combined |
| aetheris-recursive | 111 | 111 | 0 | 0 | 含 accumulator、CircuitAccumulate、VestaAccumulate |
| aetheris-node | 15 | 15 | 0 | 0 | 含 state、mixnet、adversarial_sim |
| aetheris-ffi | 3 | 1 | 0 | **1** | `test_genesis_import` 因空创世越界崩溃 |
| aetheris-wallet | 5 | 5 | 0 | 0 | 5 个 lib.rs 测试 |
| **总计** | **329** | **327** | **0** | **1** | 1 已知崩溃（`STATUS_STACK_BUFFER_OVERRUN`） |

---

## 7. 架构级偏差总结

### 7.1 白皮书要求但代码不存在

| # | 特性 | 白皮书 § | 重要性 |
|---|------|---------|--------|
| 1 | 真正递归 SNARK（证明嵌入前一个证明） | §3.1 | **核心** |
| 2 | Halo2 IPA Accumulation Scheme（folding + merge O(logN) + 结合律） | §8 | **核心** |
| 3 | 承诺的电路内绑定（Pedersen 而非加法） | §3.1 | **核心** |
| 4 | 主权日蚀检测（VDF 迭代 vs 区块计数） | §6.1 | **核心** |
| 5 | 主权重连恢复（VDF 重算） | §6.1 | **核心** |
| 6 | Sphinx 数据包格式 | §6.2 | HIGH |
| 7 | 最小手续费 / 每字节费率 | §5.4 | HIGH |
| 8 | Loopix 泊松覆盖流量 | §6.2 | MEDIUM |
| 9 | 独立验证器 CLI 模式 | §2 | MEDIUM |

### 7.2 白皮书要求但代码有 Bug

| # | 特性 | Bug 描述 | 严重度 |
|---|------|---------|--------|
| 1 | 难度自平衡 | `consensus.rs` 和 `vdf.rs` 限制语义不同→共识分裂风险 | **HIGH** |
| 2 | 空创世 | `state.rs` 拒绝且 `aetheris_import_wallet` 崩溃 | **HIGH** |
| 3 | 数学仲裁排序键 | 使用 `blake3(serialized_block)` 非 `blake3(prev_hash∥vdf)` | MEDIUM |
| 4 | 基本判别式 | 平方因子检查仅覆盖前 20 个素数 | MEDIUM |
| 5 | Hash-to-Form 算法 | 与 `math_spec.md` 描述不一致（数学等价） | LOW |
| 6 | 视图密钥派生 | FFI=blake3 vs CLI=Keccak256，不兼容 | HIGH |

### 7.3 白皮书已降级为 Future（不应出现在代码中）

| # | 特性 | 白皮书 § | protocol_design_ruling.md 裁决 |
|---|------|---------|-------------------------------|
| 1 | ZK-VM / RISC-V 智能合约 | §3.2 | 降级→future |
| 2 | FHE 全同态加密 | §3.2 | 降级→future |
| 3 | 后量子格密码 | §6.2 | 降级→future |
| 4 | 形式化验证 Coq/TLA+/Lean | §7+ | 降级→Phase E |

---

## 8. 子系统可靠度排名

| 排名 | 子系统 | 白皮书对齐度 | 测试覆盖率 | 关键问题数 | 评价 |
|------|--------|------------|-----------|-----------|------|
| 🥇 | VDF + 类群（`aetheris-crypto`） | ~90% | 41 tests, all pass | 2 个中/低 | 数学上最可靠的模块 |
| 🥈 | ZK 电路基础约束（`aetheris-zkp`） | ~65% | 129 tests, all pass | 2 个高 | 四个基本约束正确但承诺绑定缺失 |
| 🥉 | 节点共识（`aetheris-node`） | ~60% | 15 tests, all pass | 1 个共识 BUG + 多处缺失 | 基础链路打通但有多处偏离 |
| 4 | 递归证明（`aetheris-recursive`） | ~40% | 111 tests, all pass | 3 个架构级 | 功能存在但核心架构与白皮书不同 |
| 5 | FFI 桥（`aetheris-ffi`） | ~60% | 1/3 通过+1 崩溃 | 2 个严重 | 发送/扫描链路正确但创世导入崩溃 |
| 6 | 钱包 CLI（`aetheris-wallet`） | ~35% | 5 tests, all pass | 4 个严重 | 加密虚假、发送/扫描都是本地操作 |
| 7 | 网络层 Mixnet（`aetheris-node/mixnet`） | ~30% | 2 tests, all pass | 3 个缺失 | 自定义洋葱路由，非标准 Loopix/Sphinx |
| 🥇 | **全系统** | **~55%** | **296/299 + 1 崩溃** | **11 个关键/高** | 基础搭建完成但架构偏离和漏洞集中 |

---

## 附录 A：故障注入验证—发现即关闭的严重问题

以下问题在审计过程中通过读取代码发现且可独立验证，不依赖任何测试结果：

| ID | 模块 | 问题 | 位置 | 验证方式 |
|----|------|------|------|---------|
| F-1 | state | 空创世 `transactions.len() != 2` 拒绝 | `state.rs:292-294` | 静态代码分析：`create_genesis_block()` 返回 `vec![]`，但验证路径要求 `len == 2` |
| F-2 | FFI | 导入空创世时 `transactions[0]` 越界 panic | `ffi/lib.rs:1084` | 静态代码分析：空 vec 上索引 0 |
| F-3 | consensus | 难度重定向单限制 vs 双限制 | `consensus.rs:80-97` vs `vdf.rs:171-188` | 双路径对比：一个限制 actual_time 和 result，另一个只限制 actual_time |
| F-4 | adversarial_sim | 测试用 `blake3(vdf_result)` 而非实际仲裁器的 `block_hash` 算获胜者 | `tests/adversarial_sim.rs:49-57` | 测试通过纯属偶然（hash 值恰好匹配） |

---

## 附录 B：关键文件索引

| 文件 | 行数 | 内容 |
|------|------|------|
| `whitepaper.md` | 217 | 设计哲学与技术规格——唯一对标标准 |
| `protocol_design_ruling.md` | 465 | 核心协议 vs future 边界（§1.3），曲线/递归/经济终裁 |
| `aetheris-crypto/src/vdf.rs` | 589 | Wesolowski VDF solve/verify + 难度重定向 |
| `aetheris-crypto/src/classgroup.rs` | 779 | 虚二次域类群 Form 运算（compose/reduce/pow/hash-to-form） |
| `aetheris-zkp/src/halo2_pasta.rs` | 2690 | 值守恒电路 + 组合电路 + 屏蔽交易 FFI |
| `aetheris-zkp/src/combined_circuit.rs` | 1299 | 成员+nullifier+值守恒合并电路 |
| `aetheris-zkp/src/ipa/` | ~800 | IPA 承诺方案（prover/verifier/commitment/strategy） |
| `aetheris-recursive/src/accumulator.rs` | 716 | 线性组合累加器（非 IPA folding） |
| `aetheris-recursive/src/circuit_accumulate.rs` | 740 | AccumulatorCircuit——递归区块证明电路 |
| `aetheris-recursive/src/prove_recursive.rs` | 1279 | prove_block_recursive / verify_block_recursive |
| `aetheris-node/src/state.rs` | 1085 | 状态管理、apply_block、主权验证、创世哈希 |
| `aetheris-node/src/consensus.rs` | 110 | 数学仲裁器、难度计算 |
| `aetheris-node/src/mixnet.rs` | 68+ | 洋葱路由（非 Loopix/Sphinx） |
| `aetheris-ffi/src/lib.rs` | 2348 | FFI 桥、钱包发送/扫描、挖矿 |
| `aetheris-wallet/src/main.rs` | 315 | CLI 钱包（AETHSCAN 占位、文件级发送/扫描） |

---

## 附录 C：本文件更新规则

1. **仅当代码发生实质性变更时更新本文件**
2. 更新时标注日期和 commit hash
3. 每个状态变更必须附加代码位置的精确引用
4. 本文件 **取代** 所有先前存在的进度文档 (`progress.md`, `FINAL_ARCHITECTURAL_PLAN.md`, `blockers_and_gaps.md`, `diagnosis.md`, 各子 crate `*_plan.md`)
5. 与白皮书声明冲突的代码或文档以本文件为最终仲裁
