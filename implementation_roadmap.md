# Aetheris (AET) 生产成熟路线图

**评估版本**: Alpha-3 (2026-06-01)
**目标**: Mainnet Beta — 预计 6-8 个月
**MVP (Testnet)**: 预计 4 个月

---

## Phase A — 安全加固 (Security Hardening, 1-2 月)

| # | 项目 | 优先级 | 状态 | 说明 |
|---|------|--------|------|------|
| A-1 | 第三方安全审计 | P0 | ❌ | 聘请外部团队审计所有 7 crate + FFI boundary |
| A-2 | FFI 敏感数据 Zeroize | P1 | ✅ | `USER_PASSWORD` 从全局 `String` 改为 `Zeroizing<String>` |
| A-3 | 统一密钥派生 | P1 | ❌ | FFI (Keccak256) 与钱包 (blake3) viewing key 派生统一 |
| A-4 | 移除二进制测试种子 | P1 | ✅ | `TEST_SEED_MNEMONIC`/`TEST_DEV_MNEMONIC` 移至 `#[cfg(debug_assertions)]` |
| A-5 | C# 前端安全整治 | P1 | ⏸️ | 桥密钥会话化 + 移除 `aetheris_get_genesis_phrase()` |
| A-6 | `unwrap_or(Fr::zero())` 审计 | P2 | ✅ | 已全部替换为 blake3 hash + mask + `expect()` |

## Phase B — 性能工程 (Performance Engineering, 1-2 月)

| # | 项目 | 状态 | 说明 |
|---|------|------|------|
| B-1 | Class Group VDF 迁移 | ⏳ | RSA-2048 → 虚二次域类群 Cl(D)，自实现二元二次型合成/规约算法 (~290 行纯 Rust)，消除信任假设 |
| B-2 | Halo2 证明基准 | ✅ | 76 测试 22s／26× 加速：Profile 优化 + Poseidon r_f 256→8 + k 18→14 + V1 planner （待切换） |
| B-3 | sled DB 批量写入 | ❌ | 当前每区块独立 insert+flush；批量 checkpoint + WAL 优化，目标 10-100x |
| B-4 | 序列化基准测试 | ❌ | serde_json vs bincode vs protobuf 在 BlockProposal/交易集上的基准 |

## Phase C — 网络健壮性 (Network Robustness, 1-2 月)

| # | 项目 | 说明 |
|---|------|------|
| C-1 | Peer Score 实现 | gossipsub 评分配置 + 无效消息惩罚 + 自动断连 |
| C-2 | Gossip 协议规范对齐 | 实现 `AtomicProofGossip`/`AggregateProofGossip`、三级验证管道、深度优先转发 |
| C-3 | Bootstrap 节点 | ≥3 地理分布种子节点 + DNS 发现 + 持久 Peer ID |
| C-4 | NAT 穿透验收测试 | relay + dcutr 在不同网络拓扑下的功能验证 |
| C-5 | 覆盖流量参数化 | Loopix Mixnet cover traffic 频率/大小可配置 |

## Phase D — 协议完备性 (Protocol Completeness, 2-3 月)

| # | 项目 | 说明 |
|---|------|------|
| D-1 | 递归证明端到端测试 | `aetheris-recursive` 完整递归链路集成测试（当前仅单元测试） |
| D-2 | 激励模型 | 聚合节点奖励分配、交易费模型 |
| D-3 | 创世仪式 | 真正创世种子生成（非硬编码）、多方参与 Ceremony、公布 `EXPECTED_GENESIS_HASH` |
| D-4 | 区块格式版本化 | BlockHeader 添加 `version` 字段，支持向后兼容升级 |

## Phase E — 形式化验证 (Formal Verification, 2-3 月)

| # | 项目 | 说明 |
|---|------|------|
| E-1 | 递归聚合结合律证明 | `Aetheris_Recursive_Aggregation.v` 完善 Halo2 Accumulation Scheme 证明 |
| E-2 | TLA+ 并发模型 | VDF 发行 + 主权同步逻辑建模，验证日蚀定理 |
| E-3 | CI 验证门禁 | Coq 证明 + TLA+ 模型检查作为 CI 流程 |
| E-4 | Class Group VDF Coq 证明 | 证明二元二次型合成运算的正确性、Wesolowski 验证方程在 Cl(D) 上的可靠性、群阶 h(D) 在信息论意义上不可计算 |

## Phase F — 部署与运维 (Deployment & Ops, 1 月)

| # | 项目 | 说明 |
|---|------|------|
| F-1 | 多平台构建 | Linux x86_64/aarch64、macOS、Windows MSVC + 代码签名 |
| F-2 | 升级机制 | 节点版本协商 + 向后兼容区块格式 |
| F-3 | 监控集成 | Prometheus metrics：VDF 时间、网络延迟、内存、Peer 数 |
| F-4 | 文档 | RPC API 文档、CLI 手册、节点运维指南 |

## Phase F — 部署与运维 (Deployment & Ops, 1 月)

| # | 项目 | 说明 |
|---|------|------|
| F-1 | 多平台构建 | Linux x86_64/aarch64、macOS、Windows MSVC + 代码签名 |
| F-2 | 升级机制 | 节点版本协商 + 向后兼容区块格式 |
| F-3 | 监控集成 | Prometheus metrics：VDF 时间、网络延迟、内存、Peer 数 |
| F-4 | 文档 | RPC API 文档、CLI 手册、节点运维指南 |

---

## 时间线

```
Month 1-2:  A(安全) + B(性能)          ████████░░░░░░░░░░░░░░░░░░░░
Month 2-4:  C(网络) + D(协议)           ░░░░████████████░░░░░░░░░░░░
Month 4-6:  D(协议) + E(形式化验证)      ░░░░░░░░░░████████████░░░░░░
Month 6-8:  E(验证) + F(部署)           ░░░░░░░░░░░░░░░░░░██████████
           ──────────────────────────────────────────────────────
MVP:        A-1~5 + B-1 + C-1~3 + D-3   ████████████████░░░░  ~4月
Testnet:    MVP + C-4~5 + D-1            ████████████████████░░  ~5月
Mainnet:    All phases                   ████████████████████████  ~8月
```

## 关键里程碑

- **Testnet MVP** (4 月): 单节点主权验证 + P2P 同步 + 基础挖矿端到端流程
- **Testnet Full** (5 月): 多节点网络 + Gossip 聚合 + 递归证明
- **Mainnet Beta** (8 月): 第三方审计通过 + 形式化验证 + 创世仪式 + 部署基础设施
