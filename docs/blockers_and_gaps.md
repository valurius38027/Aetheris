# Blockers & Gaps — 2026-06-08

## 🔴 阻塞级

### 1. IPA-PLONK h_eval 约束已禁用
- **文件**: `ISSUE_IPA_PLONK_INTEGRATION.md`
- **问题**: `f_prover(x) ≠ f_verifier(x)`，约束检查被绕过。所有 IPA 证明缺少完整 PLONK 验证。
- **根因**: IFFT 输出在索引 4094+ 处产生系统性 DC 伪影，h_poly 含虚假度数。
- **状态**: 根因未修复。extended_k=13 (qpd+1) 已保留为正确性改进，但未解决 mismatch。

### 2. Phase 1.12 电路内 IPA 验证器 ~50%
- **完成**: §1.12a (NonNativeFqChip) ✅, §1.12b (XOR/rot) ✅, §1.12c (wrapping add) ✅, §1.12d1 (transcript) ✅, §1.12d2 (init bind) ✅
- **未完成**: §1.12d3 (12 轮 Blake2b 混合  ❌), §1.12d4 (Challenge255 ❌), §1.12d5 (IpaVerifierCircuit ❌), §1.12e (opt ❌)
- **预估**: 还需 2-3 个月研究级工作

## 🟠 高优先级

### 3. C-2: 缺少输入成员/所有权/nullifier 正确性证明 (P1)
- 交易只约束 output commitment，不约束 input 来源
- 伪造余额/无源资金风险

### 4. C-5: DB 写入顺序——先写入后检查 nullifier (P2)
### 5. H-1: state_root 未被验证为真实状态根 (P2)
### 6. H-2/M-1: Mempool→区块管道断裂 (P3)

## 🟡 Phase 2-4 完全未开始 (0%)

| Phase | 范围 | 状态 |
|-------|------|------|
| Phase 2 (钱包+隐私) | 加密发送、P2P 扫描、隐身地址、BIP32 | ❌ |
| Phase 3 (网络健壮) | Peer 评分、引导节点、NAT 穿透 | ❌ |
| Phase 4 (生产就绪) | Sled 批量写入、二进制分发、监控 | ❌ |

## 🟢 文档与实现不一致 (E-1 ~ E-11)

虚构或不存在的功能: FHE, 后量子格加密, ZK-VM/RISC-V, 形式化 Coq 证明, 递归 SNARK (实际是 Merkle 哈希链)
