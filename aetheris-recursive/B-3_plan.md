> **⚠️ SUPERSEDED** — This document is superseded by
> [`FINAL_ARCHITECTURAL_PLAN.md`](../FINAL_ARCHITECTURAL_PLAN.md) (§C).
> Do not implement from this document without cross-referencing the final plan.

# Phase 1.4 B-3: CircuitAccumulate — Inductive Recursive Chain

> **Status**: Planning
> **Depends on**: B-2 (VestaAccumulateChip, VestaIpaChip, VestaEccChip, VestaFqChip, Blake2b gadgets)
> **Replaces**: Current `verify_block_recursive_proof` placeholder (which uses PallasAccumulateChip host-precomputed approach)
> **Goal**: Build `CircuitAccumulate` — a Halo2 IPA proof over `Circuit<Fq>` (Vesta) that inductively proves the accumulator state transition `Q_old → Q_new` across all transactions in a block.

---

## 1. Architectural Context

### Protocol Design (§2.2)

Per `protocol_design_ruling.md` §2.2 (Layer 3):

```
Accumulator: Acc = (Q, transcript_state)
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

**曲线放置** (§1.1):
| 层次 | 曲线 | 电路域 |
|------|------|--------|
| 外电路（交易守恒） | **Pallas** | `Circuit<Fp>` |
| **递归电路（递归积累）** | **Vesta** | `Circuit<Fq>` |

Pasta 2-cycle: Pallas 基场 Fp = Vesta 标量场 Fp, Vesta 基场 Fq = Pallas 标量场 Fq.
→ 递归电路在 Vesta 上运行，所有累加器操作（Q 坐标、challenge 标量）都是原生 Fq。**完全消除 NonNativeChip**。

### 偏差说明：Accumulate 第 1 步（In-Circuit IPA 验证）延迟

设计文档第 1 步要求 "验证 π 对当前公开输入的可靠性（Halo2 verify）"，即在电路内验证每笔交易的 IPA 证明。当前 B-3 **不做这一步**，原因：

1. **内层证明在 Pallas 上**：`π_i` 是 Pallas IPA 证明，涉及 Pallas 点（坐标 Fp）。在 Vesta 电路（`Circuit<Fq>`）中验证 Pallas 点需要非原生 Fp 算术，~150 行/操作
2. **开销过大**：每笔交易需要 ~O(k) 个非原生点运算（k=17 ∼ 131k 行），100 笔交易的区块 > 13M 行 → 不可证明
3. **Pasta 2-cycle 只解决标量问题**：IPA 挑战 `x_i` 是 Fq（Vesta 原生），但点坐标 Fp 仍需非原生处理

**本阶段 B-3 实现步骤 2-4（Q 更新 + transcript 链）**，步骤 1 延迟到 Phase 1.6（ISSUE-1.4.A），届时有两种方案：
   - **方案 A**：在 Vesta 电路内非原生验证 Pallas IPA（用精简版 NonNativeFpChip，仅坐标层）
   - **方案 B**：将内层电路改为 Vesta（所有 IPA 在 Vesta 上，原生验证）——需要改 `aetheris-zkp`

**安全模型**：信任聚合器已在外电路验证过内层证明，任何人可通过 O(n) 重放审计。

### Current Gap (S5-a/b Placeholder)

The current `verify_block_recursive_proof` (prove_recursive.rs:94-111) uses `RecursiveProofCircuit` with `PallasAccumulateChip` — a host-precomputed Pallas IPA verifier. It extracts `acc.Q` from the accumulator and uses it as a "commitment" in a single IPA equation. This does NOT prove the accumulator transition — it's architecturally incorrect.

### B-3 Correct Design

| Aspect | Placeholder (S5-b) | CircuitAccumulate (B-3) |
|--------|-------------------|-------------------------|
| Curve | Pallas (non-native Fp over Fq) | Vesta (native Fq) |
| Proves | Single IPA equation on Q | Q_old → Q_new transition |
| Challenge | Host precomputed | In-circuit via Blake2b |
| hash-to-curve | Host side | In-circuit NUMS |
| Accumulator | Used as input only | Actively updated |
| Public instances | (commitment, state_root) | (Q_new, transcript_new) |

---

## 2. Architecture

### 2.1 Pasta 2-Cycle Role

```
Layer 1: Per-tx Conservation Proofs
  Circuit<Fp> (Pallas)  →  IPA proof (EpAffine)
  Proves: value conservation for one transaction
  (Inner IPA proofs verified out-of-circuit per §偏差说明)

Layer 2: Accumulator Reference Implementation
  Vesta curve (EqAffine): Q = Σ challenge_i · pi_commitment_i
  Matches protocol_design_ruling.md §2.2 accumulator spec (steps 2-4)
  hash_to_curve targets Vesta generator

Layer 3: CircuitAccumulate (THIS — B-3)
  Circuit<Fq> (Vesta)  →  IPA proof (EqAffine)
  Proves: accumulator transition on Vesta curve
  Re-derives challenge + pi_commitment in-circuit
  Constrains Q_new = Q_old + Σ challenge_i · pi_commitment_i
  NOTE: Step 1 (in-circuit IPA verification per design doc) deferred to Phase 1.6
```

**Key change**: The accumulator `Q` moves from Pallas to Vesta. This is architecturally sound:
- The reference `AccumulatorIPA` (accumulator.rs) uses Pallas — this was built before B-2's Vesta-native decision and before protocol_design_ruling.md was finalized. B-3 refactors it to Vesta.
- B-3 makes the accumulator a Vesta point, using Vesta's native field Fq for all operations
- The hash-to-curve for `pi_commitment` targets Vesta (`EqAffine`) instead of Pallas (`EpAffine`)
- The Pasta 2-cycle property means: Vesta 标量场 = Pallas 基场 = Fp. 内层 IPA 挑战 x_i ∈ Fp 在 Vesta 电路中是非原生, 但本 B-3 不做 IPA 验证（见 §偏差说明）

### 2.2 Pipeline

```
Block txs → Proof bytes + output_commitments + public_amounts
                    │
                    ▼
        ┌────────────────────────┐
        │  Host: For each tx:    │
        │  1. inner_proof_hash   │  blake3(proof_bytes)
        │  2. commitment_hash    │  blake3(commitments || public_amount)
        │  3. inner_proof_hash_eff  XOR
        │  4. pi_commitment_seed  │  blake3(PI_DOMAIN || inner_proof_hash_eff)
        │  5. try-and-increment   │  (or SSWU2)
        │  6. challenge_seed      │  blake3(TRANSCRIPT_DOMAIN || transcript_old || inner_proof_hash_eff)
        └────────┬───────────────┘
                 │ witness data
                 ▼
        ┌────────────────────────┐
        │  CircuitAccumulate:    │
        │  • Constrain step 1-6  │  re-derive in-circuit
        │  • Q += challenge * pi │  VestaEccChip
        │  • transcript update   │  Blake2b gadget
        │  • depth += 1          │  Fq range check
        │  • Bind Q_new,         │
        │    transcript_new      │  instance columns
        └────────┬───────────────┘
                 │
                 ▼
        Recursive SNARK proof (EqAffine, constant size)
```

### 2.3 Trust Model

**Trusted-aggregator** (deviation from `protocol_design_ruling.md` §2.2 step 1): CircuitAccumulate does NOT re-verify the inner IPA proofs. It trusts that the host verified them via `accumulate_proof` (which calls Halo2 verifier). The circuit only constrains the accumulator Q update formula.

**Security guarantee**: Anyone can challenge the aggregator by replaying the accumulator chain (O(n) audit). The recursive SNARK provides O(1) verification for honest aggregator assumption + public auditability.

**Future upgrade** (ISSUE-1.4.A / Phase 1.6): Add in-circuit IPA verification for full trustlessness per design doc §2.2 step 1. Two candidate approaches:
- **A**: Non-native Pallas IPA verify inside Vesta circuit (coordinates Fp over Fq, ~150 rows/op, feasible for small blocks)
- **B**: Migrate inner proofs to Vesta circuit (all IPA native, no non-native ops, but changes aetheris-zkp)

---

## 3. Public Instances

```
Instance[0]   = Q_new.x     (Fq, native)
Instance[1]   = Q_new.y     (Fq, native)
Instance[2..3] = transcript_new (32 bytes → 2 Fq cells)
Instance[4]   = depth       (u32 as Fq)
```

**Total: 5 Fq cells per proof.**

The verifier checks these match the expected post-block accumulator state.

---

## 4. Implementation Steps

### B3-S1: hash_to_curve Gadget for Vesta

**Goal**: In-circuit NUMS try-and-increment producing a Vesta point from 32-byte `inner_proof_hash_eff`.

**Algorithm** (matching accumulator.rs lines 227-239):
```
seed = blake3(PI_COMMITMENT_DOMAIN || inner_proof_hash_eff)  // 32 bytes
counter = 0
loop:
  mixed = le_bytes(counter, 4) || seed[0..28]  // 32 bytes
  mixed_64 = mixed || [0u8; 32]                  // pad to 64 bytes
  c = Fq::from_uniform_bytes(&mixed_64)          // mod-q reduction
  pi = VestaGenerator * c                        // Vesta scalar mul
  if pi != identity: break
  counter += 1
```

**New file**: `aetheris-recursive/src/hash_to_curve.rs`

**Required**:
- `Blake2bCompressionCircuitChip` for seed derivation
- `VestaEccChip::scalar_mul` for generator multiplication
- Identity check: `x == 0 && y == 0`
- `MAX_ITER` constant (e.g., 5) — statistically negligible collisions

**Validation**: Output matches reference `AccumulatorIPA::hash_to_curve_pallas` but targeting Vesta generator.

---

### B3-S2: AccumulatorCircuit Struct + Config

**New file**: `aetheris-recursive/src/accumulator_circuit.rs`

**Struct**:
```rust
struct AccumulatorCircuit {
    // Witness data per tx (host-precomputed seeds, computed from proof bytes)
    txs: Vec<TxAccumulateWitness>,
    // Public output
    q_new: VestaPoint,
    transcript_new: [u8; 32],
    depth: u32,
}

struct TxAccumulateWitness {
    proof_bytes: [u8; PROOF_SIZE],
    output_commitments: Vec<[u8; 32]>,
    public_amount: i64,
    inner_proof_hash: [u8; 32],
    commitment_hash: [u8; 32],
    inner_proof_hash_eff: [u8; 32],
    pi_commitment_seed: [u8; 32],
    pi_commitment: VestaPoint,
    challenge_hash: [u8; 32],
    challenge: Fq,
    // Try-and-increment counter
    pi_counter: u32,
}
```

**Config columns**:
```
- q_old_x, q_old_y (Advice) — previous accumulator Q
- q_new_x, q_new_y (Advice) — new accumulator Q
- transcript_old (Advice, 2 cells) — previous transcript
- transcript_new (Advice, 2 cells) — new transcript
- inner_proof_hash_eff (Advice, 32 bytes decomposed) — witness
- pi_commitment_x, pi_commitment_y (Advice) — pi point
- challenge (Advice) — Fiat-Shamir challenge
- depth (Advice) — counter
- Selectors for per-tx gate
```

---

### B3-S3: Transcript Hash Chain

**Goal**: Re-derive the accumulator-level Fiat-Shamir challenge from `(transcript_old, inner_proof_hash_eff)`.

**Formula**:
```
challenge_hash = blake3(ACCUMULATOR_TRANSCRIPT_DOMAIN || transcript_old || inner_proof_hash_eff)
challenge = Fq::from_uniform_bytes(&[challenge_hash || [0u8; 32]])
```

**Reuse**: `VestaAccumulateChip::squeeze_challenges` logic for Blake2b compression.

**Transcript update**:
```
transcript_new = blake3(ACCUMULATOR_TRANSCRIPT_DOMAIN || transcript_old || challenge_repr || Q_compressed || inner_proof_hash_eff)
```

**Required**: Blake2b compression circuit + Fq byte assignment.

---

### B3-S4: Multi-Proof Iteration + Q Update

**Goal**: For each tx in the block, update Q and transcript.

**Per-tx constrained operations**:
```
1. Q_temp = Q_old + challenge * pi_commitment    (VestaEccChip::scalar_mul + point_add)
2. transcript = blake3(..., transcript_old, challenge, Q_temp, inner_proof_hash_eff)
3. depth += 1
```

**Iteration**: Fixed max number of txs per block (e.g., `MAX_BLOCK_TXS = 100`). Empty slots use identity Q and zero inner_proof_hash_eff (skipped via selector).

---

### B3-S5: Public Instance Binding

**Goal**: Constrain the final Q, transcript, depth to the circuit's public instances.

**Instance columns**:
```
instance[0] = q_new_x (or 3-limb Fq for precision)
instance[1] = q_new_y
instance[2] = transcript_lo (first 16 bytes as Fq)
instance[3] = transcript_hi (last 16 bytes as Fq)
instance[4] = depth as Fq
```

**Constraint**:
```rust
layouter.constrain_instance(q_new_x_cell, config.instance, 0);
layouter.constrain_instance(q_new_y_cell, config.instance, 1);
layouter.constrain_instance(transcript_lo_cell, config.instance, 2);
layouter.constrain_instance(transcript_hi_cell, config.instance, 3);
layouter.constrain_instance(depth_cell, config.instance, 4);
```

---

### B3-S6: prove_block_recursive + verify_block_recursive

**Replace the current placeholder** in `prove_recursive.rs`:

```rust
/// Produces a recursive SNARK attesting to the accumulator transition
/// for a block. Takes the per-tx witness data and the previous
/// accumulator state.
pub fn prove_block_recursive(
    params: &ParamsIPA<EqAffine>,
    pk: &ProvingKey<EqAffine>,
    txs: Vec<TxAccumulateWitness>,
    q_old: EqAffine,
    transcript_old: [u8; 32],
    depth_old: u32,
) -> Result<(Vec<u8>, AccumulatorCircuitOutput), Error> {
    // Build circuit, create_proof, return proof + (Q_new, transcript_new)
}

/// Verifies a block's recursive SNARK. O(1) — no accumulator chain replay.
pub fn verify_block_recursive_proof(
    params: &ParamsIPA<EqAffine>,
    vk: &VerifyingKey<EqAffine>,
    proof: &[u8],
    instances: &[Vec<Fq>],
) -> bool {
    // verify_proof_with_strategy
}
```

---

### B3-S7: Miner Integration

After folding the accumulator in `aetheris-ffi/src/lib.rs`:
1. Save per-tx witness data (proof bytes, output commitments, public amounts) from mempool
2. Call `prove_block_recursive` with accumulated state
3. Store recursive proof bytes and Q_new in block header
4. Set `block.header.recursive_proof = Some(proof_bytes)`

---

### B3-S8: FFI + Tests

- `aetheris_prove_block_recursive(proofs_hex, ...)` — C-ABI wrapper
- `aetheris_verify_block_recursive(proof_hex, instances_hex)` — C-ABI wrapper
- End-to-end: generate block txs → fold → prove → verify
- Regression: all existing tests pass

---

## 5. Implementation Order

```
B3-S1 (hash_to_curve)  ─→  B3-S2 (AccumulatorCircuit)  ─→  B3-S3 (transcript chain)
        │                                                        │
        └──────────────────────┬─────────────────────────────────┘
                               ▼
                        B3-S4 (multi-proof + Q update)
                               │
                               ▼
                        B3-S5 (public instance binding)
                               │
                               ▼
                        B3-S6 (prove/verify wrappers)
                               │
                               ▼
                        B3-S7 (miner integration)
                               │
                               ▼
                        B3-S8 (FFI + tests)
```

---

## 6. Verification Checklist

- [ ] `hash_to_curve` output matches host reference for known inputs
- [ ] `AccumulatorCircuit` constrains Q = Q + challenge * pi (rejects wrong Q)
- [ ] Transcript chain matches host reference
- [ ] Depth counter increments correctly
- [ ] Public instances bind correctly (corrupt instance → reject)
- [ ] `prove_block_recursive` produces valid proof
- [ ] `verify_block_recursive` accepts valid, rejects corrupt
- [ ] Miner produces blocks with valid recursive SNARKs
- [ ] FFI functions work
- [ ] `cargo check --workspace` passes
- [ ] All existing tests pass (no regression)
