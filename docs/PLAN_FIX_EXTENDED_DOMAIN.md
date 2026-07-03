# Plan: Fix IPA-PLONK Quotient Mismatch via Extended Domain Resizing

## **⚠️ OBSOLETE — Phase 3 disproved the aliasing theory. See `ISSUE_IPA_PLONK_INTEGRATION.md` for latest findings.**

## Original Root Cause (DISPROVEN)

`domain.rs:48-50` 的扩展域大小公式不足：

```rust
// 当前（错误）
while (1 << extended_k) < (n * quotient_poly_degree) {
    extended_k += 1;
}
```

只保证能容纳 h(X)（次数 `n*qpd-1`），但 **f(X) = h(X)*(Xⁿ-1)** 的次数是 `n*(qpd+1)-1`，需要 `extended_n ≥ n*(qpd+1)` 才能无混叠采样。

**This theory was tested with extended_k=13 (8192 points) and DISPROVEN. The mismatch persists identically. The real root cause is a systematic DC artifact in the IFFT output at indices ≥ 4094.**

---

## Fix

### Step 1 — 修改扩展域大小公式（1 行）

文件：`aetheris-zkp/vendor/halo2/halo2_backend/src/poly/domain.rs:48-50`

```diff
- while (1 << extended_k) < (n * quotient_poly_degree) {
+ while (1 << extended_k) < (n * (quotient_poly_degree + 1)) {
```

加上 **+1** 后，extended_k 扩展一位（qpd=2 时：12→13），
extended_n 从 4096 翻倍到 8192，消除 f 的混叠。

### Step 2 — 连锁更新 t_evaluations 预计算

`t_evaluations` 数组大小现在应该是 `extended_n / n = 4`（之前是 2）：
- 文件：`domain.rs:92-93` 的 `step = extended_omega.pow_vartime([n, 0, 0, 0])`
- `cur` 循环逻辑需要对最多 4 个值求值

检查 `domain.rs:86-100`：
```rust
let mut t_evaluations = Vec::with_capacity(1 << (extended_k - k));
```
`extended_k - k = 1` 时 capacity=2；`extended_k - k = 2` 时 capacity=4。这行会自动适应，无需修改。

### Step 3 — 扩展域 FFT 大小的兼容性

`best_fft`（FFT 实现）支持任意 2 的幂大小，8192 是 2¹³，完全受支持。

`F::ROOT_OF_UNITY` 必须支持 2¹³ 次单位根。Pallas 的 `S ≥ 32`（ZCash 标准），13 ≤ 32 ✓。

### Step 4 — 断言检查

`domain.rs:54`：
```rust
assert!(extended_k <= F::S);
```
extended_k=13 ≤ 32，正常通过。无需修改。

### Step 5 — 测试验证

1. `cargo check -p aetheris-zkp` — 编译无错误
2. `cargo test -p aetheris-zkp --lib` — 40 测试全过
3. 检查 `[fx-MISMATCH]` 不应再出现（f_prover 与 f_direct 匹配）
4. 如果 IPA 验证通过，更新 `test_valid_proof_is_rejected_until_ipa_plonk_quotient_mismatch_is_fixed` 为接受成功

---

## 影响分析

| 维度 | 变化 | 评估 |
|------|------|------|
| 编译 | 无 | 源码级改动，无新依赖 |
| FFT 计算 | 4096 → 8192（2x） | ~15ms → ~30ms，可接受 |
| `t_evaluations` 数组 | 2 → 4 个值 | 极小 |
| h_X 构造 | 不变 | h_pieces 仍然 n*qpd=4096 元素 |
| IPA 打开向量 | 不变 | 仍然是 n=2048 |
| 证明大小 | 不变 | h_commitments 仍然是 2 个点 |
| 验证时间 | 略微增加 | extended FFT 在 verifier 侧也用，但只在 keygen 时发生一次 |
| CRS | 兼容 | 只需要 2k 次幂，Pasta 原生支持 |
| BN254/KZG 后端 | 无影响 | 共用同一个 domain.rs，也会获得正确 extended_k |
| 递归电路 (Vesta) | 同样修正 | domain.rs 是泛型代码，Pallas 和 Vesta 共用 |

---

## 回归风险

唯一风险：**FFT 大小翻倍增加了计算时间**。在证明生成的热路径上：
- `evaluate_h`（coset 表达式求值）：4096→8192 点，2x
- `divide_by_vanishing_poly`：4096→8192 次除法，2x
- `extended_to_coeff`（IFFT）：4096→8192 点 FFT，2x
- `coeff_to_extended`（FFT，其他地方调用）：同样 2x

整体证明时间增加约 2x（对当前电路 <50ms）。如果性能不可接受，后续可以优化（如只对 h_upper 做 FFT）。

---

## 验证标准

1. ✅ `cargo check --workspace` 无错误
2. ✅ `cargo test -p aetheris-zkp --lib` 全部通过且无 `[fx-MISMATCH]` 输出
3. ✅ IPA/Pasta 验证不再返回 `ConstraintSystemFailure`
4. ✅ `test_valid_proof_is_rejected_until_ipa_plonk_quotient_mismatch_is_fixed` 改为 expect accept
5. ✅ 使用 `--nocapture` 确认 `DEGREE-DIAG` 显示 h_poly[4094]=h_poly[4095]=0

---

## 文件变更清单

| 文件 | 变更 | 类型 |
|------|------|------|
| `aetheris-zkp/vendor/halo2/halo2_backend/src/poly/domain.rs:49` | `qpd` → `qpd+1` | 1 行修改 |
| `ISSUE_IPA_PLONK_INTEGRATION.md` | 添加修复状态 | 文档更新 |
| `PLAN_FIX_EXTENDED_DOMAIN.md` | 本计划文件（完成后删除或归档） | 新增 |
