# IPA + PLONK Agent Debug Guide

## 目的

本文件面向后续 Agent，用于指导排查 `aetheris-zkp` 中 `IPA commitment scheme` 接入 PSE Halo2/PLONK 时出现的 `quotient / vanishing mismatch` 问题。

目标不是“让测试看起来通过”，而是：

1. 精确定位 `f_prover(x) != f_verifier(x)` 的分叉点。
2. 防止再次引入 `transcript_h_eval` 之类的伪修复。
3. 保证排查顺序可重复、结论可验证、日志可对比。

## 必读前提

- 先读 `AGENTS.md`
- 再读 `ISSUE_IPA_PLONK_INTEGRATION.md`
- 如需额外上下文，可读 `diagnosis.md`

当前已确认事实：

- IPA primitive 单独测试可通过。
- `IPA + PLONK` 真正坏在 vanishing / quotient 语义，不在基础 IPA opening。
- 任何把 verifier 改成直接信任 prover transcript 里的 `h_eval` 的做法，都是 soundness hole。

## 严禁事项

- 严禁恢复或引入任何“直接使用 `transcript_h_eval` 绕过 `expected_h_eval`”的逻辑。
- 严禁把“测试全绿”作为成功标准，除非确认测试语义没有被改写成假通过。
- 严禁一开始就盲改 IPA folding、theta 顺序、MSM scale 方向。
- 严禁在未加日志对账前，直接大改 `evaluate_h`、`permutation`、`domain` 变换代码。
- 严禁把 `halo2_pasta.rs` 当前 harness 的通过，解释成“业务电路正确”。

## 当前基线

当前代码已经做了两件事：

1. verifier 重新强制校验 `expected_h_eval == h_eval_from_transcript`
2. `halo2_pasta` 相关测试改成 fail-closed，避免伪绿

因此，后续 Agent 不需要再做“拆除绕过逻辑”这一步，除非有人又把它加回去了。

## 涉及的关键文件

- `aetheris-zkp/vendor/halo2/halo2_backend/src/plonk/vanishing/prover.rs`
- `aetheris-zkp/vendor/halo2/halo2_backend/src/plonk/vanishing/verifier.rs`
- `aetheris-zkp/vendor/halo2/halo2_backend/src/plonk/evaluation.rs`
- `aetheris-zkp/vendor/halo2/halo2_backend/src/plonk/permutation/prover.rs`
- `aetheris-zkp/vendor/halo2/halo2_backend/src/plonk/permutation/verifier.rs`
- `aetheris-zkp/vendor/halo2/halo2_backend/src/poly/domain.rs`
- `aetheris-zkp/vendor/halo2/halo2_backend/src/plonk/prover.rs`
- `aetheris-zkp/vendor/halo2/halo2_backend/src/plonk/verifier.rs`
- `aetheris-zkp/src/ipa/prover.rs`
- `aetheris-zkp/src/ipa/verifier.rs`
- `aetheris-zkp/src/ipa/strategy.rs`
- `aetheris-zkp/src/halo2_pasta.rs`

## 问题定义

数学上应当满足：

```text
h(X) = f(X) / (X^n - 1)
```

因此在 challenge point `x` 上必须满足：

```text
f_prover(x) = h_eval_from_transcript * (x^n - 1)
f_verifier(x) = expected_h_eval * (x^n - 1)
f_prover(x) == f_verifier(x)
```

当前已知坏态是：

```text
expected_h_eval != h_eval_from_transcript
```

这说明 bug 只能在下列两类中：

1. prover 的 `evaluate_h` / coset / quotient / truncate 生成了错误的 `h(X)`
2. verifier 的表达式求值顺序、计数、或公式，与 prover 实际构造的 `f(X)` 不一致

## 排查总顺序

必须按下面顺序查，不要跳步。

### Step 1：先确认是“语义错”，不是“绕过没拆干净”

执行：

```bash
cargo test --package aetheris-zkp
```

期待：

- `aetheris-zkp` 测试通过
- `halo2_pasta` 相关测试不是在证明“proof 可验证”，而是在证明“当前坏态会被拒绝”

如果你看到“valid proof roundtrip 成功”之类测试重新出现，需要立刻审查：

- `plonk/vanishing/verifier.rs`
- `plonk/verifier.rs`
- `aetheris-zkp/src/halo2_pasta.rs`

### Step 2：缩小到最小复现面

优先使用最简单、最少 feature 的路径复现：

```bash
cargo test --package aetheris-zkp halo2_pasta::tests::test_valid_proof_is_rejected_until_ipa_plonk_quotient_mismatch_is_fixed -- --nocapture
```

原因：

- `halo2_pasta` 当前没有 lookup/shuffle 复杂逻辑作为主干扰项
- 主要复杂来源是 custom gates + permutation + vanishing
- 如果最小路径都坏，先别怀疑 lookup/shuffle

### Step 3：优先检查 permutation，不要先查 lookup/shuffle

当前最值得优先怀疑的是 permutation 路径，原因如下：

- `halo2_pasta` 电路没有 lookup/shuffle 主约束
- custom gates 很少，公式也直观
- equality / copy 会强依赖 permutation
- `evaluate_h` 中 permutation 逻辑与 verifier permutation 表达式是三地实现：
  - prover 直接构造 permutation grand product
  - verifier 直接用 opening values 求表达式
  - `evaluate_h` 在 extended coset 域中又实现了一次

任何一个地方对以下内容不一致，都可能造成当前 bug：

- `l_0`
- `l_last`
- `l_blind`
- `l_active_row`
- `delta` 幂次
- `omega^last`
- chunk 边界

### Step 4：只有在语义对不上时，才去看 IPA opening

不要一开始就看：

- `L_i / R_i`
- `x_i`
- `a_final`
- transcript 顺序

这些在当前问题里是后验检查，不是首因排查点。

## 建议的日志策略

不要只打 transcript 日志，要打“语义日志”。

### A. Query-level 日志

在：

- `aetheris-zkp/src/ipa/prover.rs`
- `aetheris-zkp/src/ipa/verifier.rs`

记录每个 unique point 的：

```text
point
query_count
query_index
commitment_kind = Commitment | MSM
eval
theta_power
poly_len
```

目的不是证明 IPA 正确，而是验证：

```text
prover 认为自己打开的对象
==
verifier 重建出来的对象
```

### B. Vanishing-level 日志

在：

- `plonk/vanishing/prover.rs`
- `plonk/vanishing/verifier.rs`

记录：

```text
xn
h_eval_from_transcript
expected_h_eval
fx_prover = h_eval * (xn - 1)
fx_verifier = expected_h_eval * (xn - 1)
```

如果这里就分叉，先不要往 IPA opening 深挖。

### C. Permutation 子项日志

最重要。

在：

- `plonk/evaluation.rs`
- `plonk/permutation/verifier.rs`

把 permutation 相关子表达式拆开分别打出来：

1. `l_0 * (1 - z_0)`
2. `l_last * (z_l^2 - z_l)`
3. `l_0 * (z_i - z_{i-1}(omega^last X))`
4. active-row 主乘积约束

要求：

- prover extended-domain 路径要能单独输出每个子项在 challenge `x` 处的值
- verifier 路径也要输出同名子项
- 日志命名必须一致，便于 diff

### D. Quotient 形态日志

在：

- `plonk/evaluation.rs`
- `poly/domain.rs`

记录：

```text
quotient_poly_degree
domain.k
domain.extended_k
extended_len
h_coeff_len_before_truncate
h_coeff_len_after_truncate
```

目标是排除：

- truncate 提前截断
- `quotient_poly_degree` 双方不一致
- extended domain 大小不符

## 推荐的排查分叉树

### 分支 A：如果 `f_verifier(x)` 与“同公式、直接在 prover 侧按 verifier 方式算出来的值”一致

说明：

- verifier 表达式求值大概率没问题
- bug 更可能在 `evaluate_h -> divide_by_vanishing_poly -> extended_to_coeff -> truncate`

下一步查：

- coset shift
- extended inverse FFT
- truncate
- h piece 重组

### 分支 B：如果 prover 侧“按 verifier 公式直接求值”仍然和 verifier 不一致

说明：

- 问题可能在 query index、表达式顺序、rotation、或 column lookup 映射

下一步查：

- `QueryBack.index`
- `ConstraintSystemBack` 查询收集顺序
- `gate / permutation / lookup / shuffle` 迭代顺序

### 分支 C：如果 `expected_h_eval == h_eval_from_transcript`，但 opening 仍失败

这时才值得深挖：

- IPA theta folding
- query ordering
- MSM commitment reconstruction
- transcript challenge 顺序

但在当前问题里，这不是最优先路线。

## 必须新增或维护的测试类型

### 1. Fail-closed 测试

必须保留至少一个测试，明确证明：

> 当前坏态下，valid proof 也必须被 verifier 拒绝

否则后续很容易有人为了“让 CI 过”又把绕过逻辑塞回去。

### 2. IPA multi-query 单元测试

保留并扩展：

- 同一点多 query
- `h_poly + random_poly`
- `MSM commitment + explicit combined polynomial`

这个测试要回答：

```text
IPA opening 层本身是否正确
```

### 3. 子项对账测试

建议新增 debug-only 或普通单测：

- 只跑一个极小 permutation 电路
- 分别输出 prover/verifier 的 permutation 子项值
- 要求逐项相等

这类测试比“整条 proof 过不过”更有定位价值。

## 修改代码时的原则

- 一次只动一个层次：
  - 要么只加日志
  - 要么只修 permutation
  - 要么只修 quotient 变换
- 不要把“加日志”和“大改公式”混在一次提交里
- 每次修改后都必须跑：

```bash
cargo check --workspace
cargo test --package aetheris-zkp
```

如改到 workspace 公共逻辑，再补：

```bash
cargo test --workspace --lib
```

## Agent 输出要求

排查阶段的 Agent 输出应包含：

1. 复现命令
2. 观察到的关键数值
3. 当前排除的假设
4. 剩余最可能的 1 到 3 个根因
5. 下一步最小行动

不要输出空泛结论，例如：

- “可能是 transcript 顺序问题”
- “可能是 MSM 有 bug”

必须带文件路径和具体表达式类别。

## 当前建议的首要行动

如果你是新的 Agent，直接从这里开始：

1. 跑最小 fail-closed 测试，确认基线一致
2. 在 `permutation verifier` 和 `evaluation.rs` 中加入逐子项日志
3. 只比较 permutation 子项，不先碰 IPA opening
4. 找到第一个不一致的子项后，再决定修 `permutation` 还是修 `domain` 变换

## 成功标准

只有同时满足以下条件，才算真正修好：

1. `expected_h_eval == h_eval_from_transcript`
2. `valid proof` 在 `halo2_pasta` 路径下被 verifier 接受
3. fail-closed 测试被替换成真正的正向 roundtrip 测试
4. `cargo check --workspace` 通过
5. `cargo test --workspace --lib` 通过
6. 没有重新引入任何“信任 prover transcript h_eval”的逻辑

## 最后提醒

这个问题是协议集成层问题，不是普通业务 bug。

请始终记住：

```text
先证明 prover 和 verifier 在语义上定义的是同一个 f(X)
再证明 IPA opening 在打开同一个对象
不要反过来
```
