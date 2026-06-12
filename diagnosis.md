这次读到了。`ISSUE_IPA_PLONK_INTEGRATION.md` 的核心结论很明确：**IPA 本身的单查询 opening 可以通过，但接入 PSE Halo2/PLONK 的 multiopen 路径后失败；失败点不是电路约束，而是 opening proof 的最终 MSM 检查。** 文档写明 `verify_proof_with_strategy(...) → Ok(strategy)`，随后 `strategy.finalize() → false`，也就是 PLONK 约束层已经通过，但 IPA 多点开启证明无效。

我的系统性诊断如下。

## 1. 这不是“电路没写对”，而是 commitment scheme 与 PLONK multiopen 协议的接口不闭合

文档里说 8 个 conservation proof roundtrip 测试失败，但 IPA 的基础测试、MSM、序列化、单查询 roundtrip 都通过。 这说明问题不在 `ValueConservationCircuit` 的基本约束，也不在 IPA primitive 的最小 open/verify 逻辑，而是在 **PLONK 把多个查询折叠为一次 multiopen 时，prover 和 verifier 对“被开启对象”的理解不一致**。

这个判断和代码吻合。`ProverIPA::create_proof_with_engine` 会按 evaluation point 分组，然后对同一点的多个 `ProverQuery` 做 theta folding：

```rust
combined = Σ theta^i * q.poly.values
```

也就是说，prover 侧实际证明的是若干 `q.poly` witness 多项式的 theta 线性组合。

而 verifier 侧并不直接拥有这些多项式，只能从 `VerifierQuery` 的 commitment reference 重建被开启承诺。它对两种情况分支处理：

```rust
CommitmentReference::Commitment(c)
CommitmentReference::MSM(msm_ref)
```

其中 `MSM` 分支会 clone 一个已有 MSM，再按 theta 幂 scale 后加入 combined commitment。

这就是最危险的接口缝隙：**prover 折叠的是 `q.poly.values`；verifier 折叠的是 `CommitmentReference` 所代表的 commitment/MSM。两边只有在 `q.poly` 与 `q.commitment` 表达的是完全同一个多项式时才成立。**

单查询测试通过，不足以证明这个接口成立；因为单查询绕过了 PLONK 中最复杂的 `h_poly + random_poly` multiopen 情形。

## 2. 最可能根因：h_poly 的 MSM commitment 与 prover 的 q.poly 表达不等价

issue 文档已经给出关键线索：失败只发生在同一点 `x` 上多个查询的 multiopen 路径，尤其是 `h_poly + random_poly`。

在 PLONK 里，`h_poly` 往往不是一个普通单承诺多项式，而是 quotient polynomial 的分片组合。verifier 侧通常会用一个 MSM 表达它，例如：

```text
h_commit = h0_commit + x^n * h1_commit + x^{2n} * h2_commit + ...
```

你的 verifier 已经意识到这一点，所以处理了 `CommitmentReference::MSM`。 但 prover 侧并没有对“这是普通 commitment 还是 h_poly MSM”做任何对应处理，它只是遍历 `q.poly.values` 并按 theta 幂加到 `combined` 里。

如果 PSE 传给 `ProverQuery` 的 `q.poly` 不是 verifier 端 MSM 所表达的那个**完全相同的线性组合多项式**，那么 IPA check 必然失败。PLONK 约束可以通过，commitments 可以读对，evaluations 也可以在 PLONK 层看似匹配，但最后 opening proof 会不成立，因为：

```text
prover opening:  P_prover = Commit(Σ θᵢ · q.polyᵢ)
verifier check:  P_verifier = Σ θᵢ · CommitmentReferenceᵢ
```

只要 `Commit(q.poly_h)` 不等于 `CommitmentReference::MSM(h)`，最终 MSM 就不会归零。

这比“transcript 顺序错了”更像根因，因为 issue 文档说单查询 IPA 正常、multiquery 同点失败；如果纯 transcript 顺序整体错，通常单查询也会较容易暴露。文档列出的 C 类原因，即 commitment MSM 构造的 scale 方向或 fold 顺序错，也与这个判断一致。

## 3. 第二可疑点：Prover 和 Verifier 的 query ordering 依赖外部迭代顺序，缺少显式 canonicalization

prover 侧：

```rust
let all_queries: Vec<ProverQuery> = queries.into_iter().collect();
unique_points = all_queries.iter().filter(...)
point_queries = all_queries.iter().filter(|q| q.point == point)
```



verifier 侧也做类似逻辑：

```rust
let all_queries: Vec<VerifierQuery> = queries.into_iter().collect();
unique_points = all_queries.iter().filter(...)
point_queries = all_queries.iter().filter(...)
```



这要求 PSE Halo2 给 prover 和 verifier 的 query 迭代顺序完全一致。只要 verifier 端 `CommitmentReference::MSM(h)` 与 `Commitment(random)` 的顺序和 prover 端 `q.poly` 的顺序不同，theta folding 就会不同：

```text
prover:   h_poly + θ · random_poly
verifier: random_commit + θ · h_commit
```

结果就是 opening proof 失败。

issue 文档也把 transcript/ordering mismatch 放在第一类可能原因。 但这里更准确地说，不只是 transcript byte ordering，而是 **query semantic ordering**。你现在没有对 query 做显式排序或 transcript tagging，只是接受 Halo2 内部迭代顺序。

短期调试时要记录的不只是 transcript scalars/points，还要记录每个 query 的：

```text
point
query index
poly kind / commitment kind
commitment bytes or MSM hash
eval
theta power
```

否则只看 L/R/x/a_final，不一定能定位根因。

## 4. 第三可疑点：IPA prover 没有把 combined commitment P 显式纳入自己的协议输入

在常见 IPA opening 中，证明关系是围绕一个承诺 (P)、向量 (a)、evaluation vector (b(x))、结果 (e) 展开的。你的 prover 只构造 `combined` 向量并开始 IPA folding；它没有显式计算并检查：

```text
P = Σ θᵢ · Commit(qᵢ)
e = Σ θᵢ · eval(qᵢ)
```

再以这个 P 作为明确协议对象。它默认 PLONK 外层已经把所有承诺写入 transcript，并默认 verifier 重构出的 P 与自己的 combined polynomial commitment 一致。

代码上，prover 写入的是：

```rust
k
theta
L_i, R_i, x_i...
a_final
```

没有写 combined commitment。 

这不一定是错的，因为 PLONK transcript 通常已经吸收了承诺。但在自定义 commitment scheme 接入时，这会让 debug 极其困难：prover 根本没有断言 `Commit(combined_poly)` 等于 verifier 后续用 `CommitmentReference` 重建的 `combined_msm`。

所以短期应该加一个 debug-only invariant：

```rust
debug_P_from_poly = params.commit(engine, combined_poly)
debug_P_from_queries = theta_fold_query_commitments(...)
assert_eq!(debug_P_from_poly, debug_P_from_queries)
```

如果这个断言失败，根因就是 commitment reference handling / h_poly composition；如果它通过，再去查 transcript ordering 和 IPA folding公式。

## 5. 第四可疑点：`commit_lagrange` 与 `commit` 的 basis 假设可能与 PSE backend 不完全匹配

`ParamsIPA::commit_lagrange` 明确把 Lagrange form 转成 coefficient form，再用 coefficient-basis generators 做 MSM。注释里也说 IPA generators are not structured，所以必须转换到 coefficient form。

`ParamsProver::commit` 则直接对 `Polynomial<_, Coeff>` 的系数做 MSM。

这个方向本身合理。但它依赖一个条件：PLONK prover 交给 `ProverQuery` 的 `q.poly` 必须与 verifier 使用的 commitment 同基底、同长度、同 padding、同 domain convention。如果某个 query 在 Halo2 backend 内部是 extended-domain polynomial、quotient chunk、或经 `xn` scaling 后的合成对象，而你的 prover 仍把 `q.poly.values` 当普通 coeff vector 打开，就会出现“单查询自测通过、PLONK multiopen 失败”的形态。

这与 issue 文档中的“query evaluation mismatch”也吻合：prover 内部 `eval_polynomial(poly, x)` 与 verifier 接收的 PLONK evaluation 只要差一个 domain scaling、chunk factor、或 `x^n` factor，就会失败。

## 6. 这对 Aetheris 架构的含义：IPA 不能作为当前主证明后端，最多是实验分支

文档已经明确说：目前没有 workaround，IPA scheme 在 multiopen integration 修复前不能与 PSE PLONK 协议一起使用；KZG 仍可作为 fallback。

这句话要严格执行。不能因为 IPA primitive 单测通过，就把 IPA 后端视为“接近可用”。当前状态应判定为：

```text
IPA primitive: 部分可用
IPA standalone single-query opening: 可用
IPA as Halo2/PLONK commitment scheme: 不可用
IPA recursive production backend: 不可用
KZG fallback: 仍是唯一可运行主路径
```

这也和 `production_gap_analysis.md` 的早期判断一致：生产级递归需要真正的 Halo2 Accumulation Scheme、IPA 延迟开启逻辑、circuit-in-circuit verification，而当前还存在后端与累积器差距。

## 7. 当前 `halo2_pasta.rs` 还暴露出一个更大的问题：测试 harness 的电路语义过弱

`halo2_pasta.rs` 里的 `ValueConservationCircuit` 本身不是你当前主线 KZG 电路的等价迁移。它在 `synthesize` 里先用普通 Rust 计算：

```rust
let net_value = total_in as i64 - total_out as i64 - self.public_amount;
if net_value != 0 { return Err(ErrorFront::Synthesis); }
```

然后电路里只是做一些 running-sum/range 形式的约束。

而且它对 `output_commitments` 只是遍历了一下，基本没有形成真正的约束绑定。

这意味着，即使 IPA/PLONK multiopen 修好，`halo2_pasta.rs` 当前也不能直接作为生产证明后端。它更像是 **IPA integration harness**，不是完整交易语义电路。诊断 IPA bug 时可以用它，但不能把它的通过视为交易层安全通过。

## 8. 修复路线：不要先改公式，先做可观测性

我建议按下面顺序，不要直接盲改 `scale()` 或 fold 公式。

### Step 1：加 query-level trace，而不是只 trace transcript

对 prover 和 verifier 都输出同一份结构化日志：

```text
for each unique point:
  point
  query_count
  for each query:
    index
    commitment_kind = Commitment | MSM
    commitment_digest / msm_digest
    poly_digest
    eval
    theta_power
  combined_poly_digest
  combined_commitment_from_poly
  combined_commitment_from_refs
```

目标是先回答一个问题：

> prover 认为自己在打开的 combined polynomial，其 commitment 是否等于 verifier 认为的 combined commitment？

如果不等，问题在 h_poly/MSM/reference/basis；如果相等，再查 IPA folding。

### Step 2：单独构造 `h_poly + random_poly` 最小复现

目前单查询 roundtrip 通过不够。需要新增一个不经过完整 PLONK 的单测：

```text
poly_a, poly_b
commit_a, commit_b
point x
theta from transcript
combined_poly = poly_a + theta poly_b
combined_commit = commit_a + theta commit_b
IPA open combined_poly
verify against combined_commit and combined_eval
```

然后再新增一个 MSM 版本：

```text
commit_h = h0 + x^n h1 + x^{2n} h2
poly_h = h0_poly + x^n h1_poly + x^{2n} h2_poly
combined = poly_h + theta random_poly
```

这个测试能直接验证 C 类问题：MSM scale 方向、fold order、h_poly composition 是否一致。

### Step 3：确认 PSE 的 `ProverQuery` 是否已经给出了合成后的 h_poly

如果 PSE backend 给 prover 的 `q.poly` 已经是合成后的 `h_poly`，那 verifier 的 `CommitmentReference::MSM` 必须重建同一个合成 commitment。
如果 PSE backend 给的是 h pieces 或某种内部对象，那你现在的 prover folding 就错了，需要在 IPA prover 里重建 h composition。

这是整个问题的分水岭。

### Step 4：最后才检查 transcript ordering

在以上都一致后，再做 byte-level transcript trace。issue 文档建议比较 prover/verifier 写入和读取的 scalar/point，这是对的，但应排在 semantic trace 之后。

因为如果 combined commitment 本身就不等，transcript 完全一致也没用。

## 9. 更根本的建议：不要在主线里维护自制 PLONK commitment scheme，除非你愿意长期追踪 PSE backend 内部接口

这个文件里已经记录了 vendor patch：为了外部实现 `CommitmentScheme`，你把 PSE fork 的 `halo2_backend` 中 query 模块和字段从 `pub(crate)` 改成 `pub`。

这本身就是一个风险信号：**你正在依赖一个原本不稳定、不打算对外暴露的 backend 内部接口。**

从工程风险看，有三条路线：

1. **保守路线**：主线继续用 KZG；IPA 保留为 research branch，不进入共识关键路径。
2. **中等路线**：fork PSE halo2，并把 IPA commitment scheme 作为 first-class backend 维护，补齐所有 multiopen 测试。
3. **激进路线**：放弃 PSE PLONK multiopen 接口，自己实现最小可控的 PLONK/IPA proving pipeline。

我建议当前选 1 或 2，不要选 3。Aetheris 已经有 VDF、record、nullifier、wallet、P2P、arbitration 等足够多的不稳定面；再自研完整 PLONK backend 会把风险指数级放大。

## 结论

`ISSUE_IPA_PLONK_INTEGRATION.md` 描述的是一个**协议集成层缺陷**，不是普通代码 bug：

> IPA opening 单独成立，但它还没有正确接入 Halo2/PLONK 的 multiopen 查询语义。失败点在 `strategy.finalize()`，说明 PLONK 约束与 transcript 主流程大体通过，但 verifier 重建的 combined commitment/evaluation 与 prover 实际打开的 combined polynomial 不一致。

最可能根因不是 IPA 折叠公式本身，而是 **h_poly 的 `CommitmentReference::MSM` 与 prover 侧 `q.poly.values` 没有表达同一个多项式**；其次是 query ordering / theta folding 顺序不一致；再次才是 transcript L/R/x/a_final 顺序问题。

在修好之前，IPA 后端不能进入生产路径。KZG fallback 可以继续作为当前主线，但文档里所有“IPA 生产级递归已完成”或“递归证明后端可用”的表述都应该降级为：**IPA primitive 与部分 harness 已实现，PLONK multiopen integration 尚未通过。**
