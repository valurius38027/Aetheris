# Aetheris (AET) 递归证明系统实现路线图

## 阶段 1：密码学原语生产化 (Cryptographic Primitives)

### 1.1 Poseidon 芯片生产化
- [x] **常量生成**：集成 Grain LFSR 算法，为 Pasta 曲线生成标准 MDS 矩阵 and Round Constants。
- [x] **电路优化**：已实现 Full/Partial Round 自定义门，优化 $x^5$ S-Box。
- [x] **多宽度支持**：`RecursiveConfig` 已支持 9 列 Advice/Fixed，基础设施已就绪，通用 T=3/5/9 逻辑已实现。

### 1.2 曲线循环与递归基础
- [x] **点运算电路**：`EccChip` 已实现基于自定义门的 `add` 和 `double` 约束。
- [x] **非本地域运算**：已定义 `NonNativeChip` 肢体结构（Limbs），加法框架已就绪，乘法与进位处理逻辑已完善。
- [x] **递归证明验证器**：在电路中集成 Halo2 的 `Verifier` 基础结构，处理递归证明的状态传递。

## 阶段 2：递归验证与累积协议 (Recursive Verification & Accumulation)

### 2.1 IPA 累积协议 (Accumulation Scheme)
- [x] **累积器验证电路**：`AccumulatorChip` 已实现基于挑战值（Challenge）的 RLC 更新逻辑，支持多证明批量聚合。
- [x] **G2V/V2G 转换**：实现 Pallas 标量场到 Vesta 基域的坐标转换电路，支持跨曲线点映射。
- [x] **证明压缩**：已实现 `IpaChip` 的对数级折叠逻辑，优化了递归链末端的验证路径。

### 2.2 公共输入与声明绑定
- [x] **Statement 绑定**：已实现 `tx_root`, `total_flow`, `depth`, `accumulator_hash` 到 Instance 列的映射。
- [x] **递归深度强制**：已实现自定义门约束 `depth[row] = depth[row-1] + num_atomic[row]`。

## 阶段 3：Gossip 聚合协议与网络层 (P2P Aggregation)

### 3.1 聚合节点网络
- [x] **节点发现**：基于 `libp2p` 构建 `P2PRecursiveManager`，支持 Peer 发现与基础消息处理。
- [x] **抗 DoS 机制**：实现基于 Peer Score 的验证机制，自动惩罚发送无效证明的节点。
- [x] **状态同步**：集成 Bloom Filter 管理已聚合交易列表，减少重复消息传输。

### 3.2 激励与分片聚合
- [x] **激励分配**：实现 `AggregationIncentive` 结构，支持基于证明贡献的奖励追踪。
- [x] **分片管理**：实现 `ShardedRecursiveManager` 与 `ShardId`，支持跨分片（Cross-shard）层级聚合。
- [x] **FFI 桥接**：完成 `aetheris-recursive` 与 `aetheris-ffi` 的对接，支持外部调用聚合逻辑。
- [ ] **最终集成**：完成 L1 奖励合约接口与 P2P 分片发现逻辑的对接。
