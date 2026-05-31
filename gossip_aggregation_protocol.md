# Aetheris (AET) Gossip-Aggregation P2P 协议规范 (草案)

## 1. 概述
Gossip-Aggregation 协议旨在解决 Aetheris 网络中分布式证明的发现、验证与协同聚合问题。不同于传统的单向 Gossip，该协议引入了“证明权重”和“聚合竞争”机制，确保网络能够快速收敛到包含最大交易集合的单一递归证明。

## 2. 消息类型 (Protobuf 定义参考)

### 2.1 `AtomicProofGossip`
当用户生成一笔新交易及其对应的原子证明时广播。
```protobuf
message AtomicProofGossip {
    bytes tx_id = 1;          // 交易哈希
    bytes statement = 2;      // RecursiveStatement (Serialized)
    bytes proof = 3;          // Halo2 Proof Bytes
    uint64 timestamp = 4;     // 时间戳 (用于简单的抗重放)
}
```

### 2.2 `AggregateProofGossip`
当聚合节点（Aggregator）完成一轮递归聚合后广播。
```protobuf
message AggregateProofGossip {
    bytes aggregate_id = 1;   // 聚合证明唯一标识 (Hash of Statement)
    bytes statement = 2;      // RecursiveStatement
    bytes proof = 3;          // Halo2 Aggregate Proof
    uint32 depth = 4;         // 递归深度 (权重指标)
    repeated bytes leaf_txs = 5; // 该聚合证明包含的所有原始交易 ID 列表
}
```

## 3. 节点行为规范

### 3.1 验证策略 (Validation Pipeline)
节点收到证明后，必须按以下顺序进行验证，通过后方可转发：
1. **基础验证**: 检查消息格式、签名及 `timestamp` 有效性。
2. **状态验证**: 
    - `total_flow` 必须为 0（价值守恒）。
    - `tx_root` 必须通过增量哈希验证。
3. **密码学验证**: 运行 `Halo2 Verifier` 验证证明的数学正确性。

### 3.2 转发策略 (Forwarding Rules)
为了防止冗余和 DoS 攻击：
- **原子证明**: 仅转发过去 $N$ 秒内未见过的有效原子证明。
- **聚合证明 (核心机制)**: 
    - 采用 **“深度优先” (Depth-First)** 转发。
    - 如果收到一个 `depth` 较小且包含交易集完全被已知证明覆盖的消息，则丢弃。
    - 如果收到一个 `depth` 更大或包含新交易集的证明，立即转发并更新本地缓存。

### 3.3 聚合触发机制 (Aggregation Trigger)
聚合节点在满足以下任一条件时启动 `aggregate_step`:
- **缓冲区满**: 本地 `pending_atomic` 数量达到阈值（如 16 个）。
- **超时**: 距离上一次聚合已过去 $T$ 毫秒（如 500ms）。
- **竞争优势**: 发现网络中存在更高深度的聚合证明，尝试将本地原子证明并入该高深度的证明中。

## 4. 抗攻击机制 (Security & Anti-DoS)

- **证明评分制**: 对发送非法证明的节点降低 Peer Score，并在严重时断开连接。
- **递归深度限制**: 协议硬性规定最大 `depth`，防止无限递归攻击。
- **工作量过滤**: 原子证明的生成本身带有计算成本，充当了天然的抗 DoS 屏障。

## 5. 待解决问题 (Open Questions)
- 如何在不完全解开聚合证明的情况下，高效判断两个聚合证明的交易交集？
- 是否需要引入“协调节点”来优化特定分片内的聚合效率？
