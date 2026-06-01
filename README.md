# Aetheris Protocol (Alpha)

Aetheris 是一种基于 **Proof of Time (PoT)** 与 **Mathematical Arbitration** 共识机制的隐私增强型区块链协议。它结合了 Wesolowski VDF（可验证延迟函数）、Halo2 ZK-SNARKs 以及 Loopix 混币网络，旨在提供极致的安全性和抗审查性。

## 核心设计哲学

- **主权验证 (Sovereign Verification)**: 每个客户端以创世锚点为起点独立验证，不依赖网络多数的"共识"。即使在完全网络隔离（日蚀攻击）下，节点也无法被欺骗接受非法状态。
- **PoT 共识**: 解决能源浪费问题，通过 VDF 确保区块产生的间隔与计算力解耦，而是与物理时间绑定。VDF 序列是确定性的，节点可独立计算时间轴。难度通过确定性重定向自动平衡，确保硬件代际提升不影响出块速率。
- **数学仲裁 (Mathematical Arbitration)**: 在并发冲突时，通过 VDF 结果哈希的确定性排序挑选胜者——无需投票或轮次协调。仲裁函数的单调性保证任何子集上的选择均收敛于真实最小值。
- **日蚀抵抗 (Eclipse Resistance)**: 协议提供数学保证：完整性（不接受非法状态）、可检测性（VDF 迭代数与区块数不匹配即告警）、可恢复性（重新连接后通过 VDF 重算恢复规范链）、有限损害（攻击者不能窃取或永久分叉）。
- **隐私优先**: 采用屏蔽交易（Shielded Transactions），所有转账金额和地址均受 ZKP 保护，对外表现为 Stealth Address。
- **解耦架构**: 内核 (Rust) 与前端 (C#/.NET) 通过加密二进制接口 (FFI) 通信，确保底层协议的通用性。

## 目录结构

- `aetheris-core`: 定义核心区块、交易及状态转移逻辑。
- `aetheris-crypto`: 实现 VDF、Keccak、AES-GCM 等加密原语。
- `aetheris-zkp`: 基于 Halo2 的零知识证明系统（含屏蔽交易电路）。
- `aetheris-recursive`: 递归证明聚合（Halo2 IPA + 非原生算术）。
- `aetheris-ffi`: 为跨语言集成提供的 C-ABI 接口层（30+ extern "C" 函数）。
- `aetheris-node`: 完整的 P2P 节点实现（libp2p + sled DB）。
- `aetheris-wallet`: CLI 钱包（助记词、UTXO 扫描、交易签名）。
- `Aetheris.App` / `Aetheris.CLI`: 参考 C# 桌面客户端实现。

## 集成指南 (FFI)

### 安全通信协议

所有前端与内核的通信均采用 **AES-GCM 256** 加密。

1. **Bridge Key**: 通过 `aetheris_handshake()` 动态交换的 AES-256 会话密钥（非预共享）。
2. **BinaryBuffer 结构**:
   ```rust
   #[repr(C)]
   pub struct BinaryBuffer {
       pub ptr: *mut u8,
       pub len: usize,
   }
   ```
3. **加密负载格式**: `[12 字节 Nonce] + [密文] + [16 字节 Auth Tag]`。

### 核心 API 示例

- `aetheris_init()`: 初始化内核。
- `aetheris_execute_command_bin(input: BinaryBuffer) -> BinaryBuffer`: 通用加密指令接口。
- `aetheris_get_node_status_bin() -> BinaryBuffer`: 获取当前节点状态（加密 JSON）。

## 开发者测试

运行全场景集成测试：
```bash
cargo test --workspace --lib
```

FFI 测试需串行执行（sled Windows 文件锁）：
```bash
cargo test -p aetheris-ffi --lib -- --test-threads=1
```

## 许可证

Aetheris Foundation (C) 2026. Reserved.

