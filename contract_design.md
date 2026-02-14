# Aetheris (AET) 智能合约设计：隐私自动做市商 (Private AMM)

本文件以“隐私 AMM”为例，展示 Aetheris 智能合约如何与主权验证框架对接。

## 1. 合约目标
在不泄露交易者身份、交易金额及池子储备金比例的前提下，实现 AET 与其他隐私资产的自动兑换。

## 2. 状态模型：基于记录 (Record-Based)
不同于以太坊的账户模型，Aetheris 合约使用 **Record** 存储状态。

### 2.1 流动性池记录 (Pool Record)
```json
{
  "record_type": "AMM_POOL",
  "asset_pair": ["AET", "Z-USD"],
  "reserve_a_commitment": "Commitment(amount_a)",
  "reserve_b_commitment": "Commitment(amount_b)",
  "vdf_nonce": "Last_Update_Time",
  "owner_predicate": "AMM_Logic_Hash"
}
```

## 3. 核心功能：隐私兑换 (Swap)

### 3.1 客户端执行步骤
1. **输入准备**：用户获取当前的 `Pool Record` 密文和自己的 `User UTXO`。
2. **本地计算**：
   - 使用常数乘积公式 $x \cdot y = k$ 计算兑换结果。
   - 生成新的 `Pool Record`（更新后的储备金）和新的 `User UTXO`。
3. **证明生成 (ZK-Proof)**：
   - 证明：输入的 $Record_{old}$ 是合法的且存在于全局树中。
   - 证明：输出的 $Record_{new}$ 严格遵循 $x \cdot y = k$ 逻辑。
   - 证明：用户确实拥有输入资产的所有权。
   - 证明：生成的 $Nullifier$ 对应于旧记录。

### 3.2 协议对接：验证谓词
网络节点接收到交易后，调用以下数学谓词：
- `Verify_ZK_VM(Program_Root, Proof, Public_Inputs)`
- `Check_Nullifier(N_pool, N_user)`
- `Verify_VDF_Consistency(vdf_nonce)`

## 4. 与现有框架的对接点

### 4.1 VDF 锚定
合约的每一次状态转换都必须附带当前的 VDF 证明高度。这防止了恶意节点通过提供过时的池子状态来实施“夹子攻击（Sandwich Attack）”。

### 4.2 递归压缩
AMM 的成千上万次兑换产生的证明，会被 Aetheris 的递归 ZK-SNARKs 压缩为一个单一的根证明。对于新加入的主权客户端，它只需要验证这个根证明，就能确信 AMM 的所有历史兑换都是公平且符合数学公式的。

## 5. 极端容错表现
即使 99% 的排序节点尝试拦截你的 Swap 交易：
- **安全性**：它们无法修改你的兑换比例，因为它们没有 ZK-VM 的私有输入。
- **一致性**：只要你本地验证通过，且你的交易最终被包含在任何一个合法的 VDF 时间片内，你的资产就是安全的。
