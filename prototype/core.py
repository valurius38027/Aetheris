from crypto import CryptoUtils, Record

class Transaction:
    """
    Aetheris 隐私交易结构
    """
    def __init__(self, inputs, outputs, zk_proof):
        self.inputs = inputs    # Nullifiers of consumed records
        self.outputs = outputs  # Commitments of new records
        self.zk_proof = zk_proof

class SovereignClient:
    """
    主权客户端：实现“不依赖多数人”的本地验证
    """
    def __init__(self, genesis_anchor):
        self.anchor = genesis_anchor
        self.nullifiers = set()  # 本地维护的已废弃凭证
        self.commitments = set() # 本地验证过的合法承诺
        self.balance_records = [] # 用户持有的私有记录

    def verify_transaction(self, tx):
        """
        核心验证逻辑：公式胜过投票
        """
        # 1. 验证 ZK 证明 (原型中模拟)
        if tx.zk_proof != "VALID_PROOF":
            return False, "Invalid ZK-Proof"

        # 2. 检查双花 (Nullifiers)
        for n in tx.inputs:
            if n in self.nullifiers:
                return False, f"Double spend detected: {n}"

        # 3. 验证通过，更新本地状态
        for n in tx.inputs:
            self.nullifiers.add(n)
        for c in tx.outputs:
            self.commitments.add(c)
        
        return True, "Success"

    def receive_minting(self, vdf_proof, record):
        """
        处理基于时间的货币发行
        """
        # 验证 VDF 逻辑 (原型简化)
        if vdf_proof["y"] is not None:
            c = record.to_commitment()
            self.commitments.add(c)
            self.balance_records.append(record)
            return True
        return False
