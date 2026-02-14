import hashlib
import json

class CryptoUtils:
    """
    Aetheris 核心密码学辅助工具
    模拟 ZK-SNARKs 行为
    """
    @staticmethod
    def poseidon_hash(data):
        """模拟 ZK-friendly 哈希函数 Poseidon"""
        s = json.dumps(data, sort_keys=True)
        return hashlib.sha256(s.encode()).hexdigest()

    @staticmethod
    def generate_nullifier(sk, record_id):
        """生成不可关联的 Nullifier"""
        return hashlib.sha256(f"{sk}{record_id}".encode()).hexdigest()

class Record:
    """
    Aetheris 状态记录模型
    """
    def __init__(self, owner_pk, amount, asset_id="AET", nonce=0):
        self.owner_pk = owner_pk
        self.amount = amount
        self.asset_id = asset_id
        self.nonce = nonce
        self.salt = hashlib.sha256(str(time.time()).encode()).hexdigest()

    def to_commitment(self):
        """生成加密承诺"""
        data = {
            "owner": self.owner_pk,
            "amount": self.amount,
            "asset": self.asset_id,
            "nonce": self.nonce,
            "salt": self.salt
        }
        return CryptoUtils.poseidon_hash(data)

import time
