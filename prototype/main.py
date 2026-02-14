from vdf import SimpleVDF, GENESIS_P, GENESIS_Q
from crypto import Record, CryptoUtils
from core import SovereignClient, Transaction
import time

def run_demo():
    print("=== Aetheris (AET) 核心功能验证原型 ===\n")

    # 1. 初始化创世锚点
    genesis_hash = "00000000aetheris_genesis_anchor_xxxxxx"
    client = SovereignClient(genesis_hash)
    print(f"[1] 创世锚点已确立: {genesis_hash}")

    # 2. 模拟 VDF 时间发行 (Time-based Minting)
    print("\n[2] 开始 VDF 时间挖矿 (模拟时间流逝)...")
    vdf = SimpleVDF(GENESIS_P, GENESIS_Q)
    x = int(genesis_hash.replace('aetheris_genesis_anchor_xxxxxx', '0'), 16) if not genesis_hash.startswith('0000') else 12345
    t = 100000 # 模拟 10 万次串行运算
    y, duration = vdf.solve(x, t)
    print(f"    VDF 计算完成! 耗时: {duration:.4f}s")
    print(f"    生成证明高度: {t}, 结果摘要: {hex(y)[:16]}...")

    # 产生新币给用户 Alice
    alice_sk = "alice_secret_key_123"
    alice_pk = "alice_public_key_456"
    new_record = Record(alice_pk, 50) # 发行 50 AET
    client.receive_minting({"y": y}, new_record)
    print(f"    主权客户端已验证发行: Alice 获得 50 AET (隐私记录已存储)")

    # 3. 模拟隐私交易 (Private Transaction)
    print("\n[3] 发起隐私交易: Alice 转账 20 AET 给 Bob")
    # Alice 消耗旧记录，产生两个新记录 (20 给 Bob, 30 找零)
    bob_pk = "bob_public_key_789"
    nullifier = CryptoUtils.generate_nullifier(alice_sk, "record_0_id")
    
    out_bob = Record(bob_pk, 20).to_commitment()
    out_change = Record(alice_pk, 30).to_commitment()
    
    # 构建交易并附带 ZK 证明 (原型中模拟 VALID_PROOF)
    tx = Transaction(inputs=[nullifier], outputs=[out_bob, out_change], zk_proof="VALID_PROOF")
    
    success, msg = client.verify_transaction(tx)
    print(f"    交易验证结果: {success} ({msg})")
    print(f"    网络状态更新: Nullifier {nullifier[:16]}... 已被作废")

    # 4. 模拟恶意攻击 (Double Spend Attack)
    print("\n[4] 模拟非理性攻击: 恶意节点尝试双花 Alice 的同一笔钱")
    malicious_tx = Transaction(inputs=[nullifier], outputs=[out_bob], zk_proof="VALID_PROOF")
    success, msg = client.verify_transaction(malicious_tx)
    print(f"    恶意交易验证结果: {success} ({msg})")
    print("    结论: 即使恶意节点控制了网络，主权客户端在数学上依然拒绝双花。")

if __name__ == "__main__":
    run_demo()
