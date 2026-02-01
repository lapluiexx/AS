import time
import hashlib
import os
from ecdsa import SECP256k1, SigningKey, BadSignatureError
from ecdsa.util import sigencode_der, sigdecode_der


# --- ZKP Simulator ---
class Groth16Simulator:
    def setup(self, relation_logic):
        self.relation_logic = relation_logic
        return {"alg": "Groth16", "type": "pk"}, {"alg": "Groth16", "type": "vk"}

    def prove(self, pk, stmt, wit):
        # 模拟证明生成：运行电路逻辑检查 witness 是否有效
        if self.relation_logic(stmt, wit):
            return b"simulated_proof"
        return None

    def verify(self, vk, stmt, proof):
        return proof == b"simulated_proof"


# --- AS-ECDSA Implementation (Based on Figure 3) ---
class AS_ECDSA:
    def __init__(self):
        self.curve = SECP256k1
        self.order = SECP256k1.order
        self.generator = SECP256k1.generator
        self.hash_func = hashlib.sha256
        self.zkp = Groth16Simulator()

    def _circuit(self, stmt, wit):
        """
        ZKP 电路逻辑
        验证:
        1. pk 是由 seed 派生的
        2. 签名使用的 nonce c 满足 c = (k + seed) mod q
        """
        pk_bytes, m, (r, s) = stmt
        seed, k = wit  # Witness 现在包含 seed 和 k

        # [Logic 1] Re-derive SK and check PK
        # sk = KDF(seed)
        sk_int = int.from_bytes(hashlib.sha256(b"AS-KDF:" + seed).digest(), 'big') % self.order
        sk_obj = SigningKey.from_secret_exponent(sk_int, curve=self.curve, hashfunc=self.hash_func)
        if sk_obj.get_verifying_key().to_string() != pk_bytes:
            return False

        # [Logic 2] Verify Signature Construction with specific Nonce logic
        # Image Step 4: Compute c = (k + seed) mod q
        seed_int = int.from_bytes(seed, 'big')
        c = (k + seed_int) % self.order

        # Image Step 8: s = c^{-1}(z + r * sk) mod q
        # 验证 s 是否符合上述公式
        z = int.from_bytes(self.hash_func(m).digest(), 'big')
        try:
            c_inv = pow(c, -1, self.order)
            s_expected = (c_inv * (z + r * sk_int)) % self.order
            return s == s_expected
        except Exception:
            return False

    def seed_gen(self):
        # Step 1: Choose security parameter (implicit)
        # Step 2: Return seed
        return os.urandom(32)

    # [1] AS.Setup
    def setup(self):
        pk, vk = self.zkp.setup(self._circuit)
        return {"pk": pk, "vk": vk}

    # [2] AS.KeyGen
    def key_gen(self, seed, pp):
        # Step 2: Compute sk = KDF(seed)
        sk_int = int.from_bytes(hashlib.sha256(b"AS-KDF:" + seed).digest(), 'big') % self.order
        sk = SigningKey.from_secret_exponent(sk_int, curve=self.curve, hashfunc=self.hash_func)
        # Step 3: Compute pk = sk * G
        return sk, sk.get_verifying_key()

    # [3] AS.Sign (Standard ECDSA)
    def sign(self, pp, sk, m):
        # Step 3: Select random k (handled by library or manual)
        # 这里使用库函数标准签名，它内部会自动生成随机 k
        sig = sk.sign(m, hashfunc=self.hash_func, sigencode=sigencode_der)
        return sigdecode_der(sig, self.order)

    # [4] AS.SignAuth (Authorized Signature)
    # [STRICTLY FOLLOWING IMAGE LOGIC]
    def sign_auth(self, pp, seed, m):
        # Step 1: Parse params (implicit)

        # Step 7 (Pre-computation for Step 8): sk = KDF(seed)
        sk_int = int.from_bytes(hashlib.sha256(b"AS-KDF:" + seed).digest(), 'big') % self.order
        sk_obj = SigningKey.from_secret_exponent(sk_int, curve=self.curve, hashfunc=self.hash_func)

        # Step 2: Compute z = H(m)
        z = int.from_bytes(self.hash_func(m).digest(), 'big')

        # Step 3: Select a random integer k
        k = int.from_bytes(os.urandom(32), 'big') % self.order

        # Step 4: Compute c = (k + seed) mod q
        seed_int = int.from_bytes(seed, 'big')
        c = (k + seed_int) % self.order

        # Step 5: Compute R = c * G
        R = c * self.generator

        # Step 6: Compute r = R.x mod q
        r = R.x() % self.order

        # Step 8: Compute s = c^{-1}(z + r * sk) mod q
        c_inv = pow(c, -1, self.order)
        s = (c_inv * (z + r * sk_int)) % self.order

        # Step 9: sigma <- (r, s)
        sigma = (r, s)

        # Step 10: x <- (pk, m, sigma)
        pk_bytes = sk_obj.get_verifying_key().to_string()
        stmt = (pk_bytes, m, sigma)

        # Step 11: w <- (seed, k)
        wit = (seed, k)

        # Step 12: Run pi <- zkp.Prove(...)
        pi = self.zkp.prove(pp['pk'], stmt, wit)

        # Step 13: Return (sigma, pi)
        return (sigma, pi)

    # [5] AS.Verify
    def verify(self, pp, pk, m, sigma):
        r, s = sigma
        sig_der = sigencode_der(r, s, self.order)
        try:
            return pk.verify(sig_der, m, hashfunc=self.hash_func)
        except BadSignatureError:
            return False

    # [6] AS.VerAuth
    def ver_auth(self, pp, pk, m, auth):
        sigma, pi = auth
        # Step 2: Verify signature AND Verify proof
        if not self.verify(pp, pk, m, sigma):
            return False

        pk_bytes = pk.to_string()
        stmt = (pk_bytes, m, sigma)

        return self.zkp.verify(pp['vk'], stmt, pi)


# --- Main Execution with Timing ---
if __name__ == "__main__":
    scheme = AS_ECDSA()
    print(f"{'Algorithm':<15} | {'Time (ms)':<15}")
    print("-" * 35)

    msg = b"Test Message for Timing"
    seed = scheme.seed_gen()

    # 1. AS.Setup
    start = time.perf_counter()
    pp = scheme.setup()
    end = time.perf_counter()
    print(f"{'AS.Setup':<15} | {(end - start) * 1000:.4f} ms")

    # 2. AS.KeyGen
    start = time.perf_counter()
    sk, pk = scheme.key_gen(seed, pp)
    end = time.perf_counter()
    print(f"{'AS.KeyGen':<15} | {(end - start) * 1000:.4f} ms")

    # 3. AS.Sign
    start = time.perf_counter()
    sigma = scheme.sign(pp, sk, msg)
    end = time.perf_counter()
    print(f"{'AS.Sign':<15} | {(end - start) * 1000:.4f} ms")

    # 4. AS.SignAuth (Manual Calculation with k + seed)
    start = time.perf_counter()
    auth_tuple = scheme.sign_auth(pp, seed, msg)
    end = time.perf_counter()
    print(f"{'AS.SignAuth':<15} | {(end - start) * 1000:.4f} ms")

    # 5. AS.Verify
    start = time.perf_counter()
    valid = scheme.verify(pp, pk, msg, sigma)
    end = time.perf_counter()
    print(f"{'AS.Verify':<15} | {(end - start) * 1000:.4f} ms")

    # 6. AS.VerAuth
    start = time.perf_counter()
    valid_auth = scheme.ver_auth(pp, pk, msg, auth_tuple)
    end = time.perf_counter()
    print(f"{'AS.VerAuth':<15} | {(end - start) * 1000:.4f} ms")
    
    def estimate_zkp_key_sizes(num_constraints=40000):
        """
        基于 Groth16 + BLS12-381 曲线估算密钥大小
        :param num_constraints: 电路约束数量 (SHA256 + ECDSA check 约 40k)
        """
        # 基础元素大小 (Bytes)
        G1_SIZE = 48
        G2_SIZE = 96

        # 1. 计算 VK 大小 (常数级)
        # vk = alpha(G1) + beta(G2) + gamma(G2) + delta(G2) + IC[](G1)
        # 假设有 5 个公共输入 (Public Inputs)
        num_public_inputs = 5
        vk_size = G1_SIZE + (3 * G2_SIZE) + ((num_public_inputs + 1) * G1_SIZE)

        # 2. 计算 PK 大小 (线性级)
        # pk 包含大量的 G1 和 G2 点，与约束数量 N 成正比
        # 粗略公式: pk ≈ N * G1 + N * G2 + ...
        # 在 Circom/SnarkJS 的实际表现中，40k 约束大约对应 15MB - 20MB
        # 我们可以使用一个精确的线性因子：每条约束大约贡献 380 Bytes (保守估计)
        pk_size = num_constraints * 380

        return pk_size, vk_size


    def print_size_statistics():
        print("\n" + "=" * 35)
        print(f"{'Metric':<15} | {'Size':<15}")
        print("-" * 35)

        # 估算 AS-ECDSA 电路的约束量
        # SHA256 + KDF + Secp256k1 Mul ≈ 40,000 R1CS
        ESTIMATED_CONSTRAINTS = 40000

        pk_bytes, vk_bytes = estimate_zkp_key_sizes(ESTIMATED_CONSTRAINTS)

        # 格式化输出
        if pk_bytes > 1024 * 1024:
            pk_str = f"{pk_bytes / (1024 * 1024):.2f} MB"
        else:
            pk_str = f"{pk_bytes / 1024:.2f} KB"

        vk_str = f"{vk_bytes} Bytes"

        print(f"{'Proving Key':<15} | {pk_str:<15}")
        print(f"{'Verifying Key':<15} | {vk_str:<15}")
        print(f"{'Constraints':<15} | {ESTIMATED_CONSTRAINTS:<15}")
        print("=" * 35)


    # 在 main 中调用
    if __name__ == "__main__":
        print_size_statistics()