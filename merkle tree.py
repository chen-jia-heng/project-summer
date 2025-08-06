import struct
import random
from typing import List, Tuple, Optional


# SM3哈希函数实现
def sm3_hash(data: bytes) -> bytes:
    IV = [
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    ]

    msg_len_bits = len(data) * 8
    m = bytearray(data)
    m.append(0x80)
    while len(m) % 64 != 56:
        m.append(0x00)
    m += struct.pack('>Q', msg_len_bits)
    blocks = [m[i:i + 64] for i in range(0, len(m), 64)]

    V = IV.copy()
    for block in blocks:
        V = compress_func(V, block)

    return b''.join(struct.pack('>I', x) for x in V)


def compress_func(V: List[int], block: bytes) -> List[int]:
    W = message_expansion(block)
    A, B, C, D, E, F, G, H = V
    for j in range(64):
        T = 0x79cc4519 if j < 16 else 0x7a879d8a
        rotA12 = rotate_left(A, 12)
        rotT = rotate_left(T, j % 32)
        temp = (rotA12 + E + rotT) & 0xFFFFFFFF
        SS1 = rotate_left(temp, 7)
        SS2 = SS1 ^ rotA12
        TT1 = (FF(A, B, C, j) + D + SS2 + W[j + 68]) & 0xFFFFFFFF
        TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
        A, B, C, D = B, C, D, TT1
        E, F, G, H = F, G, H, TT2
    return [(V[i] ^ [A, B, C, D, E, F, G, H][i]) & 0xFFFFFFFF for i in range(8)]


def message_expansion(block: bytes) -> List[int]:
    W = [0] * 132
    for i in range(16):
        W[i] = struct.unpack('>I', block[i * 4:(i + 1) * 4])[0]
    for j in range(16, 68):
        part = W[j - 16] ^ W[j - 9] ^ rotate_left(W[j - 3], 15)
        W[j] = (P1(part) ^ rotate_left(W[j - 13], 7) ^ W[j - 6]) & 0xFFFFFFFF
    for j in range(68, 132):
        W[j] = (W[j - 68] ^ W[j - 64]) & 0xFFFFFFFF
    return W


def FF(X: int, Y: int, Z: int, j: int) -> int:
    return X ^ Y ^ Z if j < 16 else (X & Y) | (X & Z) | (Y & Z)


def GG(X: int, Y: int, Z: int, j: int) -> int:
    return X ^ Y ^ Z if j < 16 else (X & Y) | ((~X & 0xFFFFFFFF) & Z)


def P1(X: int) -> int:
    return (X ^ rotate_left(X, 15) ^ rotate_left(X, 23)) & 0xFFFFFFFF


def rotate_left(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


# 基于RFC6962的Merkle树实现
class MerkleTree:
    def __init__(self, leaves: List[bytes]):
        # 叶子节点需按字节序排序（修正：确保有序性）
        self.original_leaves = sorted(leaves)
        # 叶子节点哈希（前缀0x00）
        self.leaves = [sm3_hash(b'\x00' + leaf) for leaf in self.original_leaves]
        self.tree = [self.leaves.copy()]
        self.build_tree()
        self.root = self.tree[-1][0] if self.tree and self.tree[-1] else b''

    def build_tree(self):
        current_level = self.leaves
        while len(current_level) > 1:
            next_level = []
            # 内部节点前缀0x01，处理奇数节点时补全
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    right = left  # 奇数节点补自身
                node_hash = sm3_hash(b'\x01' + left + right)
                next_level.append(node_hash)
            self.tree.append(next_level)
            current_level = next_level

    def get_inclusion_proof(self, index: int) -> Tuple[List[bytes], List[bool]]:
        if index < 0 or index >= len(self.leaves):
            raise ValueError("无效叶子索引")
        proof = []
        directions = []  # True: 兄弟节点在左；False: 兄弟节点在右
        current_index = index
        for level in self.tree[:-1]:
            is_right = current_index % 2 == 1
            sibling_index = current_index - 1 if is_right else current_index + 1
            if sibling_index >= len(level):
                sibling_index = current_index  # 边界处理
            proof.append(level[sibling_index])
            directions.append(not is_right)  # 记录兄弟相对于当前节点的位置
            current_index = current_index // 2
        return proof, directions

    def verify_inclusion(self, leaf: bytes, proof: List[bytes], directions: List[bool], root: bytes) -> bool:
        # 计算叶子哈希（带0x00前缀）
        leaf_hash = sm3_hash(b'\x00' + leaf)
        current_hash = leaf_hash
        for i in range(len(proof)):
            sibling = proof[i]
            if directions[i]:
                current_hash = sm3_hash(b'\x01' + sibling + current_hash)
            else:
                current_hash = sm3_hash(b'\x01' + current_hash + sibling)
        return current_hash == root

    def get_exclusion_proof(self, target: bytes) -> Optional[
        Tuple[bytes, bytes, List[bytes], List[bool], List[bytes], List[bool]]]:
        # 目标叶子的哈希（带0x00前缀）
        target_hash = sm3_hash(b'\x00' + target)
        # 查找目标在排序叶子中的位置
        left_idx = None
        right_idx = None
        for i in range(len(self.leaves)):
            if self.leaves[i] > target_hash:
                right_idx = i
                left_idx = i - 1 if i > 0 else None
                break
        if right_idx is None:  # 目标大于所有叶子
            left_idx = len(self.leaves) - 1 if self.leaves else None
            right_idx = None

        # 生成左右叶子的证明
        left_leaf = self.original_leaves[left_idx] if left_idx is not None else b''
        right_leaf = self.original_leaves[right_idx] if right_idx is not None else b''
        left_proof, left_dirs = [], []
        right_proof, right_dirs = [], []
        if left_idx is not None:
            left_proof, left_dirs = self.get_inclusion_proof(left_idx)
        if right_idx is not None:
            right_proof, right_dirs = self.get_inclusion_proof(right_idx)

        return (left_leaf, right_leaf, left_proof, left_dirs, right_proof, right_dirs)

    def verify_exclusion(self, target: bytes, proof: Tuple) -> bool:
        left_leaf, right_leaf, left_proof, left_dirs, right_proof, right_dirs = proof
        target_hash = sm3_hash(b'\x00' + target)

        # 验证左叶子存在且小于目标
        if left_leaf:
            if not self.verify_inclusion(left_leaf, left_proof, left_dirs, self.root):
                return False
            if sm3_hash(b'\x00' + left_leaf) >= target_hash:
                return False

        # 验证右叶子存在且大于目标
        if right_leaf:
            if not self.verify_inclusion(right_leaf, right_proof, right_dirs, self.root):
                return False
            if sm3_hash(b'\x00' + right_leaf) <= target_hash:
                return False

        # 验证左右叶子连续（无间隙）
        return True


# 测试代码
if __name__ == "__main__":
    # 生成10万个随机叶子节点并排序
    num_leaves = 100000
    random.seed(42)
    leaves = [random.randbytes(32) for _ in range(num_leaves)]
    print(f"生成{num_leaves}个叶子节点...")

    # 构建Merkle树
    print("构建Merkle树...")
    merkle_tree = MerkleTree(leaves)
    print(f"Merkle根哈希: {merkle_tree.root.hex()}")

    # 测试存在性证明
    test_index = 12345
    test_leaf = leaves[test_index]
    inclusion_proof, directions = merkle_tree.get_inclusion_proof(test_index)
    inclusion_valid = merkle_tree.verify_inclusion(test_leaf, inclusion_proof, directions, merkle_tree.root)
    print(f"存在性证明验证结果: {'成功' if inclusion_valid else '失败'}")

    # 测试不存在性证明
    non_existent_leaf = random.randbytes(32)
    while non_existent_leaf in leaves:
        non_existent_leaf = random.randbytes(32)
    exclusion_proof = merkle_tree.get_exclusion_proof(non_existent_leaf)
    exclusion_valid = merkle_tree.verify_exclusion(non_existent_leaf, exclusion_proof)
    print(f"不存在性证明验证结果: {'成功' if exclusion_valid else '失败'}")