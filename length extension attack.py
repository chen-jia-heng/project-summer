import struct
import time

def sm3_hash(message, iv=None):
    # 初始向量IV（文档中定义的标准值）
    STANDARD_IV = [
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    ]
    V = iv.copy() if iv is not None else STANDARD_IV.copy()

    # 消息填充
    msg_len_bits = len(message) * 8
    m = bytearray(message)
    m.append(0x80)  # 填充1个"1"比特
    while len(m) % 64 != 56:
        m.append(0x00)
    m += struct.pack('>Q', msg_len_bits)  # 附加64比特长度

    # 按512比特分组处理
    blocks = [m[i:i + 64] for i in range(0, len(m), 64)]
    for block in blocks:
        V = compress_func(V, block)

    return ''.join(f'{x:08x}' for x in V)


def compress_func(V, block):
    W = message_expansion(block)  # 消息扩展
    A, B, C, D, E, F, G, H = V  # 工作变量初始化

    # 64轮迭代
    for j in range(64):
        # 轮常量
        T = 0x79cc4519 if j < 16 else 0x7a879d8a

        # 计算SS1、SS2
        rotA12 = rotate_left(A, 12)
        rotT = rotate_left(T, j % 32)
        temp = (rotA12 + E + rotT) & 0xFFFFFFFF
        SS1 = rotate_left(temp, 7)
        SS2 = SS1 ^ rotA12

        # 计算TT1、TT2
        TT1 = (FF(A, B, C, j) + D + SS2 + W[j + 68]) & 0xFFFFFFFF
        TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF

        # 更新工作变量
        A, B, C, D = B, C, D, TT1
        E, F, G, H = F, G, H, TT2

    # 与初始向量异或
    return [(V[i] ^ [A, B, C, D, E, F, G, H][i]) & 0xFFFFFFFF for i in range(8)]


def message_expansion(block):
    W = [0] * 132  # 扩展为132个32位字

    # 解析16个初始字
    for i in range(16):
        W[i] = struct.unpack('>I', block[i * 4:(i + 1) * 4])[0]

    # 扩展生成W[16..67]
    for j in range(16, 68):
        part = W[j - 16] ^ W[j - 9] ^ rotate_left(W[j - 3], 15)
        W[j] = (P1(part) ^ rotate_left(W[j - 13], 7) ^ W[j - 6]) & 0xFFFFFFFF

    # 扩展生成W[68..131]
    for j in range(68, 132):
        W[j] = (W[j - 68] ^ W[j - 64]) & 0xFFFFFFFF

    return W


def FF(X, Y, Z, j):
    if j < 16:
        return X ^ Y ^ Z
    else:
        return (X & Y) | (X & Z) | (Y & Z)


def GG(X, Y, Z, j):
    if j < 16:
        return X ^ Y ^ Z
    else:
        return (X & Y) | ((~X & 0xFFFFFFFF) & Z)


def P1(X):
    return (X ^ rotate_left(X, 15) ^ rotate_left(X, 23)) & 0xFFFFFFFF


def rotate_left(x, n):
    x = x & 0xFFFFFFFF  # 确保32位无符号
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def sm3_hash_optimized(message):
    STANDARD_IV = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
                   0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]
    V = STANDARD_IV.copy()
    msg_len_bits = len(message) * 8
    m = bytearray(message)
    m.append(0x80)
    while len(m) % 64 != 56:
        m.append(0x00)
    m += struct.pack('>Q', msg_len_bits)
    blocks = [m[i:i + 64] for i in range(0, len(m), 64)]

    for block in blocks:
        W = message_expansion_optimized(block)
        A, B, C, D, E, F, G, H = V

        # 第0-7轮
        for j in range(8):
            T = 0x79cc4519
            rotA12 = rotate_left(A, 12)
            rotT = rotate_left(T, j)
            temp = (rotA12 + E + rotT) & 0xFFFFFFFF
            SS1 = rotate_left(temp, 7)
            SS2 = SS1 ^ rotA12
            TT1 = (FF(A, B, C, j) + D + SS2 + W[j + 68]) & 0xFFFFFFFF
            TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
            A, B, C, D = B, C, D, TT1
            E, F, G, H = F, G, H, TT2

        # 第8-15轮
        for j in range(8, 16):
            # 逻辑与上述一致，使用j=8-15
            T = 0x79cc4519
            rotA12 = rotate_left(A, 12)
            rotT = rotate_left(T, j)
            temp = (rotA12 + E + rotT) & 0xFFFFFFFF
            SS1 = rotate_left(temp, 7)
            SS2 = SS1 ^ rotA12
            TT1 = (FF(A, B, C, j) + D + SS2 + W[j + 68]) & 0xFFFFFFFF
            TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
            A, B, C, D = B, C, D, TT1
            E, F, G, H = F, G, H, TT2

        # 第16-63轮（按8轮一组展开）
        for j in range(16, 64, 8):
            for k in range(j, j + 8):
                T = 0x7a879d8a
                rotA12 = rotate_left(A, 12)
                rotT = rotate_left(T, k % 32)
                temp = (rotA12 + E + rotT) & 0xFFFFFFFF
                SS1 = rotate_left(temp, 7)
                SS2 = SS1 ^ rotA12
                TT1 = (FF(A, B, C, k) + D + SS2 + W[k + 68]) & 0xFFFFFFFF
                TT2 = (GG(E, F, G, k) + H + SS1 + W[k]) & 0xFFFFFFFF
                A, B, C, D = B, C, D, TT1
                E, F, G, H = F, G, H, TT2

        V = [(V[i] ^ [A, B, C, D, E, F, G, H][i]) & 0xFFFFFFFF for i in range(8)]

    return ''.join(f'{x:08x}' for x in V)


def message_expansion_optimized(block):
    W = [0] * 132
    for i in range(16):
        W[i] = struct.unpack('>I', block[i * 4:(i + 1) * 4])[0]

    # 缓存前序值，减少索引访问
    for j in range(16, 68):
        w16 = W[j - 16]
        w9 = W[j - 9]
        w3_rot15 = rotate_left(W[j - 3], 15)
        part = w16 ^ w9 ^ w3_rot15
        p1 = P1(part)
        w13_rot7 = rotate_left(W[j - 13], 7)
        w6 = W[j - 6]
        W[j] = (p1 ^ w13_rot7 ^ w6) & 0xFFFFFFFF

    for j in range(68, 132):
        W[j] = (W[j - 68] ^ W[j - 64]) & 0xFFFFFFFF

    return W


def length_extension_attack(original_hash, original_len, suffix):
    # 从原始哈希恢复内部状态（作为初始向量）
    iv = [int(original_hash[i:i + 8], 16) for i in range(0, 64, 8)]

    # 构造原始消息的填充
    pad = bytearray([0x80])
    total_pad_len = 56 - (original_len % 64)
    if total_pad_len <= 0:
        total_pad_len += 64
    pad += b'\x00' * (total_pad_len - 1)
    pad += struct.pack('>Q', original_len * 8)

    # 以恢复的内部状态为IV，计算后缀的哈希
    attack_msg = pad + suffix.encode('utf-8')
    return sm3_hash(attack_msg, iv=iv)


if __name__ == "__main__":
    test_msg = b"abc"
    standard_hash = sm3_hash(test_msg)
    print(f"基础实现哈希('abc'): {standard_hash}")
    print(f"预期结果: 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e\n")

    optimized_hash = sm3_hash_optimized(test_msg)
    print(f"优化实现哈希('abc'): {optimized_hash}")
    print(f"优化前后一致性: {standard_hash == optimized_hash}\n")

    original_msg = b"secret"
    original_len = len(original_msg)
    original_hash = sm3_hash(original_msg)
    suffix = b"_extended"

    extended_msg = original_msg + b'\x80'
    while len(extended_msg) % 64 != 56:
        extended_msg += b'\x00'
    extended_msg += struct.pack('>Q', original_len * 8) + suffix
    true_hash = sm3_hash(extended_msg)

    forged_hash = length_extension_attack(original_hash, original_len, suffix.decode())
    print(f"长度扩展攻击验证:")
    print(f"真实哈希: {true_hash}")
    print(f"伪造哈希: {forged_hash}")
    print(f"攻击成功: {true_hash == forged_hash}")