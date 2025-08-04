import struct
import random
import string
import time  # 导入时间模块


def sm3_hash(message):
    # 初始向量IV
    IV = [
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    ]

    # 消息填充
    message_bits = len(message) * 8  # 消息长度（比特）
    message += b'\x80'  # 填充1个"1"比特

    # 填充k个"0"比特，使得总长度模512 = 448
    while len(message) % 64 != 56:
        message += b'\x00'

    # 附加消息长度（64比特，小端存储）
    message += struct.pack('<Q', message_bits)

    # 将消息按512比特（64字节）分组
    blocks = [message[i:i + 64] for i in range(0, len(message), 64)]

    # 初始化哈希值
    V = IV.copy()

    # 迭代处理每个分组
    for block in blocks:
        V = compress_func(V, block)

    # 将哈希值转换为16进制字符串
    return ''.join(f'{x:08x}' for x in V)


def compress_func(V, B):
    # 消息扩展：将512比特分组扩展为132个32位字W[0..131]
    W = message_expansion(B)

    # 初始化工作变量
    A, B, C, D, E, F, G, H = V

    # 64轮迭代
    for j in range(64):
        if j < 16:
            SS1 = rotate_left(((A << 12) | (A >> 20)) + E + rotate_left(W[j], j), 7)
            SS2 = SS1 ^ rotate_left(A, 12)
            TT1 = (FF(A, B, C, j) + D + SS2 + W[j + 68]) & 0xFFFFFFFF
            TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
        else:
            SS1 = rotate_left(((A << 12) | (A >> 20)) + E + rotate_left(W[j], j % 32), 7)
            SS2 = SS1 ^ rotate_left(A, 12)
            TT1 = (FF(A, B, C, j) + D + SS2 + W[j + 68]) & 0xFFFFFFFF
            TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF

        # 更新工作变量
        D, C, B, A, H, G, F, E = TT1, A, B, C, TT2, E, F, G

    # 与前一轮哈希值异或
    return [
        (V[0] ^ A) & 0xFFFFFFFF,
        (V[1] ^ B) & 0xFFFFFFFF,
        (V[2] ^ C) & 0xFFFFFFFF,
        (V[3] ^ D) & 0xFFFFFFFF,
        (V[4] ^ E) & 0xFFFFFFFF,
        (V[5] ^ F) & 0xFFFFFFFF,
        (V[6] ^ G) & 0xFFFFFFFF,
        (V[7] ^ H) & 0xFFFFFFFF
    ]


def message_expansion(B):
    # 将B拆分为16个32位字W[0..15]（小端存储）
    W = [struct.unpack('<I', B[i:i + 4])[0] for i in range(0, 64, 4)]

    # 扩展生成W[16..67]
    for j in range(16, 68):
        Wj = (P1(W[j - 16] ^ W[j - 9] ^ rotate_left(W[j - 3], 15)) ^
              rotate_left(W[j - 13], 7) ^ W[j - 6]) & 0xFFFFFFFF
        W.append(Wj)

    # 扩展生成W[68..131]
    for j in range(68, 132):
        W.append((W[j - 68] ^ W[j - 64]) & 0xFFFFFFFF)

    return W


def FF(X, Y, Z, j):
    """布尔函数FF"""
    if j < 16:
        return X ^ Y ^ Z
    else:
        return (X & Y) | (X & Z) | (Y & Z)


def GG(X, Y, Z, j):
    """布尔函数GG"""
    if j < 16:
        return X ^ Y ^ Z
    else:
        return (X & Y) | ((~X) & Z)


def P1(X):
    """置换函数P1"""
    return X ^ rotate_left(X, 15) ^ rotate_left(X, 23)


def rotate_left(x, n):
    """32位整数左旋转n位"""
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF  # 保持32位无符号整数


# 测试示例
if __name__ == "__main__":
    # 生成随机消息（固定一条消息用于多次哈希，避免消息生成耗时干扰）
    random_length = random.randint(1, 100)
    random_chars = string.ascii_letters + string.digits + string.punctuation
    random_str = ''.join(random.choice(random_chars) for _ in range(random_length))
    random_msg = random_str.encode('utf-8')

    print("随机消息:   ", random_str)
    print("消息长度:   ", random_length, "个字符")

    # 计算单次哈希并输出结果
    single_hash = sm3_hash(random_msg)
    print("随机消息哈希:", single_hash)

    # 记录10000次哈希的时间
    iterations = 10000
    start_time = time.perf_counter()  # 开始计时

    for _ in range(iterations):
        sm3_hash(random_msg)  # 重复计算同一条消息的哈希

    end_time = time.perf_counter()  # 结束计时

    # 计算耗时统计
    total_time = end_time - start_time
    avg_time = total_time / iterations * 1000  # 平均耗时（毫秒）

    print(f"\n{iterations}次哈希总耗时: {total_time:.4f} 秒")
    print(f"单次哈希平均耗时: {avg_time:.6f} 毫秒")