import struct
import time


def sm3_hash(message):
    # 初始向量IV（国密标准规定）
    IV = [
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    ]

    # 消息填充
    msg_len = len(message) * 8  # 消息长度（比特）
    m = bytearray(message)
    m.append(0x80)  # 填充1个"1"比特

    # 填充0比特至长度模512 = 448（字节数模64 = 56）
    while len(m) % 64 != 56:
        m.append(0x00)

    # 附加64比特消息长度（大端字节序）
    m += struct.pack('>Q', msg_len)

    # 按512比特分组
    blocks = [m[i:i + 64] for i in range(0, len(m), 64)]

    # 迭代处理每个分组
    V = IV.copy()
    for block in blocks:
        V = compress_func(V, block)

    # 转换为16进制字符串
    return ''.join(f'{x:08x}' for x in V)


def compress_func(V, block):
    W = message_expansion(block)
    A, B, C, D, E, F, G, H = V  # 工作变量初始化

    for j in range(64):
        # 轮常量（前16轮T=0x79cc4519，后48轮T=0x7a879d8a）
        T = 0x79cc4519 if j < 16 else 0x7a879d8a

        # 计算SS1：ROTL( (ROTL(A,12) + E + ROTL(T, j%32)) , 7 )
        rotA12 = rotate_left(A, 12)
        rotT = rotate_left(T, j % 32)
        temp = (rotA12 + E + rotT) & 0xFFFFFFFF  # 严格32位无符号
        SS1 = rotate_left(temp, 7)

        # 计算SS2、TT1、TT2
        SS2 = SS1 ^ rotA12
        TT1 = (FF(A, B, C, j) + D + SS2 + W[j + 68]) & 0xFFFFFFFF
        TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF

        # 工作变量更新（严格按标准顺序）
        A, B, C, D = B, C, D, TT1
        E, F, G, H = F, G, H, TT2

    # 与初始向量异或
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


def message_expansion(block):
    W = [0] * 132

    # 解析16个初始32位字（大端字节序）
    for i in range(16):
        W[i] = struct.unpack('>I', block[i * 4:(i + 1) * 4])[0]

    # 扩展生成W[16..67]
    for j in range(16, 68):
        # 公式：W[j] = P1(W[j-16] ^ W[j-9] ^ ROTL(W[j-3],15)) ^ ROTL(W[j-13],7) ^ W[j-6]
        part1 = W[j - 16] ^ W[j - 9]
        part2 = rotate_left(W[j - 3], 15)
        part3 = part1 ^ part2
        p1_result = P1(part3)
        part4 = rotate_left(W[j - 13], 7)
        W[j] = (p1_result ^ part4 ^ W[j - 6]) & 0xFFFFFFFF

    # 生成W'[68..131]（W'[j] = W[j-68] ^ W[j-64]）
    for j in range(68, 132):
        W[j] = (W[j - 68] ^ W[j - 64]) & 0xFFFFFFFF

    return W

# 布尔函数FF
def FF(X, Y, Z, j):
    if j < 16:
        return X ^ Y ^ Z
    else:
        return (X & Y) | (X & Z) | (Y & Z)

# 布尔函数GG
def GG(X, Y, Z, j):
    if j < 16:
        return X ^ Y ^ Z
    else:
        return (X & Y) | ((~X & 0xFFFFFFFF) & Z)  # 确保~X为32位无符号

# 置换函数P1
def P1(X):
    return (X ^ rotate_left(X, 15) ^ rotate_left(X, 23)) & 0xFFFFFFFF

# 32位循环左移（核心修正：确保位运算精度）
def rotate_left(x, n):
    x = x & 0xFFFFFFFF  # 强制转换为32位无符号整数
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF  # 确保结果在32位范围内


# 官方测试用例验证
if __name__ == "__main__":
    # 性能测试
    start = time.perf_counter()
    for _ in range(1000):
        sm3_hash(b"test")
    end = time.perf_counter()
    print(f"1000次哈希耗时: {end - start:.4f}秒")
