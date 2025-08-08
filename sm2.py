import os
import hashlib

# SM2核心参数（文档1-32定义）
p_hex = "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3"
a_hex = "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"
b_hex = "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"
n_hex = "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7"
Gx_hex = "421DEBD61B62EAB6746434EBC3CC315E32220B3BADDD50BDC4C4E6C147FEDD43D"
Gy_hex = "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"

p = int(p_hex, 16)
a = int(a_hex, 16)
b = int(b_hex, 16)
n = int(n_hex, 16)
h = 1  # 余因子（文档1-23）
G = (int(Gx_hex, 16), int(Gy_hex, 16))  # 基点（文档1-32）


def int_to_32bytes(num):
    """大整数转32字节（解决溢出问题）"""
    hex_str = hex(num)[2:].zfill(64)
    if len(hex_str) > 64:
        hex_str = hex_str[-64:]
    return bytes.fromhex(hex_str)


def mod_inverse(a, mod):
    """扩展欧几里得算法求模逆（文档1-82）"""

    def extended_gcd(a, b):
        if b == 0:
            return (a, 1, 0)
        g, x, y = extended_gcd(b, a % b)
        return (g, y, x - (a // b) * y)

    g, x, y = extended_gcd(a, mod)
    return x % mod if g == 1 else None


def point_add(p1, p2):
    """椭圆曲线点加（文档1-18曲线方程）"""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and (y1 + y2) % p == 0:
        return None  # 逆元

    if x1 == x2:
        # 点加倍：λ=(3x₁² + a)/(2y₁)（文档1-18）
        numerator = (3 * pow(x1, 2, p) + a) % p
        denominator = (2 * y1) % p
    else:
        # 点相加：λ=(y2 - y1)/(x2 - x1)
        numerator = (y2 - y1) % p
        denominator = (x2 - x1) % p

    inv_den = mod_inverse(denominator, p)
    if inv_den is None:
        return None
    lam = (numerator * inv_den) % p

    x3 = (pow(lam, 2, p) - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def scalar_mult(k, point):
    """标量乘法（文档1-83双倍加法）"""
    result = None
    current = point
    k = k % n
    while k > 0:
        if k & 1:
            result = point_add(result, current)
        current = point_add(current, current)
        k >>= 1
    return result


def generate_key_pair():
    """密钥对生成（文档1-35）"""
    d = int.from_bytes(os.urandom(32), 'big') % (n - 1) + 1
    P = scalar_mult(d, G)
    return d, P


def sm3_hash(data):
    """SM3哈希模拟（文档1-35）"""
    return hashlib.sha256(data).digest()


def compute_ZA(ID, PA):
    """计算ZA（文档1-35）"""
    entla = len(ID) * 8
    za_data = entla.to_bytes(2, 'big') + ID.encode() + \
              int_to_32bytes(a) + int_to_32bytes(b) + \
              int_to_32bytes(G[0]) + int_to_32bytes(G[1]) + \
              int_to_32bytes(PA[0]) + int_to_32bytes(PA[1])
    return int.from_bytes(sm3_hash(za_data), 'big')


def sign(d, PA, ID, message):
    """签名生成（文档1-36）"""
    ZA = compute_ZA(ID, PA)
    e = int.from_bytes(sm3_hash(int_to_32bytes(ZA) + message.encode()), 'big')

    while True:
        k = int.from_bytes(os.urandom(32), 'big') % (n - 1) + 1
        kG = scalar_mult(k, G)
        if kG is None:
            continue
        x1, y1 = kG
        r = (e + x1) % n
        if r == 0 or (r + k) % n == 0:
            continue
        inv_1d = mod_inverse((1 + d) % n, n)
        if inv_1d is None:
            continue
        s = (inv_1d * (k - r * d)) % n
        if s != 0:
            break
    return (r, s)


def verify(PA, ID, message, signature):
    """签名验证（文档1-45）"""
    r, s = signature
    if not (1 <= r < n and 1 <= s < n):
        return False

    ZA = compute_ZA(ID, PA)
    e = int.from_bytes(sm3_hash(int_to_32bytes(ZA) + message.encode()), 'big')
    t = (r + s) % n
    if t == 0:
        return False

    sG = scalar_mult(s, G)
    tPA = scalar_mult(t, PA)
    x1y1 = point_add(sG, tPA)
    if x1y1 is None:
        return False
    x1, y1 = x1y1

    return (e + x1) % n == r


# 测试
if __name__ == "__main__":
    d, PA = generate_key_pair()
    ID = "ALICE123@YAHOO.COM"
    message = "Test SM2"

    signature = sign(d, PA, ID, message)
    print("签名验证:", verify(PA, ID, message, signature))