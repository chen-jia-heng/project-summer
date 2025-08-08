import os
from gmssl import sm3

# SM2核心参数（GB/T 32918标准）
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
G = (int(Gx_hex, 16), int(Gy_hex, 16))  # 基点


def int_to_32bytes(num):
    """大整数转32字节（确保无符号大端）"""
    return num.to_bytes(32, byteorder='big', signed=False)


def mod_inverse(a, mod):
    """扩展欧几里得算法求模逆（确保结果为正）"""

    def extended_gcd(a, b):
        if b == 0:
            return (a, 1, 0)
        g, x, y = extended_gcd(b, a % b)
        return (g, y, x - (a // b) * y)

    g, x, y = extended_gcd(a, mod)
    if g != 1:
        return None
    return x % mod  # 强制取模确保为正


def is_on_curve(point):
    """验证点是否在椭圆曲线上（y² ≡ x³ + ax + b mod p）"""
    if point is None:
        return False
    x, y = point
    left = (y * y) % p
    right = (x * x * x + a * x + b) % p
    return left == right


def point_add(p1, p2):
    """椭圆曲线点加（严格遵循标准公式，增加曲线校验）"""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if not (is_on_curve(p1) and is_on_curve(p2)):
        return None  # 输入点不在曲线上

    x1, y1 = p1
    x2, y2 = p2

    # 逆元判断（和为无穷远点）
    if x1 == x2 and (y1 + y2) % p == 0:
        return None

    # 斜率计算
    if x1 == x2:
        # 点加倍：λ = (3x₁² + a) / (2y₁)
        numerator = (3 * pow(x1, 2, p) + a) % p
        denominator = (2 * y1) % p
    else:
        # 点相加：λ = (y2 - y1) / (x2 - x1)
        numerator = (y2 - y1) % p
        denominator = (x2 - x1) % p

    inv_den = mod_inverse(denominator, p)
    if inv_den is None:
        return None
    lam = (numerator * inv_den) % p

    # 计算新坐标（严格模p，确保在曲线上）
    x3 = (pow(lam, 2, p) - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    x3 = x3 % p  # 确保非负
    y3 = y3 % p
    result = (x3, y3)

    # 验证结果是否在曲线上
    return result if is_on_curve(result) else None


def scalar_mult(k, point):
    """标量乘法（优化迭代逻辑，增加中间结果校验）"""
    if not is_on_curve(point):
        return None
    result = None  # 无穷远点
    current = point
    k = k % n  # 确保k在[1, n-1]
    while k > 0:
        if k & 1:
            result = point_add(result, current)
            if result is None:
                return None  # 中间结果无效
        current = point_add(current, current)  # 点加倍
        if current is None:
            return None
        k >>= 1
    return result


def generate_key_pair():
    """生成密钥对（增加公钥有效性校验）"""
    while True:
        d = int.from_bytes(os.urandom(32), 'big') % (n - 1) + 1
        P = scalar_mult(d, G)
        if P is not None and is_on_curve(P):
            return d, P


def sm3_hash(data):
    """标准SM3哈希（确保输入为字节列表）"""
    return bytes.fromhex(sm3.sm3_hash([b for b in data]))


def compute_ZA(ID, PA):
    """计算ZA（严格遵循拼接顺序和格式）"""
    entla = len(ID) * 8  # 比特长度
    za_data = (
            entla.to_bytes(2, 'big') +  # 2字节ENTLA
            ID.encode('utf-8') +  # ID字节
            int_to_32bytes(a) +  # 32字节a
            int_to_32bytes(b) +  # 32字节b
            int_to_32bytes(G[0]) +  # 32字节Gx
            int_to_32bytes(G[1]) +  # 32字节Gy
            int_to_32bytes(PA[0]) +  # 32字节xA
            int_to_32bytes(PA[1])  # 32字节yA
    )
    return int.from_bytes(sm3_hash(za_data), 'big')


def sign(d, PA, ID, message):
    """签名生成（修复s的模运算符号问题）"""
    ZA = compute_ZA(ID, PA)
    # 计算e = SM3(ZA || M)
    e_bytes = sm3_hash(int_to_32bytes(ZA) + message.encode('utf-8'))
    e = int.from_bytes(e_bytes, 'big')

    while True:
        k = int.from_bytes(os.urandom(32), 'big') % (n - 1) + 1
        kG = scalar_mult(k, G)
        if kG is None:
            continue
        x1, y1 = kG
        # 计算r = (e + x1) mod n（确保非负）
        r = (e + x1) % n
        if r == 0 or (r + k) % n == 0:
            continue
        # 计算s = [(1 + d)⁻¹ · (k - r·d)] mod n（修复负数处理）
        inv_1d = mod_inverse((1 + d) % n, n)
        if inv_1d is None:
            continue
        # 确保(k - r*d)模n后为正
        s = (inv_1d * ((k - r * d) % n)) % n
        if s != 0:
            break
    return (r, s)


def verify(PA, ID, message, signature):
    """签名验证（优化点运算顺序，确保结果正确）"""
    r, s = signature
    # 范围校验
    if not (1 <= r < n and 1 <= s < n):
        return False
    if not is_on_curve(PA):
        return False  # 公钥无效

    ZA = compute_ZA(ID, PA)
    e_bytes = sm3_hash(int_to_32bytes(ZA) + message.encode('utf-8'))
    e = int.from_bytes(e_bytes, 'big')
    t = (r + s) % n
    if t == 0:
        return False

    # 优化点运算顺序，先计算tPA再与sG相加
    tPA = scalar_mult(t, PA)
    if tPA is None:
        return False
    sG = scalar_mult(s, G)
    if sG is None:
        return False
    x1y1 = point_add(tPA, sG)  # 交换顺序不影响结果，但更稳定
    if x1y1 is None:
        return False
    x1, y1 = x1y1

    # 验证R = (e + x1) mod n == r
    return (e + x1) % n == r


# 测试
if __name__ == "__main__":
    # 生成密钥对
    d, PA = generate_key_pair()
    print("公钥有效性:", is_on_curve(PA))

    ID = "ALICE123@YAHOO.COM"
    message = "Test SM2"

    # 签名
    signature = sign(d, PA, ID, message)
    print("签名:", (hex(signature[0]), hex(signature[1])))

    # 验证
    print("签名验证:", verify(PA, ID, message, signature))
