import os
import hashlib
import time
from gmssl import sm3

p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0


class Point:
    __slots__ = ['x', 'y']  # 减少内存占用

    def __init__(self, x, y):
        self.x = x
        self.y = y

    def is_infinite(self):
        return self.x is None and self.y is None

    def __eq__(self, other):
        if not isinstance(other, Point):
            return False
        return self.x == other.x and self.y == other.y

    def __repr__(self):
        if self.is_infinite():
            return "Point(infinite)"
        return f"Point(0x{self.x:x}, 0x{self.y:x})"


# 无穷远点
O = Point(None, None)
G = Point(Gx, Gy)  # 基点


def mod_inv(x, m=p):
    if x == 0:
        raise ZeroDivisionError('模逆计算中出现除以零')

    x0, x1, y0, y1 = 1, 0, 0, 1
    a, b = m, x % m

    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1

    return x0 % m


def point_add(P, Q):
    if P.is_infinite():
        return Q
    if Q.is_infinite():
        return P

    if P.x == Q.x and (P.y + Q.y) % p == 0:
        return O


    if P == Q:
        numerator = (3 * pow(P.x, 2, p) + a) % p
        denominator = (2 * P.y) % p
    else:
        numerator = (Q.y - P.y) % p
        denominator = (Q.x - P.x) % p

    inv_denominator = mod_inv(denominator)
    lam = (numerator * inv_denominator) % p

    x3 = (pow(lam, 2, p) - P.x - Q.x) % p
    y3 = (lam * (P.x - x3) - P.y) % p

    return Point(x3, y3)


def point_mul(k, P):
    if k == 0 or P.is_infinite():
        return O

    result = O
    current = P
    k = k % n  # 确保k在有效范围内

    # 使用二进制方法加速标量乘法
    while k > 0:
        if k & 1:
            result = point_add(result, current)
        current = point_add(current, current)
        k >>= 1

    return result


def generate_keypair():
    while True:
        # 生成1 <= d < n的私钥
        d_bytes = os.urandom(32)  # 256位随机数
        d = int.from_bytes(d_bytes, 'big') % (n - 1) + 1
        P = point_mul(d, G)
        if not P.is_infinite():
            return d, P


def sm3_hash(data):

    return bytes.fromhex(sm3.sm3_hash([b for b in data]))


def sign(message, d):
    if isinstance(message, str):
        message = message.encode('utf-8')  # 将字符串编码为bytes
    elif not isinstance(message, bytes):
        raise TypeError("消息必须是字符串或bytes类型")

    e = int.from_bytes(sm3_hash(message), 'big')

    while True:
        # 生成安全随机数k
        k_bytes = os.urandom(32)
        k = int.from_bytes(k_bytes, 'big') % (n - 1) + 1

        P = point_mul(k, G)
        r = (e + P.x) % n

        if r == 0 or (r + k) % n == 0:
            continue

        # 计算签名s
        inv_1d = mod_inv((1 + d) % n, n)
        s = (inv_1d * (k - r * d)) % n

        if s != 0:
            return (r, s)


def verify(message, signature, P):
    if isinstance(message, str):
        message = message.encode('utf-8')  # 将字符串编码为bytes
    elif not isinstance(message, bytes):
        raise TypeError("消息必须是字符串或bytes类型")

    if not isinstance(signature, tuple) or len(signature) != 2:
        return False

    r, s = signature
    # 范围校验
    if not (1 <= r < n and 1 <= s < n):
        return False

    e = int.from_bytes(sm3_hash(message), 'big')
    t = (r + s) % n

    if t == 0:
        return False

    # 计算验证点
    sG = point_mul(s, G)
    tP = point_mul(t, P)
    x1y1 = point_add(sG, tP)

    if x1y1.is_infinite():
        return False

    R = (e + x1y1.x) % n
    return R == r


def benchmark():
    # 生成密钥对
    d, P = generate_keypair()
    print(f"私钥 d = 0x{d:x}")
    print(f"公钥 P = {P}\n")

    # 使用字符串并在签名时编码，避免bytes包含非ASCII字面量
    msg = "Hello SM2 - 优化版实现测试"

    # 签名性能测试
    sign_rounds = 100
    sign_times = []
    print(f"开始签名性能测试 ({sign_rounds}次)...")

    for _ in range(sign_rounds):
        start = time.perf_counter()
        signature = sign(msg, d)
        end = time.perf_counter()
        sign_times.append(end - start)

    avg_sign = sum(sign_times) / sign_rounds * 1000
    print(f"签名平均耗时: {avg_sign:.3f} ms")
    print(f"签名吞吐量: {1 / (avg_sign / 1000):.2f} 次/秒\n")

    # 验证性能测试
    verify_rounds = 100
    verify_times = []
    print(f"开始验证性能测试 ({verify_rounds}次)...")

    for _ in range(verify_rounds):
        start = time.perf_counter()
        valid = verify(msg, signature, P)
        end = time.perf_counter()
        verify_times.append(end - start)

    avg_verify = sum(verify_times) / verify_rounds * 1000
    print(f"验证平均耗时: {avg_verify:.3f} ms")
    print(f"验证吞吐量: {1 / (avg_verify / 1000):.2f} 次/秒")
    print(f"验证结果: {'成功' if valid else '失败'}")


if __name__ == "__main__":
    benchmark()
