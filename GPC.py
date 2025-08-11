import os
import hashlib
import random
from gmssl import sm3

# 椭圆曲线参数 (NIST标准)
p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0


class Point:
    __slots__ = ['x', 'y']

    def __init__(self, x, y):
        self.x = x
        self.y = y

    def is_infinite(self):
        return self.x is None and self.y is None

    def __eq__(self, other):
        return isinstance(other, Point) and self.x == other.x and self.y == other.y

    def __hash__(self):
        return hash((self.x, self.y))


O = Point(None, None)
G = Point(Gx, Gy)


def mod_inverse(a, mod):
    def extended_gcd(a, b):
        if b == 0:
            return (a, 1, 0)
        g, x, y = extended_gcd(b, a % b)
        return (g, y, x - (a // b) * y)

    g, x, y = extended_gcd(a, mod)
    return x % mod if g == 1 else None


def point_add(p1, p2):
    if p1.is_infinite():
        return p2
    if p2.is_infinite():
        return p1

    if p1.x == p2.x and (p1.y + p2.y) % p == 0:
        return O

    if p1.x == p2.x:
        numerator = (3 * pow(p1.x, 2, p) + a) % p
        denominator = (2 * p1.y) % p
    else:
        numerator = (p2.y - p1.y) % p
        denominator = (p2.x - p1.x) % p

    inv_den = mod_inverse(denominator, p)
    if inv_den is None:
        return O
    lam = (numerator * inv_den) % p

    x3 = (pow(lam, 2, p) - p1.x - p2.x) % p
    y3 = (lam * (p1.x - x3) - p1.y) % p
    return Point(x3, y3)


def scalar_mult(k, point):
    result = O
    current = point
    k = k % n

    while k > 0:
        if k & 1:
            result = point_add(result, current)
        current = point_add(current, current)
        k >>= 1
    return result


def hash_to_curve(data):
    while True:
        x = int.from_bytes(hashlib.sha256(data).digest(), 'big') % p
        y_sq = (pow(x, 3, p) + a * x + b) % p
        y = pow(y_sq, (p + 1) // 4, p)
        if pow(y, 2, p) == y_sq:
            return Point(x, y)
        data = hashlib.sha256(data).digest()  # 若不满足曲线方程则重新哈希


class Paillier:
    @staticmethod
    def generate_keys():
        def generate_prime(bit_length=2048):
            while True:
                p = int.from_bytes(os.urandom(bit_length // 8), 'big') | 1
                if pow(2, p - 1, p) == 1:
                    return p

        p = generate_prime()
        q = generate_prime()
        while p == q:
            q = generate_prime()

        n = p * q
        g = n + 1
        lamb = (p - 1) * (q - 1)
        mu = mod_inverse(lamb, n)
        return (n, g), (lamb, mu)

    @staticmethod
    def encrypt(pk, m):
        n, g = pk
        r = int.from_bytes(os.urandom(32), 'big') % (n - 1) + 1
        return (pow(g, m, n * n) * pow(r, n, n * n)) % (n * n)

    @staticmethod
    def decrypt(sk, pk, c):
        n, _ = pk
        lamb, mu = sk
        return (pow(c, lamb, n * n) - 1) // n * mu % n

    @staticmethod
    def add(pk, c1, c2):
        n, _ = pk
        return (c1 * c2) % (n * n)


def user_step1(credentials, k1):
    msg1 = []
    for (username, password) in credentials:
        cred_hash = hashlib.sha256(f"{username}:{password}".encode()).digest()
        P = hash_to_curve(cred_hash)
        Q = scalar_mult(k1, P)
        msg1.append(Q)

    random.shuffle(msg1)
    return [(q.x, q.y) for q in msg1]


def server_step2(leaked_db, msg1, k2, paillier_pk):
    msg2_part1 = []
    for x, y in msg1:
        P = Point(x, y)
        Q = scalar_mult(k2, P)
        msg2_part1.append((Q.x, Q.y))

    msg2_part2 = []
    for cred_hash, count in leaked_db:
        P = hash_to_curve(cred_hash)
        Q = scalar_mult(k2, P)
        enc_count = Paillier.encrypt(paillier_pk, count)
        msg2_part2.append((Q.x, Q.y, enc_count))

    random.shuffle(msg2_part1)
    random.shuffle(msg2_part2)
    return (msg2_part1, msg2_part2)


def user_step3(msg2, k1, paillier_pk):
    msg2_part1, msg2_part2 = msg2
    user_set = {Point(x, y) for x, y in msg2_part1}
    sum_enc = 0

    for x, y, enc_count in msg2_part2:
        if Point(x, y) in user_set:
            sum_enc = enc_count if sum_enc == 0 else Paillier.add(paillier_pk, sum_enc, enc_count)

    return sum_enc


def server_step4(sum_enc, paillier_sk, paillier_pk):
    return 0 if sum_enc == 0 else Paillier.decrypt(paillier_sk, paillier_pk, sum_enc)


def main():
    # 生成随机密钥
    k1 = int.from_bytes(os.urandom(32), 'big') % (n - 1) + 1
    k2 = int.from_bytes(os.urandom(32), 'big') % (n - 1) + 1
    paillier_pk, paillier_sk = Paillier.generate_keys()

    # 测试数据
    user_credentials = [
        ("a", "password123"),
        ("b", "qwerty"),
        ("c", "securePass!2023")
    ]

    leaked_db = [
        (hashlib.sha256(b"a:password123").digest(), 5),
        (hashlib.sha256(b"d:123456").digest(), 12),
        (hashlib.sha256(b"b:qwerty").digest(), 8)
    ]

    # 执行协议
    msg1 = user_step1(user_credentials, k1)
    msg2 = server_step2(leaked_db, msg1, k2, paillier_pk)
    msg3 = user_step3(msg2, k1, paillier_pk)
    result = server_step4(msg3, paillier_sk, paillier_pk)

    print(f"泄露密码匹配次数: {result}")  # 预期: 13


if __name__ == "__main__":
    main()
