import json
import hashlib
import random
import math
from typing import Tuple

# ==================== 全局常量（严格对齐项目文档3.3.7） ====================
DES_BLOCK_SIZE = 8  # DES块大小8字节(64位)
RSA_KEY_SIZE = 2048  # RSA密钥长度2048位
RSA_MODULUS_BYTES = RSA_KEY_SIZE // 8  # 256字节
HASH_ALGORITHM = hashlib.sha256
JSON_SEPARATORS = (',', ':')  # 无多余空白的JSON序列化

# ==================== DES算法实现 ====================
# DES初始置换表IP
IP_TABLE = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# DES逆初始置换表IP^-1
IP_INV_TABLE = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# DES扩展置换表E
E_TABLE = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

# DES S盒(8个)
S_BOXES = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# DES置换表P
P_TABLE = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]

# DES密钥置换表PC-1
PC1_TABLE = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

# DES密钥置换表PC-2
PC2_TABLE = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
]

# DES每轮左移位数
SHIFT_TABLE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def _bytes_to_bits(data: bytes) -> list[int]:
    """字节转比特列表(高位在前)"""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def _bits_to_bytes(bits: list[int]) -> bytes:
    """比特列表转字节"""
    bytes_data = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        bytes_data.append(byte)
    return bytes(bytes_data)

def _permute(bits: list[int], table: list[int]) -> list[int]:
    """通用置换函数"""
    return [bits[i - 1] for i in table]

def _left_shift(bits: list[int], shift: int) -> list[int]:
    """循环左移"""
    return bits[shift:] + bits[:shift]

def _generate_subkeys(key: bytes) -> list[list[int]]:
    """生成16轮DES子密钥"""
    key_bits = _bytes_to_bits(key)
    # PC-1置换(64位→56位)
    pc1_bits = _permute(key_bits, PC1_TABLE)
    # 分为左右两部分
    left = pc1_bits[:28]
    right = pc1_bits[28:]
    subkeys = []
    # 16轮移位和PC-2置换
    for shift in SHIFT_TABLE:
        left = _left_shift(left, shift)
        right = _left_shift(right, shift)
        combined = left + right
        subkey = _permute(combined, PC2_TABLE)
        subkeys.append(subkey)
    return subkeys

def _feistel_function(right: list[int], subkey: list[int]) -> list[int]:
    """DES Feistel函数"""
    # 扩展置换(32位→48位)
    expanded = _permute(right, E_TABLE)
    # 与子密钥异或
    xored = [expanded[i] ^ subkey[i] for i in range(48)]
    # S盒替换(48位→32位)
    s_output = []
    for i in range(8):
        block = xored[i*6 : (i+1)*6]
        row = (block[0] << 1) | block[5]
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
        val = S_BOXES[i][row][col]
        # 转换为4位二进制
        s_output.extend([(val >> j) & 1 for j in range(3, -1, -1)])
    # P盒置换
    return _permute(s_output, P_TABLE)

def _des_block(block: bytes, subkeys: list[list[int]], encrypt: bool) -> bytes:
    """处理单个DES块"""
    block_bits = _bytes_to_bits(block)
    # 初始置换
    ip_bits = _permute(block_bits, IP_TABLE)
    # 分为左右两部分
    left = ip_bits[:32]
    right = ip_bits[32:]
    # 16轮Feistel网络
    for i in range(16):
        subkey = subkeys[i] if encrypt else subkeys[15 - i]
        new_left = right
        new_right = [left[j] ^ _feistel_function(right, subkey)[j] for j in range(32)]
        left, right = new_left, new_right
    # 左右交换并逆初始置换
    combined = right + left
    cipher_bits = _permute(combined, IP_INV_TABLE)
    return _bits_to_bytes(cipher_bits)

def _pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """PKCS7填充"""
    pad_length = block_size - (len(data) % block_size)
    return data + bytes([pad_length] * pad_length)

def _pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    """PKCS7去填充"""
    pad_length = data[-1]
    if pad_length < 1 or pad_length > block_size:
        raise ValueError("Invalid PKCS7 padding")
    if data[-pad_length:] != bytes([pad_length] * pad_length):
        raise ValueError("Invalid PKCS7 padding")
    return data[:-pad_length]

def DESEncrypt(key: bytes, plain: bytes) -> bytes:
    """DES-ECB加密(严格对齐原pycryptodome实现)"""
    if len(key) != DES_BLOCK_SIZE:
        raise ValueError(f"DES key must be {DES_BLOCK_SIZE} bytes")
    subkeys = _generate_subkeys(key)
    padded_plain = _pkcs7_pad(plain, DES_BLOCK_SIZE)
    cipher = bytearray()
    for i in range(0, len(padded_plain), DES_BLOCK_SIZE):
        block = padded_plain[i:i+DES_BLOCK_SIZE]
        cipher.extend(_des_block(block, subkeys, encrypt=True))
    return bytes(cipher)

def DESDecrypt(key: bytes, cipher: bytes) -> bytes:
    """DES-ECB解密"""
    if len(key) != DES_BLOCK_SIZE:
        raise ValueError(f"DES key must be {DES_BLOCK_SIZE} bytes")
    if len(cipher) % DES_BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must be multiple of DES block size")
    subkeys = _generate_subkeys(key)
    plain = bytearray()
    for i in range(0, len(cipher), DES_BLOCK_SIZE):
        block = cipher[i:i+DES_BLOCK_SIZE]
        plain.extend(_des_block(block, subkeys, encrypt=False))
    return _pkcs7_unpad(bytes(plain), DES_BLOCK_SIZE)

# ==================== RSA算法实现 ====================
def _mod_pow(base: int, exponent: int, modulus: int) -> int:
    """快速模幂运算(避免Python内置pow的优化差异)"""
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

def _miller_rabin_test(n: int, k: int = 64) -> bool:
    """Miller-Rabin素性测试(2048位用64轮测试足够安全)"""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    # 分解n-1 = d*2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    # 进行k轮测试
    for _ in range(k):
        a = random.randint(2, min(n - 2, 2**32 - 1))
        x = _mod_pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = _mod_pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def _generate_prime(bit_length: int) -> int:
    """生成指定位数的大素数"""
    while True:
        # 生成随机奇数
        prime_candidate = random.getrandbits(bit_length)
        # 设置最高位和最低位为1
        prime_candidate |= (1 << (bit_length - 1)) | 1
        if _miller_rabin_test(prime_candidate):
            return prime_candidate

def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """扩展欧几里得算法求模逆"""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = _extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def _mod_inverse(a: int, m: int) -> int:
    """求a在模m下的逆元"""
    g, x, y = _extended_gcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    else:
        return x % m

def generate_rsa_key_pair(bit_length: int = RSA_KEY_SIZE) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """生成RSA密钥对(公钥(e,n), 私钥(d,n))"""
    e = 65537  # 固定公钥指数
    while True:
        p = _generate_prime(bit_length // 2)
        q = _generate_prime(bit_length // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            break
    d = _mod_inverse(e, phi)
    return ((e, n), (d, n))

def rsa_private_encrypt(private_key: Tuple[int, int], data: bytes) -> bytes:
    """RSA私钥加密(用于签名,无填充)"""
    d, n = private_key
    if len(data) > RSA_MODULUS_BYTES:
        raise ValueError(f"Data too large for RSA key: {len(data)} > {RSA_MODULUS_BYTES}")
    m = int.from_bytes(data, byteorder='big')
    c = _mod_pow(m, d, n)
    return c.to_bytes(RSA_MODULUS_BYTES, byteorder='big')

def rsa_public_decrypt(public_key: Tuple[int, int], data: bytes) -> bytes:
    """RSA公钥解密(用于验签,无填充)"""
    e, n = public_key
    if len(data) != RSA_MODULUS_BYTES:
        raise ValueError(f"Invalid ciphertext length: {len(data)} != {RSA_MODULUS_BYTES}")
    c = int.from_bytes(data, byteorder='big')
    m = _mod_pow(c, e, n)
    return m.to_bytes(RSA_MODULUS_BYTES, byteorder='big')

def import_rsa_key(key_data: bytes) -> Tuple[int, int]:
    """导入PEM格式RSA密钥(兼容OpenSSL生成的密钥)"""
    from Crypto.PublicKey import RSA  # 仅用于导入PEM格式,不用于加密
    key = RSA.import_key(key_data)
    if key.has_private():
        return (key.d, key.n)
    else:
        return (key.e, key.n)

# ==================== 对外接口(与原版本完全兼容) ====================
def Hash64(data: bytes | str) -> bytes:
    """生成64位摘要(对齐3.1.5.2)"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return HASH_ALGORITHM(data).digest()[:8]

def CanonicalJson(data: dict) -> str:
    """生成稳定JSON序列化结果(用于签名验签)"""
    return json.dumps(data, sort_keys=True, separators=JSON_SEPARATORS)

def RSASign(private_key: object, data: bytes) -> bytes:
    """RSA签名(严格对齐3.3.7: SHA-256 + 左补0到256字节 + 无填充)"""
    # 兼容原pycryptodome的RSAKey对象
    if hasattr(private_key, 'd') and hasattr(private_key, 'n'):
        priv_key = (private_key.d, private_key.n)
    else:
        priv_key = private_key
    
    # 步骤1: SHA-256哈希
    hash_obj = HASH_ALGORITHM(data)
    hash_bytes = hash_obj.digest()
    
    # 步骤2: 左补0到256字节
    padded_hash = b'\x00' * (RSA_MODULUS_BYTES - 32) + hash_bytes
    
    # 步骤3: RSA私钥加密(无填充)
    return rsa_private_encrypt(priv_key, padded_hash)

def RSAVerify(public_key: object, data: bytes, sign: bytes) -> bool:
    """RSA验签"""
    # 兼容原pycryptodome的RSAKey对象
    if hasattr(public_key, 'e') and hasattr(public_key, 'n'):
        pub_key = (public_key.e, public_key.n)
    else:
        pub_key = public_key
    
    try:
        # 步骤1: RSA公钥解密
        decrypted = rsa_public_decrypt(pub_key, sign)
        
        # 步骤2: 计算原始数据的哈希
        hash_obj = HASH_ALGORITHM(data)
        expected_hash = hash_obj.digest()
        
        # 步骤3: 比较解密后的哈希(忽略前224个0字节)
        return decrypted[-32:] == expected_hash
    except Exception:
        return False

def VerifyCertificateSignature(cert_body: dict, ca_public_key: object, ca_signature: bytes) -> bool:
    """验证证书CA签名(对齐3.1.5.2)"""
    canonical_body = CanonicalJson(cert_body).encode('utf-8')
    return RSAVerify(ca_public_key, canonical_body, ca_signature)