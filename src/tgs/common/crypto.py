#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
密码学模块 - 与 client.py 完全一致的手写 DES-ECB + PKCS7 和 SHA-256
"""

import json
import random
from typing import Optional, Union

# ================== 手写 SHA-256 ==================
_SHA256_K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]

def _rrot32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def SHA256(data: bytes) -> bytes:
    h0 = 0x6A09E667
    h1 = 0xBB67AE85
    h2 = 0x3C6EF372
    h3 = 0xA54FF53A
    h4 = 0x510E527F
    h5 = 0x9B05688C
    h6 = 0x1F83D9AB
    h7 = 0x5BE0CD19

    bit_len = len(data) * 8
    msg = bytearray(data)
    msg.append(0x80)
    while (len(msg) % 64) != 56:
        msg.append(0x00)
    msg += bit_len.to_bytes(8, "big")

    for i in range(0, len(msg), 64):
        chunk = msg[i:i + 64]
        w = [0] * 64
        for t in range(16):
            w[t] = int.from_bytes(chunk[t * 4:t * 4 + 4], "big")
        for t in range(16, 64):
            s0 = _rrot32(w[t - 15], 7) ^ _rrot32(w[t - 15], 18) ^ (w[t - 15] >> 3)
            s1 = _rrot32(w[t - 2], 17) ^ _rrot32(w[t - 2], 19) ^ (w[t - 2] >> 10)
            w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & 0xFFFFFFFF

        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
        for t in range(64):
            s1 = _rrot32(e, 6) ^ _rrot32(e, 11) ^ _rrot32(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + s1 + ch + _SHA256_K[t] + w[t]) & 0xFFFFFFFF
            s0 = _rrot32(a, 2) ^ _rrot32(a, 13) ^ _rrot32(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFF

    return b"".join(x.to_bytes(4, "big") for x in [h0, h1, h2, h3, h4, h5, h6, h7])


# ================== 手写 DES（ECB + PKCS7）==================
_DES_IP = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
]
_DES_FP = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
]
_DES_E = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23,
    24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
]
_DES_P = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
]
_DES_PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
    29, 21, 13, 5, 28, 20, 12, 4,
]
_DES_PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
]
_DES_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
_DES_SBOX = [
    [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],[4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
    [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],[0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
    [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],[13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
    [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],[10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
    [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],[4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
    [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],[9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
    [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],[1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
    [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],[7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]],
]

def _permute_by_table(v: int, in_bits: int, table: list) -> int:
    out = 0
    for pos in table:
        bit = (v >> (in_bits - pos)) & 1
        out = (out << 1) | bit
    return out

def _left_rotate(v: int, shift: int, bits: int) -> int:
    mask = (1 << bits) - 1
    return ((v << shift) & mask) | (v >> (bits - shift))

def _des_subkeys(key8: bytes) -> list:
    key64 = int.from_bytes(key8, "big")
    key56 = _permute_by_table(key64, 64, _DES_PC1)
    c = (key56 >> 28) & ((1 << 28) - 1)
    d = key56 & ((1 << 28) - 1)
    keys = []
    for s in _DES_SHIFTS:
        c = _left_rotate(c, s, 28)
        d = _left_rotate(d, s, 28)
        cd = (c << 28) | d
        keys.append(_permute_by_table(cd, 56, _DES_PC2))
    return keys

def _des_f(r32: int, subkey48: int) -> int:
    exp48 = _permute_by_table(r32, 32, _DES_E)
    x = exp48 ^ subkey48
    out32 = 0
    for i in range(8):
        block6 = (x >> (42 - 6 * i)) & 0x3F
        row = ((block6 & 0x20) >> 4) | (block6 & 0x01)
        col = (block6 >> 1) & 0x0F
        s = _DES_SBOX[i][row][col]
        out32 = (out32 << 4) | s
    return _permute_by_table(out32, 32, _DES_P)

def _des_crypt_block(block8: bytes, subkeys: list, decrypt: bool = False) -> bytes:
    x = int.from_bytes(block8, "big")
    ip = _permute_by_table(x, 64, _DES_IP)
    l = (ip >> 32) & 0xFFFFFFFF
    r = ip & 0xFFFFFFFF
    keys = list(reversed(subkeys)) if decrypt else subkeys
    for k in keys:
        l, r = r, (l ^ _des_f(r, k)) & 0xFFFFFFFF
    preout = (r << 32) | l
    fp = _permute_by_table(preout, 64, _DES_FP)
    return fp.to_bytes(8, "big")

def PKCS7Pad(data: bytes, block_size: int = 8) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len] * pad_len)

def PKCS7Unpad(data: bytes, block_size: int = 8) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("invalid padded data")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("invalid padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("invalid padding bytes")
    return data[:-pad_len]

def DESEncrypt(key8: bytes, plain: bytes) -> bytes:
    """DES-ECB 加密，自动 PKCS7 填充"""
    if len(key8) != 8:
        raise ValueError("DES key must be 8 bytes")
    subkeys = _des_subkeys(key8)
    data = PKCS7Pad(plain, 8)
    out = bytearray()
    for i in range(0, len(data), 8):
        out.extend(_des_crypt_block(data[i:i+8], subkeys, decrypt=False))
    return bytes(out)

def DESDecrypt(key8: bytes, cipher_bytes: bytes) -> Optional[bytes]:
    """DES-ECB 解密，自动去除 PKCS7 填充，失败返回 None"""
    try:
        if len(key8) != 8:
            raise ValueError("DES key must be 8 bytes")
        if len(cipher_bytes) % 8 != 0:
            return None
        subkeys = _des_subkeys(key8)
        out = bytearray()
        for i in range(0, len(cipher_bytes), 8):
            out.extend(_des_crypt_block(cipher_bytes[i:i+8], subkeys, decrypt=True))
        return PKCS7Unpad(bytes(out), 8)
    except Exception:
        return None


# ================== Crypto 类（统一接口） ==================
class Crypto:
    @staticmethod
    def hash64(data: Union[str, bytes]) -> bytes:
        """64位哈希（SHA-256前8字节）"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return SHA256(data)[:8]

    @staticmethod
    def canonical_json(obj: dict) -> str:
        return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

    @staticmethod
    def des_encrypt(key: bytes, plain: bytes) -> bytes:
        return DESEncrypt(key, plain)

    @staticmethod
    def des_decrypt(key: bytes, cipher_bytes: bytes) -> Optional[bytes]:
        return DESDecrypt(key, cipher_bytes)

    @staticmethod
    def generate_random_key() -> bytes:
        return bytes([random.randint(0, 255) for _ in range(8)])

    @staticmethod
    def hex_to_bytes(hex_str: str) -> bytes:
        return bytes.fromhex(hex_str)

    @staticmethod
    def bytes_to_hex(data: bytes) -> str:
        return data.hex()


# 为方便旧代码直接调用，导出函数（可选）
Hash64 = Crypto.hash64
CanonicalJson = Crypto.canonical_json
GenerateRandomKey = Crypto.generate_random_key
HexToBytes = Crypto.hex_to_bytes
BytesToHex = Crypto.bytes_to_hex
