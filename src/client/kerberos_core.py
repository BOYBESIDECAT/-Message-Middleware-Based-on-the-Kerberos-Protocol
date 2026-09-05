#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kerberos shared core: packet, DES, SHA256, config, logging."""

import json
import os
import queue
import socket
import struct
import threading
from datetime import datetime, timezone

# message types
MSG_AS_REQUEST = 0x01
MSG_AS_RESPONSE = 0x02
MSG_TGS_REQUEST = 0x03
MSG_TGS_RESPONSE = 0x04
MSG_SERVICE_REQUEST = 0x05
MSG_SERVICE_RESPONSE = 0x06
MSG_CHAT_HISTORY_REQUEST = 0x07
MSG_CHAT_HISTORY_RESPONSE = 0x08
MSG_CHAT_SEND = 0x09
MSG_CHAT_BROADCAST = 0x0A
MSG_ERROR_RESPONSE = 0x0B

DEFAULT_SKEW_SECONDS = 300
DEFAULT_LIFETIME2 = 600
DEFAULT_LIFETIME4 = 600


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

_DES_IP = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64,
    56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45,
    37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
]
_DES_FP = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5,
    45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10,
    50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
]
_DES_E = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19,
    20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
]
_DES_P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
_DES_PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52,
    44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5,
    28, 20, 12, 4,
]
_DES_PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31,
    37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
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


def utc_now_str():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def canonical_json(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash64(text: str) -> bytes:
    return sha256(text.encode("utf-8"))[:8]


def _rrot32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def sha256(data: bytes) -> bytes:
    h0, h1, h2, h3, h4, h5, h6, h7 = 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    bit_len = len(data) * 8
    msg = bytearray(data)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += bit_len.to_bytes(8, "big")
    for i in range(0, len(msg), 64):
        c = msg[i:i+64]
        w = [0] * 64
        for t in range(16):
            w[t] = int.from_bytes(c[t*4:t*4+4], "big")
        for t in range(16, 64):
            s0 = _rrot32(w[t-15], 7) ^ _rrot32(w[t-15], 18) ^ (w[t-15] >> 3)
            s1 = _rrot32(w[t-2], 17) ^ _rrot32(w[t-2], 19) ^ (w[t-2] >> 10)
            w[t] = (w[t-16] + s0 + w[t-7] + s1) & 0xFFFFFFFF
        a, b, c2, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
        for t in range(64):
            s1 = _rrot32(e, 6) ^ _rrot32(e, 11) ^ _rrot32(e, 25)
            ch = (e & f) ^ ((~e) & g)
            t1 = (h + s1 + ch + _SHA256_K[t] + w[t]) & 0xFFFFFFFF
            s0 = _rrot32(a, 2) ^ _rrot32(a, 13) ^ _rrot32(a, 22)
            maj = (a & b) ^ (a & c2) ^ (b & c2)
            t2 = (s0 + maj) & 0xFFFFFFFF
            h, g, f, e, d, c2, b, a = g, f, e, (d + t1) & 0xFFFFFFFF, c2, b, a, (t1 + t2) & 0xFFFFFFFF
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c2) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFF
    return b"".join(x.to_bytes(4, "big") for x in [h0, h1, h2, h3, h4, h5, h6, h7])


def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    n = block_size - (len(data) % block_size)
    if n == 0:
        n = block_size
    return data + bytes([n] * n)


def pkcs7_unpad(data: bytes, block_size: int = 8) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("invalid padded data")
    n = data[-1]
    if n < 1 or n > block_size or data[-n:] != bytes([n] * n):
        raise ValueError("invalid padding")
    return data[:-n]


def _permute(v: int, in_bits: int, table: list) -> int:
    out = 0
    for p in table:
        out = (out << 1) | ((v >> (in_bits - p)) & 1)
    return out


def _rol(v: int, s: int, bits: int) -> int:
    m = (1 << bits) - 1
    return ((v << s) & m) | (v >> (bits - s))


def _des_subkeys(key8: bytes):
    key64 = int.from_bytes(key8, "big")
    key56 = _permute(key64, 64, _DES_PC1)
    c = (key56 >> 28) & ((1 << 28) - 1)
    d = key56 & ((1 << 28) - 1)
    keys = []
    for s in _DES_SHIFTS:
        c = _rol(c, s, 28)
        d = _rol(d, s, 28)
        keys.append(_permute((c << 28) | d, 56, _DES_PC2))
    return keys


def _des_f(r32: int, k48: int) -> int:
    x = _permute(r32, 32, _DES_E) ^ k48
    out = 0
    for i in range(8):
        b = (x >> (42 - i * 6)) & 0x3F
        row = ((b & 0x20) >> 4) | (b & 1)
        col = (b >> 1) & 0x0F
        out = (out << 4) | _DES_SBOX[i][row][col]
    return _permute(out, 32, _DES_P)


def _des_block(block8: bytes, keys, decrypt=False) -> bytes:
    x = int.from_bytes(block8, "big")
    x = _permute(x, 64, _DES_IP)
    l, r = (x >> 32) & 0xFFFFFFFF, x & 0xFFFFFFFF
    it = reversed(keys) if decrypt else keys
    for k in it:
        l, r = r, (l ^ _des_f(r, k)) & 0xFFFFFFFF
    y = _permute((r << 32) | l, 64, _DES_FP)
    return y.to_bytes(8, "big")


def des_encrypt(key8: bytes, plain: bytes) -> bytes:
    if len(key8) != 8:
        raise ValueError("DES key must be 8 bytes")
    keys = _des_subkeys(key8)
    plain = pkcs7_pad(plain, 8)
    out = bytearray()
    for i in range(0, len(plain), 8):
        out.extend(_des_block(plain[i:i+8], keys, decrypt=False))
    return bytes(out)


def des_decrypt(key8: bytes, cipher: bytes) -> bytes:
    if len(key8) != 8 or len(cipher) % 8 != 0:
        raise ValueError("invalid DES input")
    keys = _des_subkeys(key8)
    out = bytearray()
    for i in range(0, len(cipher), 8):
        out.extend(_des_block(cipher[i:i+8], keys, decrypt=True))
    return pkcs7_unpad(bytes(out), 8)


def build_packet(msg_type: int, payload: bytes) -> bytes:
    total_len = 1 + len(payload)
    return struct.pack("!I", total_len) + bytes([msg_type]) + payload


def send_all(conn: socket.socket, data: bytes):
    p = 0
    while p < len(data):
        n = conn.send(data[p:])
        if n <= 0:
            raise ConnectionError("send failed")
        p += n


def _read_exact(conn: socket.socket, size: int) -> bytes:
    out = b""
    while len(out) < size:
        c = conn.recv(size - len(out))
        if not c:
            raise ConnectionError("connection closed")
        out += c
    return out


def read_packet(conn: socket.socket):
    head = _read_exact(conn, 4)
    total_len = struct.unpack("!I", head)[0]
    if total_len < 1:
        raise ValueError("INVALID_PACKET_LENGTH")
    body = _read_exact(conn, total_len)
    msg_type = body[0]
    payload = json.loads(body[1:].decode("utf-8"))
    return msg_type, payload


def error_packet(code: str, message: str) -> bytes:
    payload = {"data": {"error_code": code, "message": message}}
    return build_packet(MSG_ERROR_RESPONSE, json.dumps(payload, ensure_ascii=False).encode("utf-8"))


def load_kv_config(path: str, defaults: dict) -> dict:
    cfg = dict(defaults)
    if not os.path.exists(path):
        return cfg
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip()
            if k.endswith("_port") or k.endswith("_seconds") or k.endswith("_workers"):
                cfg[k] = int(v)
            else:
                cfg[k] = v
    return cfg


def load_key_ref(keys_path: str, key_ref: str) -> bytes:
    if not os.path.exists(keys_path):
        raise FileNotFoundError("keys file missing")
    with open(keys_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    hexv = data.get(key_ref, "")
    if not hexv:
        raise KeyError(f"missing key ref {key_ref}")
    b = bytes.fromhex(hexv)
    if len(b) != 8:
        raise ValueError("key must be 8 bytes")
    return b


class AsyncLogger:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.q = queue.Queue()
        self.stop_evt = threading.Event()
        self.t = threading.Thread(target=self._worker, daemon=True)
        self.t.start()

    def _worker(self):
        while not self.stop_evt.is_set() or not self.q.empty():
            try:
                line = self.q.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line)
            except Exception:
                pass

    def log(self, level: str, module: str, text: str, msg_type: int = 0, error_code: str = ""):
        ts = utc_now_str()
        self.q.put(f"[{ts}] [{level}] [{module}] [0x{msg_type:02X}] [{error_code}] {text}\n")

    def close(self):
        self.stop_evt.set()
        self.t.join(timeout=1.5)
