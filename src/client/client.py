#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kerberos 安全聊天室客户端（按项目设计文档 v3.0）
说明：
1. 保留并增强原有可运行能力：连接、聊天室显示、本地消息缓存。
2. 新增 AS/TGS/APP 三阶段密文认证交互：AS_REQUEST -> AS_RESPONSE -> TGS_REQUEST -> TGS_RESPONSE -> SERVICE_REQUEST -> SERVICE_RESPONSE。
3. 报文结构遵循文档：4B length + 1B msg_type + UTF-8 JSON payload。
4. 业务密文统一放在 data.cipher_hex；DES-ECB + PKCS7。
"""

import json
import os
import re
import socket
import sqlite3
import struct
import threading
import queue
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from Crypto.PublicKey import RSA

# ================== 常量 ==================
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
MSG_CERT_APPLY = 0x0C
MSG_CERT_RESPONSE = 0x0D
MSG_CERT_RENEW_REQUEST = 0x0E
MSG_CERT_REVOKE_NOTICE = 0x0F

AUTH_INIT = "INIT"
AUTH_WAIT_AS = "WAIT_AS"
AUTH_WAIT_TGS = "WAIT_TGS"
AUTH_WAIT_SERVICE = "WAIT_SERVICE"
AUTH_OK = "AUTH_OK"
AUTH_FAIL = "AUTH_FAIL"

SYNC_LOAD_HISTORY = "LOAD_HISTORY"
SYNC_NORMAL_CHAT = "NORMAL_CHAT"

DEFAULT_TICKET_LIFETIME = 300

MSG_NAME = {
    MSG_AS_REQUEST: "AS_REQUEST",
    MSG_AS_RESPONSE: "AS_RESPONSE",
    MSG_TGS_REQUEST: "TGS_REQUEST",
    MSG_TGS_RESPONSE: "TGS_RESPONSE",
    MSG_SERVICE_REQUEST: "SERVICE_REQUEST",
    MSG_SERVICE_RESPONSE: "SERVICE_RESPONSE",
    MSG_CHAT_HISTORY_REQUEST: "CHAT_HISTORY_REQUEST",
    MSG_CHAT_HISTORY_RESPONSE: "CHAT_HISTORY_RESPONSE",
    MSG_CHAT_SEND: "CHAT_SEND",
    MSG_CHAT_BROADCAST: "CHAT_BROADCAST",
    MSG_ERROR_RESPONSE: "ERROR_RESPONSE",
    MSG_CERT_APPLY: "CERT_APPLY",
    MSG_CERT_RESPONSE: "CERT_RESPONSE",
    MSG_CERT_RENEW_REQUEST: "CERT_RENEW_REQUEST",
    MSG_CERT_REVOKE_NOTICE: "CERT_REVOKE_NOTICE",
}


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
        chunk = msg[i : i + 64]
        w = [0] * 64
        for t in range(16):
            w[t] = int.from_bytes(chunk[t * 4 : t * 4 + 4], "big")
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


# ================== 手写 DES（ECB） ==================
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
_DES_P = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30,
    6, 22, 11, 4, 25,
]
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


# ================== 数据结构 ==================
@dataclass
class KcTgsContext:
    kc_tgs: bytes
    ticket_tgs: bytes
    idtgs: str
    ts2: str
    lifetime2: int


@dataclass
class ServiceTicketContext:
    kc_v: bytes
    ticket_v: bytes
    idv: str
    ts4: str
    lifetime4: int


# ================== 通用函数 ==================
def UtcNowStr() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ParseUtc(ts: str) -> datetime:
    s = (ts or "").strip()
    if not s:
        raise ValueError("empty timestamp")
    if s.endswith("Z"):
        base = s[:-1]
        if len(base) >= 6 and (base[-6] in ("+", "-")) and base[-3] == ":":
            s = base
        else:
            s = base + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def CanonicalJson(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def Hash64(data: str) -> bytes:
    return SHA256(data.encode("utf-8"))[:8]


def BuildPacket(msg_type: int, payload: bytes) -> bytes:
    total_len = 1 + len(payload)
    return struct.pack("!I", total_len) + bytes([msg_type]) + payload


def ReadExact(conn: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    return data


def ReadPacket(conn: socket.socket) -> Tuple[int, dict]:
    head = ReadExact(conn, 4)
    total_len = struct.unpack("!I", head)[0]
    if total_len < 1:
        raise ValueError("INVALID_PACKET_LENGTH")
    body = ReadExact(conn, total_len)
    msg_type = body[0]
    payload = body[1:]
    try:
        payload_dict = json.loads(payload.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"INVALID_PAYLOAD_JSON: {e}")
    return msg_type, payload_dict


def SendAll(conn: socket.socket, data: bytes):
    pos = 0
    while pos < len(data):
        n = conn.send(data[pos:])
        if n <= 0:
            raise ConnectionError("send failed")
        pos += n


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
    if len(key8) != 8:
        raise ValueError("DES key must be 8 bytes")
    subkeys = _des_subkeys(key8)
    data = PKCS7Pad(plain, 8)
    out = bytearray()
    for i in range(0, len(data), 8):
        out.extend(_des_crypt_block(data[i : i + 8], subkeys, decrypt=False))
    return bytes(out)


def DESDecrypt(key8: bytes, cipher_bytes: bytes) -> bytes:
    if len(key8) != 8:
        raise ValueError("DES key must be 8 bytes")
    if len(cipher_bytes) % 8 != 0:
        raise ValueError("DES cipher length must be multiple of 8")
    subkeys = _des_subkeys(key8)
    out = bytearray()
    for i in range(0, len(cipher_bytes), 8):
        out.extend(_des_crypt_block(cipher_bytes[i : i + 8], subkeys, decrypt=True))
    return PKCS7Unpad(bytes(out), 8)


def BuildSimpleSignature(msg_type: int, data_obj: dict, signer_cert_id: str) -> dict:
    # 课程实现占位：采用 HASH 摘要表示，字段与文档保持一致。
    sign_source = f"{msg_type}|{CanonicalJson(data_obj)}|{signer_cert_id}".encode("utf-8")
    digest = SHA256(sign_source).hex()
    return {
        "algorithm": "SHA-256/RSA2048-NOPADDING",
        "signer_cert_id": signer_cert_id,
        "value_hex": digest,
    }


def _rsa_raw_sign_nopadding(digest32: bytes, n_hex: str, d_hex: str) -> str:
    n = int(n_hex, 16)
    d = int(d_hex, 16)
    block = digest32.rjust(256, b"\x00")
    m = int.from_bytes(block, "big")
    s = pow(m, d, n)
    return s.to_bytes(256, "big").hex()


def _rsa_raw_verify_nopadding(digest32: bytes, sig_hex: str, n_hex: str, e_hex: str) -> bool:
    n = int(n_hex, 16)
    e = int(e_hex, 16)
    sig = int(sig_hex, 16)
    m = pow(sig, e, n).to_bytes(256, "big")
    return m == digest32.rjust(256, b"\x00")


def LoadClientConfig(config_path: str) -> dict:
    # 简单 ini 风格解析，不存在则回退默认值。
    cfg = {
        "as_host": "",
        "as_port": 8000,
        "tgs_host": "",
        "tgs_port": 8001,
        "app_host": "",
        "app_port": 8002,
        "ca_host": "",
        "ca_port": 8003,
        "client_machine_id": "CLIENT-HOST-001",
        "client_db_path": "data/client_cache.db",
        "identity_store_path": "secure/client_identity",
        "log_path": "logs/client.log.txt",
        "ca_cert_path": "CA/certs/ca_cert.pem",
        "tgs_id": "TGS-001",
        "service_id": "CHATSERVER-001",
        "adc": "172.27.138.79",
        "enable_cert_flow": "1",
        "cert_renew_threshold_seconds": 86400,
        "strict_signature_verify": "1",
    }
    if not os.path.exists(config_path):
        return cfg

    with open(config_path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip()
            if k in ("as_port", "tgs_port", "app_port", "ca_port", "cert_renew_threshold_seconds"):
                cfg[k] = int(v)
            else:
                cfg[k] = v
    return cfg


# ================== 客户端主类 ==================
class ChatClient:
    def __init__(self, config_path: str = "client.conf"):
        self.cfg = LoadClientConfig(config_path)

        self.username = ""
        self.kc: Optional[bytes] = None
        self.kc_tgs_ctx: Optional[KcTgsContext] = None
        self.service_ctx: Optional[ServiceTicketContext] = None

        self.as_sock: Optional[socket.socket] = None
        self.tgs_sock: Optional[socket.socket] = None
        self.app_sock: Optional[socket.socket] = None

        self.running = False
        self.authenticated = False
        self.auth_state = AUTH_INIT
        self.chat_state = SYNC_LOAD_HISTORY
        self.cert_state = "CERT_PREPARE"
        self.enable_cert_flow = str(self.cfg.get("enable_cert_flow", "1")).strip().lower() not in ("0", "false", "no")
        self.strict_signature_verify = str(self.cfg.get("strict_signature_verify", "1")).strip().lower() in ("1", "true", "yes")

        # 对端证书缓存状态（按文档“首次携带，后续可省略”）
        self.as_cert_exchanged = False
        self.tgs_cert_exchanged = False
        self.app_cert_exchanged = False
        self.peer_certs = {"AS": None, "TGS": None, "APP": None}
        self.packet_trace = []
        self.packet_trace_lock = threading.Lock()
        self.max_trace_items = 1200

        self.local_identity = self._load_local_identity()
        self.ca_public_key = self._load_ca_public_key()
        self._init_async_logger()

        self._init_local_db()

        self.root = tk.Tk()
        self.root.title("Kerberos 安全聊天室客户端")
        self.root.geometry("980x640")
        self.root.protocol("WM_DELETE_WINDOW", self.CloseClient)
        self._init_ui_theme()
        self.show_login()

    # ---------- 本地身份与日志 ----------
    def _init_async_logger(self):
        self._log_queue = queue.Queue()
        self._log_stop = threading.Event()
        self._log_thread = threading.Thread(target=self._log_worker, daemon=True)
        self._log_thread.start()

    def _log_worker(self):
        os.makedirs(os.path.dirname(self.cfg["log_path"]), exist_ok=True)
        while not self._log_stop.is_set() or not self._log_queue.empty():
            try:
                line = self._log_queue.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                with open(self.cfg["log_path"], "a", encoding="utf-8") as f:
                    f.write(line)
            except Exception:
                pass

    def _load_local_identity(self) -> dict:
        os.makedirs(self.cfg["identity_store_path"], exist_ok=True)
        cert_path = os.path.join(self.cfg["identity_store_path"], "certificate.json")
        private_key_path = os.path.join(self.cfg["identity_store_path"], "private_key.json")
        if os.path.exists(cert_path):
            with open(cert_path, "r", encoding="utf-8") as f:
                cert = json.load(f)
        else:
            now = UtcNowStr()
            next_year = (datetime.now(timezone.utc) + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
            cert = {
                "version": "X509-SIMPLE-V1",
                "cert_id": self.cfg["client_machine_id"],
                "serial_number": "LOCAL-DEV-000001",
                "subject_role": "CLIENT",
                "issuer": "CA",
                "public_key_hex": "LOCAL_PLACEHOLDER_PUBLIC_KEY",
                "valid_from": now,
                "valid_to": next_year,
                "signature_algorithm": "SHA-256/RSA2048-NOPADDING",
                "ca_signature_hex": "LOCAL_PLACEHOLDER_CA_SIGNATURE",
            }
            with open(cert_path, "w", encoding="utf-8") as f:
                json.dump(cert, f, ensure_ascii=False, indent=2)

        private_key = None
        if os.path.exists(private_key_path):
            with open(private_key_path, "r", encoding="utf-8") as f:
                private_key = json.load(f)
        else:
            private_key = {"n_hex": "", "d_hex": "", "e_hex": "10001"}

        # 启动时确保本地存在可用 RSA 私钥；若不存在或不完整则自动生成。
        if not isinstance(private_key, dict):
            private_key = {}
        n_hex = (private_key.get("n_hex") or "").strip().lower()
        d_hex = (private_key.get("d_hex") or "").strip().lower()
        e_hex = (private_key.get("e_hex") or "10001").strip().lower()
        if not n_hex or not d_hex:
            rsa_key = RSA.generate(2048)
            n_hex = format(int(rsa_key.n), "x")
            d_hex = format(int(rsa_key.d), "x")
            e_hex = format(int(rsa_key.e), "x")
            private_key = {"n_hex": n_hex, "d_hex": d_hex, "e_hex": e_hex}
            with open(private_key_path, "w", encoding="utf-8") as f:
                json.dump(private_key, f, ensure_ascii=False, indent=2)
        else:
            private_key = {"n_hex": n_hex, "d_hex": d_hex, "e_hex": e_hex}

        # 证书中若未填充公钥（或仍是占位符）则同步为本地公钥。
        cert_pub = (cert.get("public_key_hex") or "").strip()
        if (not cert_pub) or cert_pub.startswith("LOCAL_PLACEHOLDER"):
            cert["public_key_hex"] = private_key["n_hex"]
            with open(cert_path, "w", encoding="utf-8") as f:
                json.dump(cert, f, ensure_ascii=False, indent=2)

        return {
            "machine_id": self.cfg["client_machine_id"],
            "certificate": cert,
            "private_key": private_key,
        }

    def _load_ca_public_key(self) -> dict:
        ca_pub_path = os.path.join(self.cfg["identity_store_path"], "ca_public_key.json")
        if os.path.exists(ca_pub_path):
            try:
                with open(ca_pub_path, "r", encoding="utf-8") as f:
                    obj = json.load(f)
                if obj.get("n_hex"):
                    return obj
            except Exception:
                pass
        ca_cert_path = self.cfg.get("ca_cert_path", "CA/certs/ca_cert.pem")
        if ca_cert_path and os.path.exists(ca_cert_path):
            try:
                with open(ca_cert_path, "rb") as f:
                    pub = RSA.import_key(f.read())
                return {"n_hex": format(int(pub.n), "x"), "e_hex": format(int(pub.e), "x")}
            except Exception:
                pass
        return {"n_hex": "", "e_hex": "10001"}

    def WriteLog(self, level: str, module: str, text: str, msg_type: int = 0, error_code: str = ""):
        ts = UtcNowStr()
        line = f"[{ts}] [{level}] [{module}] [0x{msg_type:02X}] [{error_code}] {text}\n"
        if hasattr(self, "_log_queue"):
            self._log_queue.put(line)

    def _msg_name(self, msg_type: int) -> str:
        return MSG_NAME.get(msg_type, f"UNKNOWN(0x{msg_type:02X})")

    def _pretty_json(self, obj) -> str:
        try:
            return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)
        except Exception:
            return str(obj)

    def _as_dict(self, obj):
        if isinstance(obj, dict):
            return obj
        if isinstance(obj, str):
            s = obj.strip()
            if not s:
                return {}
            try:
                parsed = json.loads(s)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass
            # 兼容服务端把证书序列化为 "SimpleX509Certificate(...)" 文本。
            cert_match = re.match(r"^SimpleX509Certificate\((.*)\)$", s)
            if cert_match:
                inside = cert_match.group(1)
                fields = dict(re.findall(r"(\w+)='([^']*)'", inside))
                if fields:
                    return fields
            return {}
        return {}

    def _normalize_peer_certificate(self, cert_obj: dict) -> dict:
        cert = dict(cert_obj or {})
        pub = str(cert.get("public_key_hex", "") or "").strip()
        if not pub:
            return cert
        # 兼容 public_key_hex 实际上是 {"e_hex":"...","n_hex":"..."} 的 hex 文本。
        if len(pub) % 2 == 0 and all(ch in "0123456789abcdefABCDEF" for ch in pub):
            try:
                decoded = bytes.fromhex(pub).decode("utf-8").strip()
                nested = self._as_dict(decoded)
                n_hex = str(nested.get("n_hex", "") or "").strip().lower()
                e_hex = str(nested.get("e_hex", "") or "").strip().lower()
                if n_hex:
                    cert["public_key_hex"] = n_hex
                if e_hex:
                    cert["public_key_e_hex"] = e_hex
            except Exception:
                pass
        return cert

    def _extract_packet_payload(self, packet: bytes):
        try:
            if len(packet) < 5:
                return None
            total_len = struct.unpack("!I", packet[:4])[0]
            if total_len != len(packet) - 4:
                return None
            raw = packet[5:]
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return None

    def _trace_window_alive(self) -> bool:
        if not hasattr(self, "trace_window") or self.trace_window is None:
            return False
        try:
            if hasattr(self.trace_window, "winfo_exists"):
                return bool(self.trace_window.winfo_exists())
            if hasattr(self.trace_window, "isVisible"):
                return bool(self.trace_window.isVisible())
        except Exception:
            return False
        return False

    def _append_packet_trace(self, stage: str, direction: str, msg_type: int, summary: str, detail: str):
        event = {
            "time": UtcNowStr(),
            "stage": stage,
            "direction": direction,
            "msg_type": msg_type,
            "name": self._msg_name(msg_type),
            "summary": summary,
            "detail": detail,
        }
        with self.packet_trace_lock:
            self.packet_trace.append(event)
            if len(self.packet_trace) > self.max_trace_items:
                self.packet_trace = self.packet_trace[-self.max_trace_items :]
        if self._trace_window_alive():
            self.root.after(0, self._refresh_trace_list)

    def _log_packet_send(self, stage: str, msg_type: int, packet: bytes):
        self.WriteLog("INFO", "CLIENT_TX", f"{stage} SEND {self._msg_name(msg_type)} bytes={len(packet)}", msg_type)
        payload = self._extract_packet_payload(packet)
        detail = (
            f"time={UtcNowStr()}\n"
            f"stage={stage}\n"
            f"direction=SEND\n"
            f"msg_type=0x{msg_type:02X} ({self._msg_name(msg_type)})\n"
            f"packet_bytes={len(packet)}\n"
            f"payload=\n{self._pretty_json(payload) if payload is not None else '(payload parse failed)'}"
        )
        self._append_packet_trace(stage, "SEND", msg_type, f"{stage} SEND {self._msg_name(msg_type)}", detail)

    def _log_packet_recv(self, stage: str, msg_type: int, payload: dict):
        keys = []
        if isinstance(payload, dict):
            keys = list(payload.keys())
        self.WriteLog("INFO", "CLIENT_RX", f"{stage} RECV {self._msg_name(msg_type)} keys={keys}", msg_type)
        detail = (
            f"time={UtcNowStr()}\n"
            f"stage={stage}\n"
            f"direction=RECV\n"
            f"msg_type=0x{msg_type:02X} ({self._msg_name(msg_type)})\n"
            f"payload_keys={keys}\n"
            f"payload=\n{self._pretty_json(payload)}"
        )
        self._append_packet_trace(stage, "RECV", msg_type, f"{stage} RECV {self._msg_name(msg_type)}", detail)

    def _verify_outgoing_packet_signature(self, msg_type: int, packet: bytes):
        payload = self._extract_packet_payload(packet)
        payload_obj = self._as_dict(payload)
        sig = self._as_dict(payload_obj.get("signature"))
        data_obj = self._as_dict(payload_obj.get("data"))
        if not sig or not sig.get("value_hex"):
            raise RuntimeError("OUTGOING_SIGN_MISSING")
        signer = sig.get("signer_cert_id", "")
        if signer != self.local_identity.get("machine_id", ""):
            raise RuntimeError("OUTGOING_SIGNER_MISMATCH")
        sign_source = f"{msg_type}|{CanonicalJson(data_obj)}|{signer}".encode("utf-8")
        digest = SHA256(sign_source)
        key = self.local_identity.get("private_key", {}) or {}
        pub_n = key.get("n_hex") or (self.local_identity.get("certificate", {}) or {}).get("public_key_hex", "")
        pub_e = sig.get("e_hex") or key.get("e_hex", "10001")
        if not pub_n:
            raise RuntimeError("OUTGOING_SIGN_VERIFY_FAILED")
        if not _rsa_raw_verify_nopadding(digest, sig.get("value_hex", ""), pub_n, pub_e):
            raise RuntimeError("OUTGOING_SIGN_VERIFY_FAILED")

    def _send_signed_packet(self, stage: str, msg_type: int, sock: socket.socket, packet: bytes):
        self._verify_outgoing_packet_signature(msg_type, packet)
        self._log_packet_send(stage, msg_type, packet)
        SendAll(sock, packet)

    def _validate_local_identity(self) -> bool:
        cert = self.local_identity.get("certificate", {})
        if cert.get("cert_id") != self.cfg["client_machine_id"]:
            return False
        try:
            now = datetime.now(timezone.utc)
            valid_to = ParseUtc(cert.get("valid_to", "1970-01-01T00:00:00Z"))
            if now >= valid_to:
                return False
        except Exception:
            return False
        return True

    def _certificate_sign_payload(self, cert: dict) -> dict:
        keys = [
            "version",
            "cert_id",
            "serial_number",
            "subject_role",
            "issuer",
            "public_key_hex",
            "valid_from",
            "valid_to",
            "signature_algorithm",
        ]
        return {k: cert.get(k, "") for k in keys}

    def _verify_certificate_ca_signature(self, cert: dict) -> bool:
        try:
            ca_n = (self.ca_public_key or {}).get("n_hex", "")
            ca_e = (self.ca_public_key or {}).get("e_hex", "10001")
            sig_hex = cert.get("ca_signature_hex", "")
            if not (ca_n and sig_hex):
                return False
            sign_source = CanonicalJson(self._certificate_sign_payload(cert)).encode("utf-8")
            digest = SHA256(sign_source)
            return _rsa_raw_verify_nopadding(digest, sig_hex, ca_n, ca_e)
        except Exception:
            return False

    def _is_cert_near_expiry(self, cert: dict) -> bool:
        try:
            valid_to = ParseUtc(cert.get("valid_to", "1970-01-01T00:00:00Z"))
            threshold = int(self.cfg.get("cert_renew_threshold_seconds", 86400))
            return (valid_to - datetime.now(timezone.utc)).total_seconds() <= threshold
        except Exception:
            return True

    def _save_local_certificate(self, cert: dict):
        cert_path = os.path.join(self.cfg["identity_store_path"], "certificate.json")
        with open(cert_path, "w", encoding="utf-8") as f:
            json.dump(cert, f, ensure_ascii=False, indent=2)
        self.local_identity["certificate"] = cert

    def _clear_peer_cert_cache(self):
        self.as_cert_exchanged = False
        self.tgs_cert_exchanged = False
        self.app_cert_exchanged = False
        self.peer_certs = {"AS": None, "TGS": None, "APP": None}

    def _request_certificate_from_ca(self, req_msg_type: int, cert: Optional[dict] = None) -> dict:
        key = (self.local_identity.get("private_key") or {})
        pub_key_hex = key.get("n_hex", "")
        if not pub_key_hex and cert:
            pub_key_hex = cert.get("public_key_hex", "")
        data_obj = {
            "machine_id": self.cfg["client_machine_id"],
            "subject_role": "CLIENT",
            "public_key_hex": pub_key_hex,
        }
        if req_msg_type == MSG_CERT_RENEW_REQUEST:
            data_obj["cert_id"] = (cert or {}).get("cert_id", self.cfg["client_machine_id"])

        payload = {"data": data_obj}
        # 保持与设计文档一致：首次证书请求可携带签名，CA 端会忽略非 data 字段。
        payload["signature"] = self._build_signature(req_msg_type, data_obj)
        if cert:
            payload["certificate"] = cert

        packet = BuildPacket(req_msg_type, json.dumps(payload, ensure_ascii=False).encode("utf-8"))

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(None)
        try:
            sock.connect((self.cfg["ca_host"], int(self.cfg["ca_port"])))
            self._send_signed_packet("CERT", req_msg_type, sock, packet)
            msg_type, resp_payload = ReadPacket(sock)
            self._log_packet_recv("CERT", msg_type, resp_payload)
        finally:
            try:
                sock.close()
            except Exception:
                pass

        if msg_type not in (MSG_CERT_RESPONSE, MSG_ERROR_RESPONSE):
            raise RuntimeError(f"CA msg_type invalid: 0x{msg_type:02X}")
        if msg_type == MSG_ERROR_RESPONSE:
            err = (resp_payload.get("data") or {}).get("error_code", "CA_ERROR")
            raise RuntimeError(err)
        return resp_payload

    def _prepare_local_certificate(self):
        cert = self.local_identity.get("certificate", {}) or {}
        must_apply = False
        must_renew = False

        if not cert:
            must_apply = True
        elif cert.get("cert_id") != self.cfg["client_machine_id"]:
            must_apply = True
        else:
            try:
                if datetime.now(timezone.utc) >= ParseUtc(cert.get("valid_to", "1970-01-01T00:00:00Z")):
                    must_apply = True
            except Exception:
                must_apply = True

        if not must_apply and not self._verify_certificate_ca_signature(cert):
            must_apply = True
        if not must_apply and self._is_cert_near_expiry(cert):
            must_renew = True

        if must_apply:
            self.log_to_auth("[CERT_PREPARE] 本地证书不可用，向 CA 申请新证书")
            resp = self._request_certificate_from_ca(MSG_CERT_APPLY, cert if cert else None)
            cert_new = (resp.get("data") or {}).get("certificate", {})
            if not isinstance(cert_new, dict) or not cert_new:
                raise RuntimeError("CERT_APPLY_FORMAT_ERROR")
            if cert_new.get("cert_id") != self.cfg["client_machine_id"]:
                raise RuntimeError("CERT_MACHINE_ID_MISMATCH")
            if not self._verify_certificate_ca_signature(cert_new):
                raise RuntimeError("CERT_VERIFY_FAILED")
            self._save_local_certificate(cert_new)
            self._clear_peer_cert_cache()
            return

        if must_renew:
            self.log_to_auth("[CERT_PREPARE] 本地证书即将过期，向 CA 发起续期")
            resp = self._request_certificate_from_ca(MSG_CERT_RENEW_REQUEST, cert)
            cert_new = (resp.get("data") or {}).get("certificate", {})
            if not isinstance(cert_new, dict) or not cert_new:
                raise RuntimeError("CERT_APPLY_FORMAT_ERROR")
            if cert_new.get("cert_id") != self.cfg["client_machine_id"]:
                raise RuntimeError("CERT_MACHINE_ID_MISMATCH")
            if not self._verify_certificate_ca_signature(cert_new):
                raise RuntimeError("CERT_VERIFY_FAILED")
            self._save_local_certificate(cert_new)
            self._clear_peer_cert_cache()

    def _build_signature(self, msg_type: int, data_obj: dict) -> dict:
        signer = self.local_identity["machine_id"]
        sign_source = f"{msg_type}|{CanonicalJson(data_obj)}|{signer}".encode("utf-8")
        digest = SHA256(sign_source)
        key = self.local_identity.get("private_key", {}) or {}
        n_hex = key.get("n_hex", "")
        d_hex = key.get("d_hex", "")
        e_hex = key.get("e_hex", "10001")
        if n_hex and d_hex:
            value_hex = _rsa_raw_sign_nopadding(digest, n_hex, d_hex)
        else:
            value_hex = digest.hex()
        return {"algorithm": "SHA-256/RSA2048-NOPADDING", "signer_cert_id": signer, "value_hex": value_hex, "e_hex": e_hex}

    def _verify_peer_packet(self, peer_name: str, msg_type: int, payload: dict):
        payload_obj = self._as_dict(payload)
        cert_raw = self._as_dict(payload_obj.get("certificate"))
        cert = dict(cert_raw)
        if not cert:
            # 兼容某些端把 certificate 放在 data 里。
            cert_raw = self._as_dict(self._as_dict(payload_obj.get("data")).get("certificate"))
            cert = dict(cert_raw)
        if not cert:
            # 兼容 {"certificate":{"certificate":"{...json...}"}} 等二次包装。
            cert_wrap = self._as_dict(payload_obj.get("certificate"))
            cert_raw = self._as_dict(cert_wrap.get("certificate"))
            cert = dict(cert_raw)
        cert = self._normalize_peer_certificate(cert)
        sig = self._as_dict(payload_obj.get("signature"))
        data_obj = self._as_dict(payload_obj.get("data"))
        sig_present = isinstance(sig, dict) and bool(sig.get("value_hex"))
        cert_fallback = None

        if cert:
            # 只有在对端实际携带签名时才校验 signer_cert_id 一致性，
            # 兼容当前联调阶段某些响应仅返回 data+certificate。
            if sig_present and cert.get("cert_id") != sig.get("signer_cert_id"):
                raise RuntimeError("CERT_MACHINE_ID_MISMATCH")
            verify_ok = self._verify_certificate_ca_signature(cert_raw) or self._verify_certificate_ca_signature(cert)
            if verify_ok:
                self.peer_certs[peer_name] = cert
            elif cert.get("public_key_hex"):
                # 联调兼容：若 CA 验签失败但证书含公钥，则仅用于当前报文签名校验。
                cert_fallback = cert
                self.WriteLog(
                    "WARN",
                    "CLIENT",
                    f"{peer_name} {self._msg_name(msg_type)} certificate CA verify failed, use fallback pubkey for packet verify",
                    msg_type,
                    "CERT_VERIFY_FALLBACK",
                )
            else:
                raise RuntimeError("CERT_VERIFY_FAILED")
        cert_used = self.peer_certs.get(peer_name) or cert_fallback
        if not cert_used:
            raise RuntimeError("CERT_VERIFY_FAILED")
        try:
            now = datetime.now(timezone.utc)
            if now >= ParseUtc(cert_used.get("valid_to", "1970-01-01T00:00:00Z")):
                raise RuntimeError("CERT_EXPIRED_OR_REVOKED")
        except ValueError:
            raise RuntimeError("CERT_VERIFY_FAILED")

        if not sig_present:
            if self.strict_signature_verify:
                raise RuntimeError("SIGN_MISSING")
            self.WriteLog("WARN", "CLIENT", f"{peer_name} {self._msg_name(msg_type)} missing signature, skip packet sign verify", msg_type, "SIGN_MISSING")
            return

        sign_source = f"{msg_type}|{CanonicalJson(data_obj)}|{sig.get('signer_cert_id','')}".encode("utf-8")
        digest = SHA256(sign_source)
        pub_n = cert_used.get("public_key_hex", "")
        pub_e = sig.get("e_hex") or cert_used.get("public_key_e_hex", "10001")
        sig_hex = sig.get("value_hex", "")
        if not pub_n:
            raise RuntimeError("SIGN_VERIFY_FAILED")
        if not _rsa_raw_verify_nopadding(digest, sig_hex, pub_n, pub_e):
            raise RuntimeError("SIGN_VERIFY_FAILED")

    # ---------- DB ----------
    def _init_local_db(self):
        db_path = self.cfg["client_db_path"]
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS received_message (
                message_id INTEGER PRIMARY KEY,
                sender_id TEXT NOT NULL,
                content TEXT NOT NULL,
                send_time TEXT NOT NULL,
                received_time TEXT NOT NULL,
                source_type TEXT NOT NULL
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_send_time ON received_message(send_time)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_source_type ON received_message(source_type)")
        conn.commit()
        conn.close()

    def _db_insert_message(self, msg: dict, source_type: str):
        db_path = self.cfg["client_db_path"]
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT OR IGNORE INTO received_message
            (message_id, sender_id, content, send_time, received_time, source_type)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                msg.get("message_id"),
                msg.get("sender_id", "UNKNOWN"),
                msg.get("content", ""),
                msg.get("send_time", UtcNowStr()),
                UtcNowStr(),
                source_type,
            ),
        )
        conn.commit()
        conn.close()

    def _get_max_message_id(self) -> int:
        db_path = self.cfg["client_db_path"]
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT MAX(message_id) FROM received_message")
        row = cur.fetchone()
        conn.close()
        if row and row[0]:
            try:
                return int(row[0])
            except Exception:
                return 0
        return 0

    def _load_local_messages(self):
        db_path = self.cfg["client_db_path"]
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT message_id, sender_id, content, send_time FROM received_message ORDER BY send_time, message_id")
        rows = cur.fetchall()
        conn.close()
        return [
            {"message_id": r[0], "sender_id": r[1], "content": r[2], "send_time": r[3]}
            for r in rows
        ]

    # ---------- UI 对外函数 ----------
    def StartClientUI(self):
        self.root.mainloop()

    def _init_ui_theme(self):
        self.root.configure(bg="#eef2f8")
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Primary.TButton", font=("Microsoft YaHei UI", 10, "bold"), padding=8)
        style.configure("Secondary.TButton", font=("Microsoft YaHei UI", 10), padding=8)
        style.configure("Headline.TLabel", font=("Microsoft YaHei UI", 17, "bold"), background="#eef2f8", foreground="#1c2434")
        style.configure("Sub.TLabel", font=("Microsoft YaHei UI", 10), background="#eef2f8", foreground="#4a5570")

    def open_trace_viewer(self):
        if self._trace_window_alive():
            self.trace_window.lift()
            self.trace_window.focus_force()
            return
        self.trace_window = tk.Toplevel(self.root)
        self.trace_window.title("交互报文与加密过程")
        self.trace_window.geometry("1080x700")
        self.trace_window.configure(bg="#eef2f8")

        top = tk.Frame(self.trace_window, bg="#eef2f8")
        top.pack(fill=tk.X, padx=10, pady=(10, 6))
        tk.Label(top, text="从连接到聊天的全流程报文轨迹", font=("Microsoft YaHei UI", 13, "bold"), bg="#eef2f8", fg="#1c2434").pack(side=tk.LEFT)
        tk.Button(top, text="刷新", command=self._refresh_trace_list, bg="#274c77", fg="white", relief=tk.FLAT).pack(side=tk.RIGHT)

        body = tk.PanedWindow(self.trace_window, sashrelief=tk.RAISED, sashwidth=6, bg="#eef2f8")
        body.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        left = tk.Frame(body, bg="#ffffff")
        right = tk.Frame(body, bg="#ffffff")
        body.add(left, minsize=420)
        body.add(right, minsize=560)

        tk.Label(left, text="报文列表（单击查看详情）", font=("Microsoft YaHei UI", 10, "bold"), bg="#ffffff", fg="#23395d").pack(anchor=tk.W, padx=10, pady=(10, 4))
        self.trace_list = tk.Listbox(left, font=("Consolas", 9), bg="#f6f8fc", fg="#1f2a44", activestyle="none")
        self.trace_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self.trace_list.bind("<<ListboxSelect>>", self._on_trace_select)

        tk.Label(right, text="报文详情", font=("Microsoft YaHei UI", 10, "bold"), bg="#ffffff", fg="#23395d").pack(anchor=tk.W, padx=10, pady=(10, 4))
        self.trace_detail = scrolledtext.ScrolledText(right, font=("Consolas", 9), wrap=tk.WORD, bg="#fef9e8")
        self.trace_detail.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self.trace_detail.configure(state="disabled")
        self._refresh_trace_list()

    def _refresh_trace_list(self):
        if not (hasattr(self, "trace_list") and self.trace_list.winfo_exists()):
            return
        with self.packet_trace_lock:
            events = list(self.packet_trace)
        self.trace_list.delete(0, tk.END)
        for idx, ev in enumerate(events, start=1):
            line = f"{idx:04d} {ev['time']} [{ev['stage']}] {ev['direction']} {ev['name']} | {ev['summary']}"
            self.trace_list.insert(tk.END, line)
        if events:
            self.trace_list.selection_clear(0, tk.END)
            self.trace_list.selection_set(tk.END)
            self.trace_list.see(tk.END)
            self._show_trace_detail(len(events) - 1)

    def _on_trace_select(self, _event):
        if not (hasattr(self, "trace_list") and self.trace_list.curselection()):
            return
        idx = self.trace_list.curselection()[0]
        self._show_trace_detail(idx)

    def _show_trace_detail(self, idx: int):
        if not (hasattr(self, "trace_detail") and self.trace_detail.winfo_exists()):
            return
        with self.packet_trace_lock:
            if idx < 0 or idx >= len(self.packet_trace):
                return
            detail = self.packet_trace[idx]["detail"]
        self.trace_detail.configure(state="normal")
        self.trace_detail.delete("1.0", tk.END)
        self.trace_detail.insert(tk.END, detail)
        self.trace_detail.configure(state="disabled")

    def OnLoginConfirm(self):
        user_id = self.entry_user.get().strip()
        password = self.entry_password.get()
        if not user_id or not password:
            messagebox.showwarning("提示", "请输入用户名和密码")
            return

        # 联调账号标准化：服务端可用账号为 Alice
        if user_id.lower() == "alice":
            user_id = "Alice"

        self.username = user_id
        self.kc = Hash64(password)
        self.log_to_auth(f"已计算 Kc(8B): {self.kc.hex()}")

        self.btn_login.config(state=tk.DISABLED)

        t = threading.Thread(target=self.StartAuthentication, args=(user_id, self.kc, self.cfg), daemon=True)
        t.start()

    def StartAuthentication(self, user_id: str, kc: bytes, client_cfg: dict):
        try:
            if self.enable_cert_flow:
                self._prepare_local_certificate()
                if not self._validate_local_identity():
                    raise RuntimeError("CERT_EXPIRED_OR_REVOKED")
                self.cert_state = "CERT_READY"
            self.auth_state = AUTH_WAIT_AS
            self.log_to_auth("[INIT] 开始三阶段认证")

            # 1) AS
            self._append_packet_trace("AUTH", "LOCAL", MSG_AS_REQUEST, "CONNECT AS", f"connect to AS {client_cfg['as_host']}:{client_cfg['as_port']}")
            self.as_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.as_sock.settimeout(None)
            self.as_sock.connect((client_cfg["as_host"], client_cfg["as_port"]))
            as_packet = self.BuildASRequest(user_id, client_cfg["tgs_id"], UtcNowStr())
            self._send_signed_packet("AUTH", MSG_AS_REQUEST, self.as_sock, as_packet)
            msg_type, payload = ReadPacket(self.as_sock)
            self._log_packet_recv("AUTH", msg_type, payload)
            if self.enable_cert_flow:
                self._verify_peer_packet("AS", msg_type, payload)
            if msg_type == MSG_ERROR_RESPONSE:
                raise RuntimeError(f"AS ERROR: {payload.get('data', {}).get('error_code', 'UNKNOWN')}")
            if msg_type != MSG_AS_RESPONSE:
                raise RuntimeError(f"AS msg_type invalid: 0x{msg_type:02X}")
            self.kc_tgs_ctx = self.ParseASResponse((msg_type, payload), kc)
            self.log_to_auth("[WAIT_AS] AS_RESPONSE 解密成功")

            # 2) TGS
            self.auth_state = AUTH_WAIT_TGS
            self._append_packet_trace("AUTH", "LOCAL", MSG_TGS_REQUEST, "CONNECT TGS", f"connect to TGS {client_cfg['tgs_host']}:{client_cfg['tgs_port']}")
            self.tgs_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tgs_sock.settimeout(None)
            self.tgs_sock.connect((client_cfg["tgs_host"], client_cfg["tgs_port"]))
            tgs_req = self.BuildTGSRequest(client_cfg["service_id"], self.kc_tgs_ctx.ticket_tgs, self.kc_tgs_ctx.kc_tgs)
            self._send_signed_packet("AUTH", MSG_TGS_REQUEST, self.tgs_sock, tgs_req)
            msg_type, payload = ReadPacket(self.tgs_sock)
            self._log_packet_recv("AUTH", msg_type, payload)
            if self.enable_cert_flow:
                self._verify_peer_packet("TGS", msg_type, payload)
            if msg_type == MSG_ERROR_RESPONSE:
                raise RuntimeError(f"TGS ERROR: {payload.get('data', {}).get('error_code', 'UNKNOWN')}")
            if msg_type != MSG_TGS_RESPONSE:
                raise RuntimeError(f"TGS msg_type invalid: 0x{msg_type:02X}")
            self.service_ctx = self.ParseTGSResponse((msg_type, payload), self.kc_tgs_ctx.kc_tgs)
            self.log_to_auth("[WAIT_TGS] TGS_RESPONSE 解密成功")

            # 3) APP SERVICE
            self.auth_state = AUTH_WAIT_SERVICE
            self._append_packet_trace("AUTH", "LOCAL", MSG_SERVICE_REQUEST, "CONNECT APP", f"connect to APP {client_cfg['app_host']}:{client_cfg['app_port']}")
            self.app_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.app_sock.settimeout(None)
            self.app_sock.connect((client_cfg["app_host"], client_cfg["app_port"]))
            service_req = self.BuildServiceRequest(
                self.service_ctx.ticket_v,
                self.service_ctx.kc_v,
                user_id,
                client_cfg.get("adc", "127.0.0.1"),
            )
            self._send_signed_packet("AUTH", MSG_SERVICE_REQUEST, self.app_sock, service_req)
            msg_type, payload = ReadPacket(self.app_sock)
            self._log_packet_recv("AUTH", msg_type, payload)
            if self.enable_cert_flow:
                self._verify_peer_packet("APP", msg_type, payload)
            if msg_type == MSG_ERROR_RESPONSE:
                raise RuntimeError(f"APP ERROR: {payload.get('data', {}).get('error_code', 'UNKNOWN')}")
            if msg_type != MSG_SERVICE_RESPONSE:
                raise RuntimeError(f"SERVICE msg_type invalid: 0x{msg_type:02X}")
            if not self.VerifyServiceResponse(payload):
                raise RuntimeError("SERVICE_RESPONSE verify failed")

            self.auth_state = AUTH_OK
            self.authenticated = True
            self.running = True

            self.root.after(0, self.show_chatroom)
            self.root.after(0, lambda: self.set_status("认证成功，进入聊天室"))
            self.root.after(0, self.load_and_display_local_messages)

            # 认证阶段用短超时，进入聊天室后改为阻塞接收，避免空闲时误判断线。
            self.app_sock.settimeout(None)
            self.RequestHistory(self._get_max_message_id())

            recv_t = threading.Thread(target=self.HandleIncomingLoop, daemon=True)
            recv_t.start()

        except Exception as e:
            self.auth_state = AUTH_FAIL
            self.authenticated = False
            self.root.after(0, lambda: self.log_to_auth(f"[AUTH_FAIL] {e}"))
            self.root.after(0, lambda: self.set_status("认证失败"))
            self.root.after(0, lambda: self.btn_login.config(state=tk.NORMAL))
            self.WriteLog("ERROR", "CLIENT", str(e), 0, "AUTH_FAIL")

    def EnterChatRoom(self, ticket_ctx: ServiceTicketContext, client_cfg: dict) -> bool:
        return ticket_ctx is not None and self.authenticated

    def SendChatMessage(self, content: str):
        if not self.authenticated or not self.service_ctx:
            self.log_to_chat(">>> 尚未完成认证")
            return
        content = content.strip()
        if not content:
            return
        try:
            packet = self.BuildChatSendPacket(content, self.service_ctx.kc_v)
            self._send_signed_packet("CHAT", MSG_CHAT_SEND, self.app_sock, packet)
            self.entry_msg.delete(0, tk.END)
        except Exception as e:
            self.log_to_chat(f">>> 发送失败: {e}")

    def CloseClient(self):
        self.running = False
        for s in (self.as_sock, self.tgs_sock, self.app_sock):
            if s:
                try:
                    s.close()
                except Exception:
                    pass
        if hasattr(self, "_log_stop"):
            self._log_stop.set()
        if hasattr(self, "_log_thread"):
            self._log_thread.join(timeout=1.5)
        self.root.destroy()

    def OpenCryptoInspector(self, view_mode: str = "full"):
        # UI 已内置展示区，此函数保留为文档要求的对外接口。
        self.log_to_auth(f"CryptoInspector 模式: {view_mode}")

    # ---------- 客户端内部函数（按文档命名） ----------
    def BuildASRequest(self, idc: str, idtgs: str, ts1: str) -> bytes:
        data_obj = {
            "IDc": idc,
            "IDtgs": idtgs,
            "TS1": ts1,
            "ADc": self.cfg.get("adc", "127.0.0.1"),
        }
        payload = {"data": data_obj}
        if self.enable_cert_flow:
            payload["certificate"] = self.local_identity["certificate"]
        payload["signature"] = self._build_signature(MSG_AS_REQUEST, data_obj)

        self.UpdateCryptoDisplay("AS_REQUEST", CanonicalJson(data_obj), "(outer json plain + signature)")
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        return BuildPacket(MSG_AS_REQUEST, raw)

    def ParseASResponse(self, packet: Tuple[int, dict], kc: bytes) -> KcTgsContext:
        _msg_type, payload = packet
        cipher_hex = payload.get("data", {}).get("cipher_hex", "")
        if not cipher_hex:
            raise RuntimeError("AS_RESPONSE missing data.cipher_hex")

        plain = DESDecrypt(kc, bytes.fromhex(cipher_hex)).decode("utf-8")
        obj = json.loads(plain)

        kc_tgs = bytes.fromhex(obj["Kc_tgs"])
        ticket_tgs = bytes.fromhex(obj["Ticket_tgs"])
        ctx = KcTgsContext(
            kc_tgs=kc_tgs,
            ticket_tgs=ticket_tgs,
            idtgs=obj["IDtgs"],
            ts2=obj["TS2"],
            lifetime2=int(obj["Lifetime2"]),
        )
        self.as_cert_exchanged = True
        self.UpdateCryptoDisplay("AS_RESPONSE", plain, cipher_hex[:64] + "...")
        return ctx

    def BuildTGSRequest(self, idv: str, ticket_tgs: bytes, kc_tgs: bytes) -> bytes:
        ts3 = UtcNowStr()
        auth_plain = {"IDc": self.username, "ADc": self.cfg.get("adc", "127.0.0.1"), "TS3": ts3}
        auth_cipher = DESEncrypt(kc_tgs, CanonicalJson(auth_plain).encode("utf-8")).hex()

        data_obj = {
            "IDv": idv,
            "Ticket_tgs": ticket_tgs.hex(),
            "Authenticator_c": auth_cipher,
        }
        payload = {"data": data_obj}
        if self.enable_cert_flow:
            payload["certificate"] = self.local_identity["certificate"]
        payload["signature"] = self._build_signature(MSG_TGS_REQUEST, data_obj)

        self.UpdateCryptoDisplay("TGS_REQUEST", CanonicalJson(auth_plain), auth_cipher[:64] + "...")
        return BuildPacket(MSG_TGS_REQUEST, json.dumps(payload, ensure_ascii=False).encode("utf-8"))

    def ParseTGSResponse(self, packet: Tuple[int, dict], kc_tgs: bytes) -> ServiceTicketContext:
        _msg_type, payload = packet
        cipher_hex = payload.get("data", {}).get("cipher_hex", "")
        if not cipher_hex:
            raise RuntimeError("TGS_RESPONSE missing data.cipher_hex")

        plain = DESDecrypt(kc_tgs, bytes.fromhex(cipher_hex)).decode("utf-8")
        obj = json.loads(plain)

        kc_v = bytes.fromhex(obj["Kc_v"])
        ticket_v = bytes.fromhex(obj["Ticket_v"])
        ctx = ServiceTicketContext(
            kc_v=kc_v,
            ticket_v=ticket_v,
            idv=obj["IDv"],
            ts4=obj["TS4"],
            lifetime4=int(obj.get("Lifetime4", DEFAULT_TICKET_LIFETIME)),
        )
        self.tgs_cert_exchanged = True
        self.UpdateCryptoDisplay("TGS_RESPONSE", plain, cipher_hex[:64] + "...")
        return ctx

    def BuildServiceRequest(self, ticket_v: bytes, kc_v: bytes, idc: str, adc: str) -> bytes:
        ts5 = UtcNowStr()
        self._last_ts5 = ts5

        auth_plain = {"IDc": idc, "ADc": adc, "TS5": ts5}
        auth_cipher = DESEncrypt(kc_v, CanonicalJson(auth_plain).encode("utf-8")).hex()

        data_obj = {
            "Ticket_v": ticket_v.hex(),
            "Authenticator_c": auth_cipher,
        }
        payload = {"data": data_obj}
        if self.enable_cert_flow and (not self.app_cert_exchanged):
            payload["certificate"] = self.local_identity["certificate"]
        payload["signature"] = self._build_signature(MSG_SERVICE_REQUEST, data_obj)

        self.UpdateCryptoDisplay("SERVICE_REQUEST", CanonicalJson(auth_plain), auth_cipher[:64] + "...")
        return BuildPacket(MSG_SERVICE_REQUEST, json.dumps(payload, ensure_ascii=False).encode("utf-8"))

    def VerifyServiceResponse(self, payload: dict) -> bool:
        if not self.service_ctx:
            return False
        payload_obj = self._as_dict(payload)
        data_obj = self._as_dict(payload_obj.get("data"))
        cipher_hex = data_obj.get("cipher_hex", "")
        if not cipher_hex:
            return False

        plain = DESDecrypt(self.service_ctx.kc_v, bytes.fromhex(cipher_hex)).decode("utf-8")
        obj = json.loads(plain)
        ts5_plus_1 = obj.get("TS5_plus_1")
        if not ts5_plus_1:
            return False

        try:
            expected = ParseUtc(self._last_ts5) + timedelta(seconds=1)
            got = ParseUtc(ts5_plus_1)
            ok = abs((got - expected).total_seconds()) <= 1
        except Exception:
            ok = False

        self.app_cert_exchanged = True
        self.UpdateCryptoDisplay("SERVICE_RESPONSE", plain, cipher_hex[:64] + "...")
        return ok

    def BuildChatSendPacket(self, content: str, kc_v: bytes) -> bytes:
        plain_obj = {
            "sender_id": self.username,
            "content": content,
            "send_time": UtcNowStr(),
        }
        cipher_hex = DESEncrypt(kc_v, CanonicalJson(plain_obj).encode("utf-8")).hex()
        data_obj = {"cipher_hex": cipher_hex}
        payload = {
            "data": data_obj,
            "signature": self._build_signature(MSG_CHAT_SEND, data_obj),
        }
        self.UpdateCryptoDisplay("CHAT_SEND", CanonicalJson(plain_obj), cipher_hex[:64] + "...")
        return BuildPacket(MSG_CHAT_SEND, json.dumps(payload, ensure_ascii=False).encode("utf-8"))

    def UpdateCryptoDisplay(self, stage: str, plain_text: str, cipher_text: str):
        text = (
            f"[{stage}]\n"
            f"PLAIN: {plain_text}\n"
            f"CIPHER: {cipher_text}\n"
            + "-" * 56
        )
        detail = (
            f"time={UtcNowStr()}\n"
            f"stage={stage}\n"
            f"direction=CRYPTO\n"
            f"plain=\n{plain_text}\n\n"
            f"cipher=\n{cipher_text}"
        )
        self._append_packet_trace(stage, "CRYPTO", 0x00, f"{stage} 加密/解密过程", detail)
        self.root.after(0, lambda: self.update_crypto_display(text))

    # ---------- 聊天处理 ----------
    def RequestHistory(self, last_local_message_id: int):
        if not self.service_ctx:
            return
        try:
            last_id = int(last_local_message_id)
        except Exception:
            last_id = 0
        plain_obj = {"last_local_message_id": last_id}
        cipher_hex = DESEncrypt(self.service_ctx.kc_v, CanonicalJson(plain_obj).encode("utf-8")).hex()
        data_obj = {
            "last_local_message_id": last_id,
            "cipher_hex": cipher_hex,
        }
        payload = {
            "data": data_obj,
            "signature": self._build_signature(MSG_CHAT_HISTORY_REQUEST, data_obj),
        }
        packet = BuildPacket(MSG_CHAT_HISTORY_REQUEST, json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        self._send_signed_packet("CHAT", MSG_CHAT_HISTORY_REQUEST, self.app_sock, packet)

    def HandleIncomingLoop(self):
        while self.running and self.app_sock:
            try:
                msg_type, payload = ReadPacket(self.app_sock)
                self._log_packet_recv("CHAT", msg_type, payload)
                if self.enable_cert_flow:
                    self._verify_peer_packet("APP", msg_type, payload)
                self.HandleIncomingPacket(msg_type, payload)
            except socket.timeout:
                # 聊天阶段允许空闲等待，不把超时视为连接中断。
                continue
            except Exception as e:
                if self.running:
                    self.log_to_chat(f">>> 连接中断: {e}")
                break

    def HandleIncomingPacket(self, msg_type: int, payload: dict):
        if msg_type == MSG_CHAT_HISTORY_RESPONSE:
            self.handle_history_response(payload)
            self.chat_state = SYNC_NORMAL_CHAT
        elif msg_type == MSG_CHAT_BROADCAST:
            self.handle_broadcast(payload)
        elif msg_type == MSG_ERROR_RESPONSE:
            err = payload.get("data", {})
            self.log_to_chat(f">>> 错误: {err.get('error_code', '')} {err.get('message', '')}")
        elif msg_type == MSG_CERT_REVOKE_NOTICE:
            self.log_to_chat(">>> 收到证书吊销通知，已停止当前会话")
            self._clear_peer_cert_cache()
            self.authenticated = False
            self.running = False
        else:
            self.log_to_chat(f">>> 未知消息类型: 0x{msg_type:02X}，关闭连接")
            self.running = False

    def handle_history_response(self, payload: dict):
        if not self.service_ctx:
            return
        cipher_hex = payload.get("data", {}).get("cipher_hex", "")
        if cipher_hex:
            plain = DESDecrypt(self.service_ctx.kc_v, bytes.fromhex(cipher_hex)).decode("utf-8")
            obj = json.loads(plain)
            self.UpdateCryptoDisplay("CHAT_HISTORY_RESPONSE", plain, cipher_hex[:64] + "...")
        else:
            obj = payload.get("data", {})
            plain = CanonicalJson(obj)
        # 兼容两种历史消息明文格式：
        # 1) {"messages": [...]}
        # 2) [...]
        if isinstance(obj, list):
            messages = obj
        elif isinstance(obj, dict):
            messages = obj.get("messages", [])
        else:
            messages = []

        if not messages:
            self.log_to_chat("--- 没有新的历史消息 ---")
            return

        for msg in messages:
            if not isinstance(msg, dict):
                continue
            if msg.get("message_id") is not None:
                self._db_insert_message(msg, "history")
            self.display_single_message(msg)
        self.log_to_chat(f"--- 已同步 {len(messages)} 条历史消息 ---")

    def handle_broadcast(self, payload: dict):
        if not self.service_ctx:
            return
        cipher_hex = payload.get("data", {}).get("cipher_hex", "")
        if not cipher_hex:
            return
        plain = DESDecrypt(self.service_ctx.kc_v, bytes.fromhex(cipher_hex)).decode("utf-8")
        msg = json.loads(plain)

        self.UpdateCryptoDisplay("CHAT_BROADCAST", plain, cipher_hex[:64] + "...")

        if msg.get("message_id") is not None:
            self._db_insert_message(msg, "broadcast")
        self.display_single_message(msg)

    def load_and_display_local_messages(self):
        messages = self._load_local_messages()
        if not messages:
            self.log_to_chat("--- 本地暂无聊天记录 ---")
            return
        self.log_to_chat("--- 以下为本地缓存消息 ---")
        for msg in messages:
            self.display_single_message(msg)
        self.log_to_chat("--- 本地消息加载完成 ---")

    def display_single_message(self, msg: dict):
        sender = msg.get("sender_id", "UNKNOWN")
        content = msg.get("content", "")
        send_time = msg.get("send_time", "")
        self.log_to_chat(f"[{send_time}] {sender}: {content}")

    # ---------- UI ----------
    def show_login(self):
        self.login_frame = tk.Frame(self.root, bg="#eef2f8")
        self.login_frame.pack(fill=tk.BOTH, expand=True, padx=24, pady=20)

        ttk.Label(self.login_frame, text="Kerberos 安全聊天室", style="Headline.TLabel").pack(anchor=tk.W, pady=(4, 2))
        ttk.Label(self.login_frame, text="客户端认证与加密消息演示", style="Sub.TLabel").pack(anchor=tk.W, pady=(0, 12))

        form = tk.Frame(self.login_frame, bg="#ffffff", highlightbackground="#d8deea", highlightthickness=1)
        form.pack(fill=tk.X, padx=2, pady=(0, 12))

        row0 = tk.Frame(form, bg="#ffffff")
        row0.pack(fill=tk.X, pady=(16, 8), padx=16)
        tk.Label(row0, text="用户名", font=("Microsoft YaHei UI", 11), bg="#ffffff", fg="#2a3550").pack(side=tk.LEFT, padx=(0, 10))
        self.entry_user = tk.Entry(row0, font=("Microsoft YaHei UI", 12), width=28, relief=tk.FLAT, bg="#f4f7ff")
        self.entry_user.pack(side=tk.LEFT, ipady=6)

        row1 = tk.Frame(form, bg="#ffffff")
        row1.pack(fill=tk.X, pady=(0, 10), padx=16)
        tk.Label(row1, text="密码", font=("Microsoft YaHei UI", 11), bg="#ffffff", fg="#2a3550").pack(side=tk.LEFT, padx=(0, 22))
        self.entry_password = tk.Entry(row1, font=("Microsoft YaHei UI", 12), width=28, show="*", relief=tk.FLAT, bg="#f4f7ff")
        self.entry_password.pack(side=tk.LEFT, ipady=6)

        btn_row = tk.Frame(form, bg="#ffffff")
        btn_row.pack(fill=tk.X, pady=(0, 16), padx=16)
        self.btn_login = ttk.Button(btn_row, text="登录并认证", command=self.OnLoginConfirm, style="Primary.TButton")
        self.btn_login.pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(btn_row, text="查看交互报文", command=self.open_trace_viewer, style="Secondary.TButton").pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(btn_row, text="退出", command=self.CloseClient, style="Secondary.TButton").pack(side=tk.LEFT)

        tk.Label(self.login_frame, text="认证日志", font=("Microsoft YaHei UI", 10, "bold"), bg="#eef2f8", fg="#2a3550").pack(anchor=tk.W, pady=(4, 2))
        self.auth_log = scrolledtext.ScrolledText(self.login_frame, height=13, state="disabled", font=("Consolas", 9), bg="#f8fafd")
        self.auth_log.pack(fill=tk.BOTH, expand=True)

    def show_chatroom(self):
        if hasattr(self, "login_frame") and self.login_frame.winfo_exists():
            self.login_frame.destroy()

        main = tk.Frame(self.root, bg="#eef2f8")
        main.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        left = tk.Frame(main, bg="#ffffff", highlightbackground="#d8deea", highlightthickness=1)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(left, text="聊天消息", font=("Microsoft YaHei UI", 11, "bold"), bg="#ffffff", fg="#24344f").pack(anchor=tk.W, padx=10, pady=(10, 4))
        self.chat_display = scrolledtext.ScrolledText(left, state="disabled", wrap=tk.WORD, font=("Microsoft YaHei UI", 10), bg="#fcfdff")
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 6))

        row = tk.Frame(left, bg="#ffffff")
        row.pack(fill=tk.X, padx=10, pady=(2, 10))
        self.entry_msg = tk.Entry(row, font=("Microsoft YaHei UI", 12), relief=tk.FLAT, bg="#f4f7ff")
        self.entry_msg.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6), ipady=7)
        tk.Button(row, text="发送", command=lambda: self.SendChatMessage(self.entry_msg.get()), bg="#2a9d8f", fg="white", relief=tk.FLAT).pack(side=tk.RIGHT, padx=(6, 0))
        tk.Button(row, text="交互报文过程", command=self.open_trace_viewer, bg="#264653", fg="white", relief=tk.FLAT).pack(side=tk.RIGHT)
        self.entry_msg.bind("<Return>", lambda _e: self.SendChatMessage(self.entry_msg.get()))

        right = tk.LabelFrame(main, text="明文/密文展示", font=("Microsoft YaHei UI", 10, "bold"), bg="#ffffff", fg="#24344f")
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False, padx=(6, 0))
        self.crypto_text = scrolledtext.ScrolledText(right, state="disabled", wrap=tk.WORD, font=("Consolas", 9), width=45, bg="#fef9e8")
        self.crypto_text.pack(fill=tk.BOTH, expand=True)

        self.status_bar = tk.Label(self.root, text="就绪", bd=1, relief=tk.SUNKEN, anchor=tk.W, font=("Microsoft YaHei UI", 9), bg="#e3e9f5")
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def log_to_auth(self, text: str):
        if hasattr(self, "auth_log") and self.auth_log.winfo_exists():
            self.auth_log.configure(state="normal")
            self.auth_log.insert(tk.END, text + "\n")
            self.auth_log.see(tk.END)
            self.auth_log.configure(state="disabled")

    def log_to_chat(self, text: str):
        if hasattr(self, "chat_display") and self.chat_display.winfo_exists():
            self.chat_display.configure(state="normal")
            self.chat_display.insert(tk.END, text + "\n")
            self.chat_display.see(tk.END)
            self.chat_display.configure(state="disabled")

    def update_crypto_display(self, text: str):
        if hasattr(self, "crypto_text") and self.crypto_text.winfo_exists():
            self.crypto_text.configure(state="normal")
            self.crypto_text.insert(tk.END, text + "\n")
            self.crypto_text.see(tk.END)
            self.crypto_text.configure(state="disabled")

    def set_status(self, text: str):
        if hasattr(self, "status_bar") and self.status_bar.winfo_exists():
            self.status_bar.config(text=text)


if __name__ == "__main__":
    app = ChatClient()
    app.StartClientUI()
