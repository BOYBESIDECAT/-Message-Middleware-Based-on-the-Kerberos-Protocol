import socket
import json
from typing import Tuple

# 对齐3.3.2节msg_type编码表
MSG_TYPE = {
    "CERT_APPLY": 0x0C,
    "CERT_RESPONSE": 0x0D,
    "CERT_RENEW_REQUEST": 0x0E,
    "CERT_REVOKE_NOTICE": 0x0F,
    "ERROR_RESPONSE": 0x0B
}

MAX_PACKET_SIZE = 1024 * 1024  # 1MB最大报文长度

def BuildPacket(msg_type: int, payload: bytes) -> bytes:
    """封装报文(4字节长度 + 1字节msg_type + payload)"""
    if len(payload) > MAX_PACKET_SIZE - 1:
        raise ValueError("Payload too large")
    total_len = 1 + len(payload)
    return total_len.to_bytes(4, byteorder='big') + msg_type.to_bytes(1, byteorder='big') + payload

def ReadExact(conn: socket.socket, n: int) -> bytes:
    """循环读取n字节"""
    data = b''
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed prematurely")
        data += chunk
    return data

def ReadPacket(conn: socket.socket) -> Tuple[int, bytes]:
    """读取完整报文"""
    # 读取4字节长度
    len_bytes = ReadExact(conn, 4)
    total_len = int.from_bytes(len_bytes, byteorder='big')
    if total_len < 1 or total_len > MAX_PACKET_SIZE:
        raise ValueError(f"Invalid packet length: {total_len}")
    # 读取msg_type和payload
    msg_type_byte = ReadExact(conn, 1)
    msg_type = int.from_bytes(msg_type_byte, byteorder='big')
    payload = ReadExact(conn, total_len - 1)
    return msg_type, payload

def SendAll(conn: socket.socket, data: bytes) -> None:
    """循环发送完整数据"""
    sent = 0
    while sent < len(data):
        chunk = conn.send(data[sent:])
        if chunk == 0:
            raise ConnectionError("Connection closed during send")
        sent += chunk

def MapMsgType(msg_type: int) -> str:
    """映射msg_type到名称"""
    for name, code in MSG_TYPE.items():
        if code == msg_type:
            return name
    return f"UNKNOWN(0x{msg_type:02X})"