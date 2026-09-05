import struct
import socket
from typing import Optional, Tuple


class Packet:
    """报文封装与解析"""

    MAX_PACKET_SIZE = 1024 * 1024  # 1MB

    @staticmethod
    def build_packet(msg_type: int, payload: bytes) -> bytes:
        """构建报文: 4Bytes长度 + 1Byte msg_type + payload"""
        total_len = 1 + len(payload)
        packet = struct.pack('!I', total_len)
        packet += bytes([msg_type])
        packet += payload
        return packet

    @staticmethod
    def read_exact(conn: socket.socket, n: int) -> Optional[bytes]:
        """循环读取n字节"""
        data = b''
        while len(data) < n:
            try:
                chunk = conn.recv(n - len(data))
                if not chunk:
                    return None
                data += chunk
            except (socket.timeout, socket.error):
                return None
        return data

    @staticmethod
    def read_packet(conn: socket.socket) -> Optional[Tuple[int, bytes]]:
        """读取完整报文，返回(msg_type, payload)"""
        length_data = Packet.read_exact(conn, 4)
        if not length_data:
            return None

        total_len = struct.unpack('!I', length_data)[0]
        if total_len <= 0 or total_len > Packet.MAX_PACKET_SIZE:
            return None

        body = Packet.read_exact(conn, total_len)
        if not body:
            return None

        return body[0], body[1:]

    @staticmethod
    def send_all(conn: socket.socket, data: bytes) -> bool:
        """循环发送完整数据"""
        sent = 0
        while sent < len(data):
            try:
                result = conn.send(data[sent:])
                if result == 0:
                    return False
                sent += result
            except socket.error:
                return False
        return True

    @staticmethod
    def map_msg_type(msg_type: int) -> str:
        """映射msg_type到可读名称"""
        mapping = {
            0x01: "AS_REQUEST", 0x02: "AS_RESPONSE",
            0x03: "TGS_REQUEST", 0x04: "TGS_RESPONSE",
            0x05: "SERVICE_REQUEST", 0x06: "SERVICE_RESPONSE",
            0x07: "CHAT_HISTORY_REQUEST", 0x08: "CHAT_HISTORY_RESPONSE",
            0x09: "CHAT_SEND", 0x0A: "CHAT_BROADCAST",
            0x0B: "ERROR_RESPONSE",
            0x0C: "CERT_APPLY", 0x0D: "CERT_RESPONSE",
            0x0E: "CERT_RENEW_REQUEST", 0x0F: "CERT_REVOKE_NOTICE",
        }
        return mapping.get(msg_type, f"UNKNOWN(0x{msg_type:02X})")