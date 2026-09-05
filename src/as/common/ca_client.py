#!/usr/bin/env python3
"""
CA客户端模块 - 通过网络向CA服务器申请证书
"""

import socket
import json
from datetime import datetime
from typing import Optional, Tuple
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.packet import Packet
from common.certificate import SimpleX509Certificate


# msg_type 常量
MSG_CERT_APPLY = 0x0C
MSG_CERT_RESPONSE = 0x0D
MSG_CERT_RENEW_REQUEST = 0x0E


class CAClient:
    """CA客户端 - CA地址由构造函数传入"""

    def __init__(self, ca_host: str, ca_port: int):
        self.ca_host = ca_host
        self.ca_port = ca_port
        self.socket_timeout = 10

    def _connect(self) -> Optional[socket.socket]:
        """连接到CA服务器"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.socket_timeout)
            sock.connect((self.ca_host, self.ca_port))
            print(f"[CAClient] 已连接到CA服务器 {self.ca_host}:{self.ca_port}")
            return sock
        except ConnectionRefusedError:
            print(f"[CAClient] CA服务器未启动: {self.ca_host}:{self.ca_port}")
            return None
        except Exception as e:
            print(f"[CAClient] 连接CA失败: {e}")
            return None

    def apply_certificate(self, machine_id: str, subject_role: str,
                          public_key_hex: str) -> Tuple[bool, Optional[SimpleX509Certificate], Optional[str]]:
        """向CA申请证书"""
        print(f"\n[CAClient] 申请证书 -> {self.ca_host}:{self.ca_port}")
        print(f"   machine_id: {machine_id}")
        print(f"   subject_role: {subject_role}")

        sock = self._connect()
        if not sock:
            return False, None, "CA_CONNECTION_FAILED"

        try:
            request_data = {
                'machine_id': machine_id,
                'subject_role': subject_role,
                'public_key_hex': public_key_hex,
                'ts': datetime.now().isoformat()
            }

            request = {'data': request_data}
            request_json = json.dumps(request)
            packet = Packet.build_packet(MSG_CERT_APPLY, request_json.encode())
            Packet.send_all(sock, packet)
            print(f"[CAClient] 已发送 CERT_APPLY 请求")

            result = Packet.read_packet(sock)
            sock.close()

            if result is None:
                return False, None, "NO_RESPONSE"

            msg_type, payload = result
            print(f"[CAClient] 收到响应: {Packet.map_msg_type(msg_type)}")

            if msg_type == MSG_CERT_RESPONSE:
                response = json.loads(payload.decode())
                data = response.get('data', {})
                status = data.get('status')

                if status == 'issued':
                    cert_data = data.get('certificate')
                    if cert_data:
                        certificate = SimpleX509Certificate.from_dict(cert_data)
                        print(f"[CAClient] 证书申请成功!")
                        return True, certificate, None
                else:
                    error_code = data.get('error_code', 'UNKNOWN')
                    print(f"[CAClient] 证书申请失败: {error_code}")
                    return False, None, error_code

            return False, None, f"UNEXPECTED_MSG_TYPE_{msg_type}"

        except Exception as e:
            print(f"[CAClient] 申请证书异常: {e}")
            return False, None, str(e)

    def renew_certificate(self, cert_id: str, machine_id: str,
                          subject_role: str, public_key_hex: str) -> Tuple[
        bool, Optional[SimpleX509Certificate], Optional[str]]:
        """续期证书"""
        print(f"\n[CAClient] 续期证书: {cert_id}")

        sock = self._connect()
        if not sock:
            return False, None, "CA_CONNECTION_FAILED"

        try:
            request_data = {
                'cert_id': cert_id,
                'machine_id': machine_id,
                'subject_role': subject_role,
                'public_key_hex': public_key_hex,
                'ts': datetime.now().isoformat()
            }

            request = {'data': request_data}
            request_json = json.dumps(request)
            packet = Packet.build_packet(MSG_CERT_RENEW_REQUEST, request_json.encode())
            Packet.send_all(sock, packet)
            print(f"[CAClient] 已发送 CERT_RENEW_REQUEST")

            result = Packet.read_packet(sock)
            sock.close()

            if result is None:
                return False, None, "NO_RESPONSE"

            msg_type, payload = result
            if msg_type == MSG_CERT_RESPONSE:
                response = json.loads(payload.decode())
                data = response.get('data', {})
                status = data.get('status')

                if status == 'issued':
                    cert_data = data.get('certificate')
                    if cert_data:
                        certificate = SimpleX509Certificate.from_dict(cert_data)
                        print(f"[CAClient] 证书续期成功!")
                        return True, certificate, None
                else:
                    error_code = data.get('error_code', 'UNKNOWN')
                    print(f"[CAClient] 证书续期失败: {error_code}")
                    return False, None, error_code

            return False, None, f"UNEXPECTED_MSG_TYPE_{msg_type}"

        except Exception as e:
            print(f"[CAClient] 续期证书异常: {e}")
            return False, None, str(e)


class CertificateManager:
    """证书管理器 - 管理本端证书"""

    def __init__(self, machine_id: str, role: str, cert_storage_path: str,
                 ca_host: str = None, ca_port: int = None):
        self.machine_id = machine_id
        self.role = role
        self.cert_storage_path = cert_storage_path
        self.ca_host = ca_host
        self.ca_port = ca_port
        self.certificate: Optional[SimpleX509Certificate] = None
        self.private_key_hex: Optional[str] = None
        self.ca_client = CAClient(ca_host, ca_port) if ca_host and ca_port else None

        os.makedirs(cert_storage_path, exist_ok=True)

    def _generate_keypair(self) -> Tuple[str, str]:
        """生成RSA密钥对（模拟）"""
        import secrets
        mock_base = f"{self.machine_id}_{self.role}_"
        public_key = mock_base + secrets.token_hex(32)
        private_key = mock_base + secrets.token_hex(32)
        return public_key, private_key

    def _save_certificate(self):
        """保存证书到本地"""
        if not self.certificate:
            return
        cert_file = os.path.join(self.cert_storage_path, f"{self.role}_cert.json")
        key_file = os.path.join(self.cert_storage_path, f"{self.role}_private_key.hex")

        with open(cert_file, 'w') as f:
            json.dump(self.certificate.to_dict(), f, indent=2)
        with open(key_file, 'w') as f:
            f.write(self.private_key_hex)
        print(f"[CertManager] 证书已保存: {cert_file}")

    def _load_certificate(self) -> bool:
        """从本地加载证书"""
        cert_file = os.path.join(self.cert_storage_path, f"{self.role}_cert.json")
        key_file = os.path.join(self.cert_storage_path, f"{self.role}_private_key.hex")

        if not os.path.exists(cert_file) or not os.path.exists(key_file):
            return False

        try:
            with open(cert_file, 'r') as f:
                cert_dict = json.load(f)
            with open(key_file, 'r') as f:
                self.private_key_hex = f.read().strip()

            self.certificate = SimpleX509Certificate.from_dict(cert_dict)

            # 检查有效期
            now = datetime.now()
            if self.certificate.valid_from <= now <= self.certificate.valid_to:
                print(f"[CertManager] 加载本地证书成功，有效期至: {self.certificate.valid_to}")
                return True
            else:
                print(f"[CertManager] 本地证书已过期")
                return False
        except Exception as e:
            print(f"[CertManager] 加载本地证书失败: {e}")
            return False

    def ensure_certificate(self) -> bool:
        """确保证书可用"""
        print(f"\n[CertManager] 确保证书: role={self.role}, machine_id={self.machine_id}")

        # 尝试加载本地证书
        if self._load_certificate():
            return True

        # 向CA申请证书
        if not self.ca_client:
            print(f"[CertManager] 未配置CA地址，使用模拟证书")
            return self._create_mock_certificate()

        public_key_hex, private_key_hex = self._generate_keypair()
        success, certificate, error = self.ca_client.apply_certificate(
            machine_id=self.machine_id,
            subject_role=self.role,
            public_key_hex=public_key_hex
        )

        if success and certificate:
            self.certificate = certificate
            self.private_key_hex = private_key_hex
            self._save_certificate()
            return True
        else:
            print(f"[CertManager] 证书申请失败: {error}，使用模拟证书")
            return self._create_mock_certificate()

    def _create_mock_certificate(self) -> bool:
        """创建模拟证书"""
        print(f"[CertManager] 创建模拟证书: {self.role}")

        public_key, private_key = self._generate_keypair()

        self.certificate = SimpleX509Certificate(
            version="X509-SIMPLE-V1",
            cert_id=self.machine_id,
            serial_number=f"SERIAL-{self.role}-001",
            subject_role=self.role,
            issuer="CA-DEV",
            public_key_hex=public_key,
            valid_from=datetime.now(),
            valid_to=datetime.now().replace(year=datetime.now().year + 1),
            signature_algorithm="SHA-256/RSA2048-NOPADDING",
            ca_signature_hex="mock_signature_12345678"
        )
        self.private_key_hex = private_key
        self._save_certificate()
        return True

    def get_certificate(self) -> Optional[SimpleX509Certificate]:
        return self.certificate

    def get_private_key(self) -> Optional[str]:
        return self.private_key_hex

    def sign_data(self, data: str) -> str:
        """签名（模拟）"""
        import hashlib
        return hashlib.sha256(data.encode()).hexdigest()