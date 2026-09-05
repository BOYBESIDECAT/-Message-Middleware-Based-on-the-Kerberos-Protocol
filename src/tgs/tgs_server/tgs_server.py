#!/usr/bin/env python3
"""
TGS服务器 - 集成CA证书申请，支持完整签名验证机制
符合设计文档 3.7.2 要求
支持多线程并发处理
"""

import socket
import threading
import json
from datetime import datetime, timezone, timedelta
from typing import Optional
import sys
import os
from concurrent.futures import ThreadPoolExecutor, TimeoutError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.packet import Packet
from common.crypto import Crypto
from common.logger import AsyncLogger
from common.config import ConfigLoader
from common.ca_client import CertificateManager
from common.certificate import SimpleX509Certificate

# 线程池配置
MAX_WORKER_THREADS = 50
MAX_QUEUE_SIZE = 100
CONNECTION_TIMEOUT = 60

# 允许的服务列表（硬编码，可根据需要扩展）
ALLOWED_SERVICES = {
    "CHATSERVER-001": "ChatServer",
    "CHATSERVER-002": "ChatServer2",
    "FILESERVER-001": "FileServer",
}


class TGSServer:
    def __init__(self, config_path: str):
        self.config = ConfigLoader.load_tgs_config(config_path)
        if not self.config:
            raise Exception("Failed to load TGS config")

        self.logger = AsyncLogger(self.config.log_path, "TGS")
        self.server_socket = None
        self.running = False
        self.ktgs_key = ConfigLoader.load_shared_key(self.config.ktgs_ref)
        self.kv_key = ConfigLoader.load_shared_key(self.config.kv_ref)

        # 线程池
        self.executor = ThreadPoolExecutor(
            max_workers=MAX_WORKER_THREADS,
            thread_name_prefix="TGS-Worker"
        )
        self.active_connections = {}
        self.connections_lock = threading.Lock()

        # 加载 CA 根证书
        self.ca_public_key = self._load_ca_root_certificate()

        # 加载 TGS 自己的私钥和证书
        self.tgs_private_key = None
        self.tgs_certificate = None
        self._load_tgs_identity()

        # 证书管理器
        self.cert_manager = CertificateManager(
            machine_id=self.config.tgs_machine_id,
            role='TGS',
            cert_storage_path=self.config.identity_store_path,
            ca_host=self.config.ca_host,
            ca_port=self.config.ca_port
        )

    def _load_ca_root_certificate(self) -> Optional[dict]:
        """加载 CA 根证书"""
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        ca_cert_paths = [
            os.path.join(project_root, "certs", "ca_cert.pem"),
        ]

        print(f"[TGS] 项目根目录: {project_root}")
        print(f"[TGS] 当前工作目录: {os.getcwd()}")

        for ca_cert_path in ca_cert_paths:
            print(f"[TGS] 尝试加载 CA 根证书: {ca_cert_path}")
            if os.path.exists(ca_cert_path):
                print(f"[TGS] 文件存在: {ca_cert_path}")
                try:
                    with open(ca_cert_path, "r", encoding="utf-8") as f:
                        pem_cert = f.read()
                    print(f"[TGS] 文件内容长度: {len(pem_cert)} 字符")

                    from common.crypto import parse_pem_certificate
                    ca_key = parse_pem_certificate(pem_cert)

                    if ca_key and ca_key.get("n_hex"):
                        print(f"[TGS] ✅ 已加载 CA 根证书: {ca_cert_path}")
                        print(f"[TGS] CA公钥 n 前64位: {ca_key.get('n_hex', '')[:64]}")
                        return ca_key
                    else:
                        print(f"[TGS] ❌ 解析证书失败，返回空公钥")
                except Exception as e:
                    print(f"[TGS] 加载 CA 根证书失败 ({ca_cert_path}): {e}")
                    import traceback
                    traceback.print_exc()
            else:
                print(f"[TGS] 文件不存在: {ca_cert_path}")

        print("[TGS] 警告: 未找到 CA 根证书，将跳过证书验证")
        return None

    def _load_tgs_identity(self):
        """加载 TGS 的私钥和证书"""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        identity_path = os.path.join(base_dir, self.config.identity_store_path)

        # 确保目录存在
        os.makedirs(identity_path, exist_ok=True)

        self.logger.write_log("INFO", "TGS_IDENTITY", f"从 {identity_path} 加载身份材料")
        print(f"[TGS] 从 {identity_path} 加载身份材料")

        # 1. 加载私钥 - 使用 TGS_private_key.hex
        key_path = os.path.join(identity_path, "TGS_private_key.hex")
        if os.path.exists(key_path):
            try:
                with open(key_path, "r", encoding="utf-8") as f:
                    content = f.read().strip()

                if '|' in content:
                    parts = content.split('|')
                    if len(parts) >= 2:
                        self.tgs_private_key = {
                            "n_hex": parts[0].strip(),
                            "d_hex": parts[1].strip(),
                            "e_hex": "10001"
                        }
                        self.logger.write_log("INFO", "TGS_IDENTITY", f"✅ 已加载私钥: {key_path}")
                        print(f"[TGS] ✅ 已加载私钥: {key_path}")
                else:
                    self.logger.write_log("ERROR", "TGS_IDENTITY", f"私钥格式错误，应为 n|d 格式: {key_path}")
                    self.tgs_private_key = None
            except Exception as e:
                self.logger.write_log("ERROR", "TGS_IDENTITY", f"加载私钥失败 ({key_path}): {str(e)}")
                self.tgs_private_key = None
        else:
            self.logger.write_log("WARN", "TGS_IDENTITY", f"私钥文件不存在: {key_path}")
            self.tgs_private_key = None

        # 2. 加载证书 - 使用 TGS_cert.json
        cert_path = os.path.join(identity_path, "TGS_cert.json")
        if os.path.exists(cert_path):
            try:
                with open(cert_path, "r", encoding="utf-8") as f:
                    self.tgs_certificate = json.load(f)
                self.logger.write_log("INFO", "TGS_IDENTITY", f"✅ 已加载证书: {cert_path}")
                self.logger.write_log("INFO", "TGS_IDENTITY", f"证书 ID: {self.tgs_certificate.get('cert_id')}")
                self.logger.write_log("INFO", "TGS_IDENTITY",
                                      f"证书公钥长度: {len(self.tgs_certificate.get('public_key_hex', ''))}")
                print(f"[TGS] ✅ 已加载证书: {cert_path}")
            except Exception as e:
                self.logger.write_log("ERROR", "TGS_IDENTITY", f"加载证书失败 ({cert_path}): {str(e)}")
                self.tgs_certificate = None
        else:
            self.logger.write_log("WARN", "TGS_IDENTITY", f"证书文件不存在: {cert_path}")
            self.tgs_certificate = None

    def _get_identity_path(self) -> str:
        """获取证书存储路径"""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base_dir, self.config.identity_store_path)

    def _validate_local_identity(self) -> bool:
        """验证本地身份材料是否有效"""
        cert = self.tgs_certificate
        if not cert:
            return False

        # 检查 cert_id 是否匹配
        if cert.get('cert_id') != self.config.tgs_machine_id:
            self.logger.write_log("WARN", "TGS_IDENTITY",
                                  f"证书 ID 不匹配: {cert.get('cert_id')} vs {self.config.tgs_machine_id}")
            return False

        # 检查有效期
        try:
            valid_to = cert.get('valid_to', '')
            if valid_to:
                valid_to_clean = valid_to.replace('Z', '+00:00')
                if '+00:00+00:00' in valid_to_clean:
                    valid_to_clean = valid_to_clean.replace('+00:00+00:00', '+00:00')
                valid_to_date = datetime.fromisoformat(valid_to_clean)
                now = datetime.now(timezone.utc)
                if now > valid_to_date:
                    self.logger.write_log("WARN", "TGS_IDENTITY", f"证书已过期: {valid_to}")
                    return False
        except Exception as e:
            self.logger.write_log("WARN", "TGS_IDENTITY", f"证书有效期验证异常: {e}")
            return False

        # 验证 CA 签名（如果有 CA 公钥）
        if self.ca_public_key and self.ca_public_key.get('n_hex'):
            if not Crypto.verify_certificate_signature(
                    cert,
                    self.ca_public_key.get('n_hex', ''),
                    self.ca_public_key.get('e_hex', '10001')
            ):
                self.logger.write_log("WARN", "TGS_IDENTITY", "证书 CA 签名验证失败")
                return False

        return True

    def _is_cert_near_expiry(self, cert: dict, threshold_days: int = 7) -> bool:
        """检查证书是否即将过期"""
        try:
            valid_to = cert.get('valid_to', '')
            if valid_to:
                valid_to_clean = valid_to.replace('Z', '+00:00')
                if '+00:00+00:00' in valid_to_clean:
                    valid_to_clean = valid_to_clean.replace('+00:00+00:00', '+00:00')
                valid_to_date = datetime.fromisoformat(valid_to_clean)
                days_left = (valid_to_date - datetime.now(timezone.utc)).days
                return 0 < days_left <= threshold_days
        except Exception:
            pass
        return False
    def _request_new_certificate(self) -> bool:
        """向 CA 申请新证书"""
        print(f"[TGS] 正在生成 RSA 密钥对...")

        # 生成 RSA 密钥对
        n_hex, e_hex, d_hex, p_hex, q_hex = Crypto.generate_rsa_keypair(2048)

        print(f"[TGS] 公钥长度: {len(n_hex)} 字符")
        print(f"[TGS] 向 CA 申请证书...")

        # 使用证书管理器申请证书
        success, certificate, error = self.cert_manager.ca_client.apply_certificate(
            machine_id=self.config.tgs_machine_id,
            subject_role='TGS',
            public_key_hex=n_hex
        )

        if success and certificate:
            identity_path = self._get_identity_path()
            os.makedirs(identity_path, exist_ok=True)

            # 保存私钥 (HEX 格式)
            key_path = os.path.join(identity_path, "TGS_private_key.hex")
            with open(key_path, "w", encoding="utf-8") as f:
                f.write(f"{n_hex}|{d_hex}")
            print(f"[TGS] ✅ 私钥已保存: {key_path}")

            # 保存证书 (JSON 格式)
            cert_path = os.path.join(identity_path, "TGS_cert.json")
            cert_dict = certificate.to_dict()
            with open(cert_path, "w", encoding="utf-8") as f:
                json.dump(cert_dict, f, indent=2, ensure_ascii=False)
            print(f"[TGS] ✅ 证书已保存: {cert_path}")

            # 重新加载证书和私钥
            self.tgs_certificate = cert_dict
            self.tgs_private_key = {
                "n_hex": n_hex,
                "d_hex": d_hex,
                "e_hex": "10001"
            }

            self.logger.write_log("INFO", "TGS_IDENTITY", f"证书申请成功: {certificate.cert_id}")
            print(f"[TGS] ✅ 证书申请成功: {certificate.cert_id}")
            return True
        else:
            self.logger.write_log("ERROR", "TGS_IDENTITY", f"证书申请失败: {error}")
            print(f"[TGS] ❌ 证书申请失败: {error}")
            return False

    def _renew_certificate(self) -> bool:
        """续期证书"""
        old_cert = self.tgs_certificate
        if not old_cert:
            return self._request_new_certificate()

        print(f"[TGS] 正在续期证书: {old_cert.get('cert_id')}")

        # 获取当前私钥的公钥
        if not self.tgs_private_key:
            print(f"[TGS] ❌ 无法续期：私钥不存在")
            return self._request_new_certificate()

        public_key_hex = self.tgs_private_key.get('n_hex', '')

        # 使用证书管理器续期
        success, certificate, error = self.cert_manager.ca_client.renew_certificate(
            cert_id=old_cert.get('cert_id'),
            machine_id=self.config.tgs_machine_id,
            subject_role='TGS',
            public_key_hex=public_key_hex
        )

        if success and certificate:
            identity_path = self._get_identity_path()
            cert_path = os.path.join(identity_path, "TGS_cert.json")
            cert_dict = certificate.to_dict()
            with open(cert_path, "w", encoding="utf-8") as f:
                json.dump(cert_dict, f, indent=2, ensure_ascii=False)

            self.tgs_certificate = cert_dict
            self.logger.write_log("INFO", "TGS_IDENTITY", f"证书续期成功: {certificate.cert_id}")
            print(f"[TGS] ✅ 证书续期成功: {certificate.cert_id}")
            return True
        else:
            self.logger.write_log("ERROR", "TGS_IDENTITY", f"证书续期失败: {error}")
            print(f"[TGS] ❌ 证书续期失败: {error}")
            # 续期失败，尝试重新申请
            return self._request_new_certificate()


    def _ensure_certificate(self) -> bool:
        """确保证书可用，如果不可用则自动申请"""
        print(f"\n[TGS] 检查本地证书状态...")

        # 检查证书是否存在且有效
        if self.tgs_certificate and self._validate_local_identity():
            cert_id = self.tgs_certificate.get('cert_id')
            print(f"[TGS] ✅ 本地证书有效: {cert_id}")

            # 检查是否即将过期
            if self._is_cert_near_expiry(self.tgs_certificate):
                print(f"[TGS] ⚠️ 证书即将过期，尝试续期...")
                return self._renew_certificate()
            return True

        # 证书无效或不存在，申请新证书
        print(f"[TGS] 本地证书无效或不存在，向 CA 申请新证书...")
        return self._request_new_certificate()


    def _check_service_exists(self, service_id: str) -> bool:
        """检查服务是否存在"""
        return service_id in ALLOWED_SERVICES

    def _verify_client_certificate_and_signature(self, msg_type: int, payload: dict) -> bool:
        """验证客户端请求的证书和签名"""
        certificate = payload.get("certificate")
        signature = payload.get("signature", {})
        data_obj = payload.get("data", {})

        thread_name = threading.current_thread().name
        self.logger.write_log("INFO", "TGS_AUTH", f"[{thread_name}] ========== 开始验证客户端请求 ==========")
        self.logger.write_log("INFO", "TGS_AUTH", f"[{thread_name}] msg_type: 0x{msg_type:02X}")

        # 1. 验证是否携带证书
        if not certificate:
            self.logger.write_log("ERROR", "TGS_AUTH", f"[{thread_name}] ❌ 客户端请求缺少证书")
            print(f"[TGS] [{thread_name}] ❌ 客户端请求缺少证书")
            return False

        self.logger.write_log("INFO", "TGS_AUTH", f"[{thread_name}] 客户端证书 ID: {certificate.get('cert_id')}")
        self.logger.write_log("INFO", "TGS_AUTH",
                              f"[{thread_name}] 客户端证书公钥长度: {len(certificate.get('public_key_hex', ''))} 字符")
        self.logger.write_log("INFO", "TGS_AUTH",
                              f"[{thread_name}] 客户端证书公钥前64位: {certificate.get('public_key_hex', '')[:64] if certificate.get('public_key_hex') else 'None'}")
        self.logger.write_log("INFO", "TGS_AUTH",
                              f"[{thread_name}] 客户端证书 CA 签名前64位: {certificate.get('ca_signature_hex', '')[:64] if certificate.get('ca_signature_hex') else 'None'}")
        self.logger.write_log("INFO", "TGS_AUTH", f"[{thread_name}] 客户端证书签发者: {certificate.get('issuer', 'Unknown')}")

        # 验证证书签名（使用 CA 根证书公钥）
        if self.ca_public_key and self.ca_public_key.get("n_hex"):
            if not Crypto.verify_certificate_signature(
                    certificate,
                    self.ca_public_key.get("n_hex", ""),
                    self.ca_public_key.get("e_hex", "10001")
            ):
                self.logger.write_log("ERROR", "TGS_AUTH", f"[{thread_name}] ❌ 客户端证书 CA 签名验证失败")
                print(f"[TGS] [{thread_name}] ❌ 客户端证书 CA 签名验证失败")
                return False
            self.logger.write_log("INFO", "TGS_AUTH", f"[{thread_name}] ✅ 客户端证书 CA 签名验证通过")
        else:
            self.logger.write_log("WARN", "TGS_AUTH", f"[{thread_name}] ⚠️ 无 CA 公钥，跳过证书签名验证")
            print(f"[TGS] [{thread_name}] ⚠️ 无 CA 公钥，跳过证书签名验证")

        # 验证证书有效期
        try:
            valid_to = certificate.get("valid_to", "")
            if valid_to:
                valid_to_clean = valid_to.replace('Z', '+00:00')
                if '+00:00+00:00' in valid_to_clean:
                    valid_to_clean = valid_to_clean.replace('+00:00+00:00', '+00:00')
                valid_to_date = datetime.fromisoformat(valid_to_clean)
                now = datetime.now(timezone.utc)
                if now > valid_to_date:
                    self.logger.write_log("ERROR", "TGS_AUTH", f"[{thread_name}] ❌ 客户端证书已过期: {valid_to}")
                    print(f"[TGS] [{thread_name}] ❌ 客户端证书已过期: {valid_to}")
                    return False
                self.logger.write_log("INFO", "TGS_AUTH", f"[{thread_name}] ✅ 客户端证书有效期验证通过，有效期至: {valid_to}")
        except Exception as e:
            self.logger.write_log("WARN", "TGS_AUTH", f"[{thread_name}] ⚠️ 证书有效期验证异常: {str(e)}")

        # 2. 验证签名
        if not signature:
            self.logger.write_log("ERROR", "TGS_AUTH", f"[{thread_name}] ❌ 客户端请求缺少签名")
            print(f"[TGS] [{thread_name}] ❌ 客户端请求缺少签名")
            return False

        public_key_n = certificate.get("public_key_hex", "")
        public_key_e = signature.get("e_hex", "10001")

        self.logger.write_log("INFO", "TGS_AUTH", f"[{thread_name}] 签名者: {signature.get('signer_cert_id')}")
        self.logger.write_log("INFO", "TGS_AUTH",
                              f"[{thread_name}] 签名值前64位: {signature.get('value_hex', '')[:64] if signature.get('value_hex') else 'None'}")

        # 构建签名输入
        sign_input = Crypto.build_signature_input(msg_type, data_obj, signature.get("signer_cert_id", ""))
        self.logger.write_log("DEBUG", "TGS_AUTH",
                              f"[{thread_name}] 签名输入前100字符: {sign_input[:100] if len(sign_input) > 100 else sign_input}")

        if not Crypto.verify_signature(msg_type, data_obj, signature, public_key_n, public_key_e):
            self.logger.write_log("ERROR", "TGS_AUTH", f"[{thread_name}] ❌ 客户端签名验证失败")
            print(f"[TGS] [{thread_name}] ❌ 客户端签名验证失败")
            return False

        self.logger.write_log("INFO", "TGS_AUTH", f"[{thread_name}] ✅ 客户端证书和签名验证全部通过")
        self.logger.write_log("INFO", "TGS_AUTH", f"[{thread_name}] ========== 验证完成 ==========\n")
        return True

    def start(self) -> bool:
        print(f"\n{'=' * 60}")
        print(f"[TGS] 启动票据服务器 (多线程模式)")
        print(f"[TGS] 监听地址: {self.config.listen_host}:{self.config.listen_port}")
        print(f"[TGS] Machine ID: {self.config.tgs_machine_id}")
        print(f"[TGS] 证书存储: {self.config.identity_store_path}")
        print(f"[TGS] CA地址: {self.config.ca_host}:{self.config.ca_port}")
        print(f"[TGS] 日志路径: {self.config.log_path}")
        print(f"[TGS] 最大工作线程: {MAX_WORKER_THREADS}")
        print(f"{'=' * 60}\n")

        self.logger.start()
        self.logger.write_log("INFO", "TGS_SERVER", "TGS server starting (multi-threaded)...")

        # 确保证书可用（自动检测并申请）
        print(f"\n[TGS] 检查证书状态...")
        if not self._ensure_certificate():
            self.logger.write_log("ERROR", "TGS_SERVER", "无法获取有效证书，服务器启动失败")
            print(f"[TGS] ❌ 无法获取有效证书，服务器启动失败")
            return False

        print(f"[TGS] ✅ 证书已就绪: {self.tgs_certificate.get('cert_id') if self.tgs_certificate else 'Unknown'}")

        if not self.tgs_private_key:
            self.logger.write_log("ERROR", "TGS_SERVER", "无法加载私钥，服务器无法启动")
            print(f"[TGS] ❌ 无法加载私钥，服务器无法启动")
            return False

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.config.listen_host, self.config.listen_port))
            self.server_socket.listen(MAX_QUEUE_SIZE)
            self.server_socket.settimeout(1.0)
            self.running = True

            self.logger.write_log("INFO", "TGS_SERVER",
                                  f"Server started on {self.config.listen_host}:{self.config.listen_port}")
            print(f"\n[TGS] 服务器启动成功，等待连接...\n")

            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    client_socket.settimeout(CONNECTION_TIMEOUT)

                    self.logger.write_log("INFO", "TGS_SERVER", f"新连接: {addr}")
                    print(f"[TGS] 新连接: {addr}")

                    future = self.executor.submit(self._handle_connection, client_socket, addr)

                    with self.connections_lock:
                        self.active_connections[addr] = future

                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.write_log("ERROR", "TGS_SERVER", f"Accept error: {str(e)}")
                        print(f"[TGS] Accept error: {e}")
        except Exception as e:
            self.logger.write_log("ERROR", "TGS_SERVER", f"启动失败: {str(e)}")
            print(f"[TGS] 启动失败: {e}")
            return False
        return True

    def _handle_tgs_request(self, payload: bytes, addr: tuple) -> Optional[bytes]:
        """处理 TGS_REQUEST,返回TGS_RESPONSE，但不发包 - 在工作线程中执行"""
        thread_name = threading.current_thread().name

        try:
            request = json.loads(payload.decode())

            if not self._verify_client_certificate_and_signature(0x03, request):
                return self._build_error_response("CERT_VERIFY_FAILED")

            data = request.get('data', {})
            idv = data.get('IDv')
            ticket_tgs_hex = data.get('Ticket_tgs', '')
            auth_hex = data.get('Authenticator_c', '')

            self.logger.write_log("INFO", "TGS_REQ", f"[{thread_name}] 处理目标服务: {idv}")
            print(f"[TGS] [{thread_name}] 处理目标服务: {idv}")

            if not idv:
                return self._build_error_response("INVALID_REQUEST")

            # 检查服务是否存在
            if not self._check_service_exists(idv):
                self.logger.write_log("ERROR", "TGS_REQ", f"[{thread_name}] 服务不存在: {idv}")
                print(f"[TGS] [{thread_name}] 服务不存在: {idv}")
                return self._build_error_response("SERVICE_NOT_FOUND")

            # 解密 Ticket_tgs
            kc_tgs = None
            user_id = None
            client_addr = None
            try:
                ticket_tgs_bytes = bytes.fromhex(ticket_tgs_hex)
                decrypted = Crypto.des_decrypt(self.ktgs_key, ticket_tgs_bytes)
                if decrypted is None:
                    self.logger.write_log("ERROR", "TGS_REQ", f"[{thread_name}] Ticket_tgs 解密失败")
                    return self._build_error_response("TGT_DECRYPT_ERROR")

                ticket_data = json.loads(decrypted.decode())
                kc_tgs_hex = ticket_data.get('Kc_tgs', '')
                user_id = ticket_data.get('IDc', 'unknown')
                client_addr = ticket_data.get('ADc', 'unknown')
                if kc_tgs_hex:
                    kc_tgs = bytes.fromhex(kc_tgs_hex)
                    self.logger.write_log("INFO", "TGS_REQ", f"[{thread_name}] Kc_tgs: {kc_tgs.hex()}, 用户: {user_id}")
                    print(f"[TGS] [{thread_name}] Kc_tgs: {kc_tgs.hex()}, 用户: {user_id}")
                else:
                    return self._build_error_response("TGT_DECRYPT_ERROR")
            except Exception as e:
                self.logger.write_log("ERROR", "TGS_REQ", f"[{thread_name}] 解密 Ticket_tgs 异常: {e}")
                return self._build_error_response("TGT_DECRYPT_ERROR")

            if not kc_tgs:
                return self._build_error_response("TGT_DECRYPT_ERROR")

            # 解密 Authenticator
            try:
                auth_bytes = bytes.fromhex(auth_hex)
                decrypted_auth = Crypto.des_decrypt(kc_tgs, auth_bytes)
                if decrypted_auth is None:
                    self.logger.write_log("ERROR", "TGS_REQ", f"[{thread_name}] Authenticator 解密失败")
                    return self._build_error_response("AUTHENTICATOR_ERROR")

                auth_data = json.loads(decrypted_auth.decode())
                auth_idc = auth_data.get('IDc', '')
                auth_adc = auth_data.get('ADc', '')
                ts3 = auth_data.get('TS3', '')

                if auth_idc != user_id:
                    self.logger.write_log("ERROR", "TGS_REQ", f"[{thread_name}] IDc 不匹配: {auth_idc} vs {user_id}")
                    return self._build_error_response("AUTHENTICATOR_MISMATCH")

                # 可选：验证时间戳 TS3
                if ts3:
                    try:
                        ts3_clean = ts3.replace('Z', '+00:00')
                        ts3_time = datetime.fromisoformat(ts3_clean)
                        now = datetime.now(timezone.utc)
                        if abs((now - ts3_time).total_seconds()) > 300:
                            self.logger.write_log("WARN", "TGS_REQ", f"[{thread_name}] TS3 超时: {ts3}")
                    except Exception as e:
                        self.logger.write_log("WARN", "TGS_REQ", f"[{thread_name}] TS3 解析失败: {e}")

                self.logger.write_log("INFO", "TGS_REQ", f"[{thread_name}] Authenticator 验证通过")
                print(f"[TGS] [{thread_name}] Authenticator 验证通过")
            except Exception as e:
                self.logger.write_log("ERROR", "TGS_REQ", f"[{thread_name}] 解密 Authenticator 异常: {e}")
                return self._build_error_response("AUTHENTICATOR_ERROR")

            # 生成服务票据
            kc_v = Crypto.generate_random_key()
            ts4 = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            self.logger.write_log("INFO", "TGS_REQ", f"[{thread_name}] 生成 Kc_v: {kc_v.hex()}")
            print(f"[TGS] [{thread_name}] 生成 Kc_v: {kc_v.hex()}")

            ticket_v_plain = {
                'Kc_v': Crypto.bytes_to_hex(kc_v),
                'IDc': user_id,
                'ADc': client_addr,
                'IDv': idv,
                'TS4': ts4,
                'Lifetime4': 300
            }
            ticket_v_json = json.dumps(ticket_v_plain, sort_keys=True)
            ticket_v_cipher = Crypto.des_encrypt(self.kv_key, ticket_v_json.encode())
            self.logger.write_log("INFO", "TGS_REQ", f"[{thread_name}] Ticket_v 密文长度: {len(ticket_v_cipher)}")

            # 构造响应
            response_plain = {
                'Kc_v': Crypto.bytes_to_hex(kc_v),
                'IDv': idv,
                'TS4': ts4,
                'Ticket_v': Crypto.bytes_to_hex(ticket_v_cipher)
            }
            response_json = json.dumps(response_plain, sort_keys=True)
            cipher_payload = Crypto.des_encrypt(kc_tgs, response_json.encode())

            response_data = {'data': {'cipher_hex': Crypto.bytes_to_hex(cipher_payload)}}

            # 添加证书
            if self.tgs_certificate:
                response_data['certificate'] = self.tgs_certificate
                self.logger.write_log("INFO", "TGS_REQ",
                                      f"[{thread_name}] 已添加证书: {self.tgs_certificate.get('cert_id')}")

            # 添加签名
            if self.tgs_private_key and self.tgs_private_key.get("n_hex") and self.tgs_private_key.get("d_hex"):
                self.logger.write_log("INFO", "TGS_REQ", f"[{thread_name}] 正在生成签名...")
                response_data['signature'] = Crypto.build_signature(
                    0x04,
                    response_data['data'],
                    self.config.tgs_machine_id,
                    self.tgs_private_key.get("n_hex", ""),
                    self.tgs_private_key.get("d_hex", "")
                )
                self.logger.write_log("INFO", "TGS_REQ",
                                      f"[{thread_name}] ✅ 已添加签名，签名值前64位: {response_data['signature']['value_hex'][:64]}")
            else:
                self.logger.write_log("ERROR", "TGS_REQ", f"[{thread_name}] ❌ 无法添加签名：私钥未加载")
                return self._build_error_response("KEY_NOT_FOUND")

            response_packet = Packet.build_packet(0x04, json.dumps(response_data).encode())
            self.logger.write_log("INFO", "TGS_REQ", f"[{thread_name}] 授权成功")
            print(f"[TGS] [{thread_name}] 授权成功")
            return response_packet

        except Exception as e:
            self.logger.write_log("ERROR", "TGS_REQ", f"[{thread_name}] 处理失败: {str(e)}")
            import traceback
            traceback.print_exc()
            return self._build_error_response("SERVER_INTERNAL_ERROR")

    def _handle_connection(self, client_socket: socket.socket, addr: tuple):
        """处理REQUESE,并返回RESPONSE - 在工作线程中执行"""
        thread_name = threading.current_thread().name
        self.logger.write_log("INFO", "TGS_SERVER", f"[{thread_name}] 开始处理连接: {addr}")

        try:
            while self.running:
                try:
                    result = Packet.read_packet(client_socket)

                    if result is None:
                        break

                    msg_type, payload = result
                    self.logger.write_log("INFO", "TGS_SERVER",
                                          f"[{thread_name}] 收到: {Packet.map_msg_type(msg_type)}")
                    print(f"[TGS] [{thread_name}] 收到: {Packet.map_msg_type(msg_type)}")

                    if msg_type == 0x03:
                        response = self._handle_tgs_request(payload, addr)
                        if response:
                            Packet.send_all(client_socket, response)
                            print("张晶虎")
                           
                    else:
                        error = self._build_error_response("INVALID_MSG_TYPE")
                        Packet.send_all(client_socket, error)
                except socket.timeout:
                    continue
                except Exception as e:
                    self.logger.write_log("ERROR", "TGS_SERVER", f"[{thread_name}] 处理错误: {str(e)}")
                    print(f"[TGS] [{thread_name}] 处理错误: {e}")
                    break
        finally:
            client_socket.close()
            self.logger.write_log("INFO", "TGS_SERVER", f"[{thread_name}] 连接关闭: {addr}")

            with self.connections_lock:
                if addr in self.active_connections:
                    del self.active_connections[addr]

    def _build_error_response(self, error_code: str) -> bytes:
        error_data = {'data': {'error_code': error_code, 'message': f"TGS error: {error_code}"}}

        if self.tgs_private_key and self.tgs_private_key.get("n_hex") and self.tgs_private_key.get("d_hex"):
            error_data['signature'] = Crypto.build_signature(
                0x0B,
                error_data['data'],
                self.config.tgs_machine_id,
                self.tgs_private_key.get("n_hex", ""),
                self.tgs_private_key.get("d_hex", "")
            )

        self.logger.write_log("ERROR", "TGS_RESP", f"返回错误响应: {error_code}")
        return Packet.build_packet(0x0B, json.dumps(error_data).encode())

    def stop(self):
        """优雅关闭服务器"""
        self.running = False
        self.logger.write_log("INFO", "TGS_SERVER", "TGS server stopping...")

        if self.server_socket:
            self.server_socket.close()

        print("[TGS] 正在等待工作线程完成...")
        self.executor.shutdown(wait=True, cancel_futures=False)

        self.logger.stop()
        print("[TGS] 已停止")


if __name__ == '__main__':
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config_path = os.path.join(project_root, 'configs', 'tgs_server.conf')

    server = TGSServer(config_path)
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
