#!/usr/bin/env python3
"""
AS认证服务器 - 集成CA证书申请
兼容 client.py 的手写 DES 实现
"""

import socket
import threading
import json
from datetime import datetime, timedelta, timezone
from typing import Optional
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.packet import Packet
from common.crypto import Crypto
from common.logger import AsyncLogger
from common.config import ConfigLoader
from common.ca_client import CertificateManager
from as_server.as_db import ASDatabase

# 允许的时间偏差（秒）
MAX_TIME_SKEW = 300


class ASServer:
    def __init__(self, config_path: str):
        self.config = ConfigLoader.load_as_config(config_path)
        if not self.config:
            raise Exception("Failed to load AS config")

        self.logger = AsyncLogger(self.config.log_path, "AS")
        self.db = ASDatabase(self.config.as_db_path)
        self.server_socket = None
        self.running = False
        self.ktgs_key = ConfigLoader.load_shared_key(self.config.ktgs_ref)

        # 证书管理器
        print(f"\n[AS] CA服务器地址: {self.config.ca_host}:{self.config.ca_port}")
        self.cert_manager = CertificateManager(
            machine_id=self.config.as_machine_id,
            role='AS',
            cert_storage_path=self.config.identity_store_path,
            ca_host=self.config.ca_host,
            ca_port=self.config.ca_port
        )

    def start(self) -> bool:
        print(f"\n{'=' * 60}")
        print(f"[AS] 启动认证服务器")
        print(f"[AS] 监听地址: {self.config.listen_host}:{self.config.listen_port}")
        print(f"[AS] Machine ID: {self.config.as_machine_id}")
        print(f'[AS] CA服务器: {self.config.ca_host}:{self.config.ca_port}')
        print(f"{'=' * 60}\n")

        self.logger.write("INFO", "AS server starting...")

        if not self.db.init_tables():
            self.logger.write("ERROR", "Failed to init database")
            return False

        # 申请证书
        print(f"\n[AS] 正在向CA申请证书...")
        if not self.cert_manager.ensure_certificate():
            print(f"[AS] 证书申请失败，使用模拟模式")
        else:
            cert = self.cert_manager.get_certificate()
            print(f"[AS] 证书已就绪: {cert.cert_id}")

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.config.listen_host, self.config.listen_port))
            self.server_socket.listen(100)
            self.running = True

            print(f"\n[AS] 服务器启动成功，等待连接...\n")

            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    print(f"[AS] 新连接: {addr}")
                    thread = threading.Thread(target=self._handle_connection, args=(client_socket, addr))
                    thread.daemon = True
                    thread.start()
                except Exception as e:
                    if self.running:
                        print(f"[AS] Accept error: {e}")
        except Exception as e:
            print(f"[AS] 启动失败: {e}")
            return False
        return True

    def _handle_connection(self, client_socket: socket.socket, addr: tuple):
        try:
            while True:
                result = Packet.read_packet(client_socket)
                if result is None:
                    break

                msg_type, payload = result
                print(f"[AS] 收到: {Packet.map_msg_type(msg_type)}")

                if msg_type == 0x01:  # AS_REQUEST
                    response = self._handle_as_request(payload, addr)
                    if response:
                        Packet.send_all(client_socket, response)
                else:
                    error = self._build_error_response("INVALID_MSG_TYPE")
                    Packet.send_all(client_socket, error)
        except Exception as e:
            print(f"[AS] 处理错误: {e}")
        finally:
            client_socket.close()

    def _handle_as_request(self, payload: bytes, addr: tuple) -> Optional[bytes]:
        try:
            request = json.loads(payload.decode())
            data = request.get('data', {})
            idc = data.get('IDc')
            idtgs = data.get('IDtgs')
            ts1_str = data.get('TS1')

            print(f"[AS] 处理用户: {idc}, 目标TGS: {idtgs}")

            # 1. 校验 TS1 时间窗口（防重放）
            if ts1_str:
                try:
                    ts1 = datetime.fromisoformat(ts1_str.replace('Z', '+00:00'))
                    now = datetime.now(timezone.utc)
                    if abs((now - ts1).total_seconds()) > MAX_TIME_SKEW:
                        print(f"[AS] TS1 超时: {ts1_str} vs {now.isoformat()}")
                        return self._build_error_response("TIME_SKEW_EXCEEDED")
                except Exception as e:
                    print(f"[AS] TS1 解析失败: {e}")

            # 2. 获取用户 Kc
            kc = self.db.get_user_kc(idc)
            if not kc:
                print(f"[AS] 用户不存在: {idc}")
                return self._build_error_response("USER_NOT_FOUND")
            print(f"[AS] 用户 Kc: {kc.hex()}")

            # 3. 生成 Kc_tgs
            kc_tgs = Crypto.generate_random_key()
            adc = addr[0]  # 客户端真实 IP
            print(f"[AS] 生成 Kc_tgs: {kc_tgs.hex()}, 客户端 ADc: {adc}")

            # 4. 构造 Ticket_tgs
            ticket_plain = {
                'Kc_tgs': Crypto.bytes_to_hex(kc_tgs),
                'IDc': idc,
                'ADc': adc,
                'IDtgs': idtgs if idtgs else self.config.tgs_id,
                'TS2': datetime.now(timezone.utc).isoformat(),
                'Lifetime2': 300
            }
            ticket_json = json.dumps(ticket_plain, sort_keys=True)
            ticket_cipher = Crypto.des_encrypt(self.ktgs_key, ticket_json.encode())
            print(f"[AS] Ticket_tgs 密文长度: {len(ticket_cipher)}")

            # 5. 构造 AS_RESPONSE 明文
            response_plain = {
                'Kc_tgs': Crypto.bytes_to_hex(kc_tgs),
                'IDtgs': ticket_plain['IDtgs'],
                'TS2': ticket_plain['TS2'],
                'Lifetime2': ticket_plain['Lifetime2'],
                'Ticket_tgs': Crypto.bytes_to_hex(ticket_cipher)
            }
            response_json = json.dumps(response_plain, sort_keys=True)
            print(f"[AS] 响应明文: {response_json}")

            # 6. 使用 Kc 加密整体响应
            cipher_payload = Crypto.des_encrypt(kc, response_json.encode())
            print(f"[AS] 响应密文: {cipher_payload.hex()[:64]}...")

            response_data = {'data': {'cipher_hex': Crypto.bytes_to_hex(cipher_payload)}}

            # 可选：添加证书（如果存在且需要）
            cert = self.cert_manager.get_certificate()
            if cert:
                response_data['certificate'] = cert.to_dict()

            response_packet = Packet.build_packet(0x02, json.dumps(response_data).encode())
            print(f"[AS] 认证成功，返回 Ticket_tgs")
            return response_packet

        except Exception as e:
            print(f"[AS] 处理失败: {e}")
            import traceback
            traceback.print_exc()
            return self._build_error_response("SERVER_INTERNAL_ERROR")

    def _build_error_response(self, error_code: str) -> bytes:
        error_data = {'data': {'error_code': error_code, 'message': f"AS error: {error_code}"}}
        return Packet.build_packet(0x0B, json.dumps(error_data).encode())

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        self.logger.stop()
        self.db.close()
        print("[AS] 已停止")


if __name__ == '__main__':
    os.makedirs('logs', exist_ok=True)
    os.makedirs('secure/as_identity', exist_ok=True)

    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config_path = os.path.join(project_root, 'configs', 'as_server.conf')

    print(f"[AS] 配置文件路径: {config_path}")
    print(f"[AS] 配置文件存在: {os.path.exists(config_path)}")

    server = ASServer(config_path)
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
