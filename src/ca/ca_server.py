import socket
import threading
import json
import datetime
import argparse
import queue
import tkinter as tk
from tkinter import scrolledtext, ttk
from typing import Optional
from Crypto.PublicKey import RSA
from common.config import LoadCAConfig, CAConfig
from common.db import CADatabase
from common.logger import AsyncLogger, ca_logger
from common.crypto import CanonicalJson, RSASign
from common.certificate import SimpleX509Certificate
from common.packet import BuildPacket, ReadPacket, SendAll, MSG_TYPE, MapMsgType

VERSION="1.0.0"
BUILD_DATE="2026-05-25"
UTC=datetime.timezone.utc

class CAUI(tk.Tk):
    """UI"""
    def __init__(self, config: CAConfig):
        super().__init__()
        self.config = config
        self.title(f"CA服务器收发报文监控")
        self.geometry("800x500")
        self.minsize(800,500)

        self.log_queue = queue.Queue()

        self._create_widgets()

        self._process_log_queue()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.ca_server: Optional[CAServer] =None

    def _create_widgets(self):
        """创建组件"""
        # 创建顶部状态栏的框架容器
        status_frame = ttk.Frame(self)
        status_frame.pack(fill=tk.X, padx=10, pady=5)

        # 创建状态显示标签
        ttk.Label(status_frame, text="服务器状态", font=("微软雅黑", 10, "bold")).grid(row=0, column=0, sticky=tk.W)
        self.status_label = ttk.Label(status_frame, text="启动中...", foreground="blue")
        self.status_label.grid(row=0, column=1, sticky=tk.W, padx=5)

        # 创建在线连接标签
        ttk.Label(status_frame, text="在线连接:").grid(row=0, column=2, sticky=tk.W, padx=20)
        self.conn_label = ttk.Label(status_frame, text="0")
        self.conn_label.grid(row=0, column=3, sticky=tk.W)

        # 创建颁发证书标签
        ttk.Label(status_frame, text="颁发证书:").grid(row=0, column=4, sticky=tk.W, padx=20)
        self.cert_label = ttk.Label(status_frame, text="0")
        self.cert_label.grid(row=0, column=5, sticky=tk.W)

        # 创建显示详细报文复选框
        self.show_detail = tk.BooleanVar(value=True)
        detail_check = ttk.Checkbutton(
            status_frame,
            text="显示详细报文",
            variable=self.show_detail,
            command=self._toggle_detail
        )
        detail_check.grid(row=0, column=6, sticky=tk.W, padx=30)

        # 创建日志显示区域的框架容器
        log_frame = ttk.Frame(self)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # 创建滚动文本框
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            font=("Consolas", 9),
            state=tk.DISABLED
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # 配置文本颜色
        self.log_text.tag_config("INFO", foreground="black")
        self.log_text.tag_config("WARN", foreground="orange")
        self.log_text.tag_config("ERROR", foreground="red")
        self.log_text.tag_config("SUCCESS", foreground="green")
        self.log_text.tag_config("TIME", foreground="gray")
        self.log_text.tag_config("DETAIL", foreground="darkblue")

        # 创建底部状态栏的框架容器
        bottom_frame = ttk.Frame(self)
        bottom_frame.pack(fill=tk.X, padx=10, pady=5)

        # 创建监听地址标签
        ttk.Label(
            bottom_frame,
            text=f"监听地址:{self.config.listen_host}:{self.config.listen_port}",
            foreground="gray"
        ).pack(side=tk.LEFT)

    def _toggle_detail(self):
        """切换详细报文显示状态"""
        if self.show_detail.get():
            self.log("INFO", "已开启详细报文显示")
        else:
            self.log("INFO", "已关闭详细报文显示")
    
    def _format_json(self, data: bytes | dict) -> str:
        """格式化JSON数据"""
        try:
            if isinstance(data, bytes):
                data = json.loads(data.decode('utf-8'))
            return json.dumps(data, indent=2, ensure_ascii=False)
        except json.JSONDecodeError as e:
            return f"JSON解析失败: {str(e)}\n原始数据: {data.hex() if isinstance(data, bytes) else str(data)}"
        except Exception as e:
            return f"格式化失败: {str(e)}\n原始数据: {data.hex() if isinstance(data, bytes) else str(data)}"
    
    def _process_log_queue(self):
        """"循环读取日志队列,将日志添加到文本框"""
        while not self.log_queue.empty():
            log_item = self.log_queue.get()
            self._append_log(log_item)

        # 定时检查队列,非阻塞 
        self.after(100, self._process_log_queue)

    def _append_log(self, log_item: dict):
        """将日志项插入到文本框"""
        self.log_text.config(state=tk.NORMAL)

        self.log_text.insert(tk.END, f"[{log_item['time']}] ", "TIME")

        level = log_item["level"]
        content = log_item["content"]
        tag = log_item.get("tag", level)
        self.log_text.insert(tk.END, f"[{level}] {content}\n", tag)

        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def update_stats(self, stats: dict):
        """"更新在线连接数、颁发证书数状态标签"""
        self.conn_label.config(text=str(stats["active_connections"]))
        self.cert_label.config(text=str(stats["certs_issued"]))

    def set_server_running(self):
        """"设置运行状态标签为'运行中'"""
        self.status_label.config(text="运行中", foreground="green")

    def set_server_stopped(self):
        """设置运行状态标签为'已停止'"""
        self.status_label.config(text="已停止", foreground="red")

    def log(self, level: str, content: str, tag: str = None):
        """向日志队列添加日志"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_queue.put({
            "time": timestamp,
            "level": level,
            "content": content,
            "tag": tag or level
        })

    def log_detail(self, title: str, data: bytes | dict):
        """若开启显示详细内容则格式化并记录报文内容"""
        if not self.show_detail.get():
            return
        formatted = self._format_json(data)
        self.log("INFO", f"{title}:\n{formatted}", "DETAIL")

    def _on_close(self):
        """关闭窗口事件处理"""
        if self.ca_server:
            self.log("INFO", "正在停止CA服务器...")
            self.ca_server.stop()
        self.destroy()

class CAServer:
    """CA服务器"""
    def __init__(self, config_path: str, ui: CAUI):
        self.config_path = config_path
        self.config = LoadCAConfig(config_path)
        self.db = CADatabase(self.config.ca_db_path)
        self.logger = AsyncLogger(self.config.log_path)
        global ca_logger
        ca_logger = self.logger

        self.ui = ui

        self.stats = {
            "total_connections": 0,
            "active_connections": 0,
            "certs_issued": 0,
            "certs_renewed": 0,
            "certs_revoked": 0
        }

        self.stats_lock = threading.Lock()

        self.ca_private_key = self._load_ca_private_key()
        self.ca_public_key = self.ca_private_key.publickey()

        self.serial_counter = self.config.serial_counter
        self.serial_lock = threading.Lock()

        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.server_thread: Optional[threading.Thread] = None

    def _load_ca_private_key(self) -> RSA.RsaKey:
        """加载CA根私钥"""
        try:
            with open(self.config.ca_private_key_path, 'rb') as f:
                return RSA.import_key(f.read())
        except Exception as e:
            error_msg = f"CA私钥加载失败: {str(e)}"
            self.ui.log("ERROR", error_msg)
            self.logger.write_log("ERROR", "CA_INIT", error_msg, error_code="CA_PRIVATE_KEY_ERROR")
            raise SystemExit(1)
        
    def start(self):
        """启动CA服务器"""
        self.running = True
        self.server_thread = threading.Thread(target=self._server_main, daemon=True)
        self.server_thread.start()

    def _server_main(self):
        """服务器主循环"""
        self.ui.log("INFO", "正在启动CA服务器...")
        self.ui.log("INFO", f"配置文件: {self.config_path}")
        self.ui.log("INFO", f"数据库路径: {self.config.ca_db_path}")
        self.ui.log("INFO", f"日志文件: {self.config.log_path}")
        self.ui.log("INFO", f"CA根证书: {self.config.ca_cert_path}")
        self.ui.log("INFO", f"当前序列号: {self.serial_counter:06d}")

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind((self.config.listen_host, self.config.listen_port))
        except OSError as e:
            error_msg = f"端口绑定失败: {self.config.listen_port} - {str(e)}"
            self.ui.log("ERROR", error_msg)
            self.logger.write_log("ERROR", "CA_SERVER", error_msg)
            self.ui.set_server_stopped()
            return
        
        self.server_socket.listen(5)

        self.ui.log("SUCCESS", f"CA服务器已启动, 监听地址: {self.config.listen_host}:{self.config.listen_port}")
        self.ui.set_server_running()
        self.logger.write_log("INFO", "CA_SERVER", f"CA server started on {self.config.listen_host}:{self.config.listen_port}")

        try:
            while self.running:
                conn, addr = self.server_socket.accept()
                with self.stats_lock:
                    self.stats["total_connections"] += 1
                    self.stats["active_connections"] += 1
                    self.ui.update_stats(self.stats)
                client_addr = f"{addr[0]}:{addr[1]}"
                self.ui.log("INFO", f"新客户端连接: {client_addr} (当前在线: {self.stats['active_connections']})")
                self.logger.write_log("INFO", "CA_CONN", f"New connection from {client_addr}")

                client_thread = threading.Thread(
                    target=self._handle_ca_connection,
                    args=(conn, client_addr),
                    daemon=True
                )
                client_thread.start()
        except Exception as e:
            if self.running:
                self.ui.log("ERROR", f"服务器运行错误: {str(e)}")
        finally:
            self.stop()

    def stop(self):
        """停止CA服务器"""
        if not self.running:
            return
        self.running = False
        if self.server_socket:
            self.server_socket.close()

        self.ui.log("INFO", "CA服务器已停止")
        self.ui.log("INFO", "运行统计:")
        self.ui.log("INFO", f" 总连接数: {self.stats['total_connections']}")
        self.ui.log("INFO", f" 颁发证书: {self.stats['certs_issued']}")

        self.logger.write_log("INFO", "CA_SERVER", "CA server stopped")
        self.logger.stop()
        self.ui.set_server_stopped()

    def _handle_ca_connection(self, conn: socket.socket, remote_addr: str):
        """处理客户端连接"""
        try:
            while self.running:
                msg_type, payload = ReadPacket(conn)
                msg_name = MapMsgType(msg_type)

                self.ui.log("INFO", f"收到来自 {remote_addr} 的 {msg_name} 请求")
                self.ui.log_detail("请求报文详情", payload)
                self.logger.write_log("DEBUG", "CA_CONN", f"Received {msg_name} from {remote_addr}", msg_type=msg_type)

                if msg_type == MSG_TYPE["CERT_APPLY"]:
                    response = self._handle_cert_apply(payload, remote_addr)
                elif msg_type == MSG_TYPE["CERT_RENEW_REQUEST"]:
                    response = self._handle_cert_renew(payload, remote_addr)
                else:
                    error_msg = f"不支持的消息类型: {msg_name}"
                    self.ui.log("WARN", f"{error_msg} (来自 {remote_addr})")
                    response = self._build_error_response("INVALID_MSG_TYPE", error_msg)

                self.ui.log("INFO", f"向 {remote_addr} 发送 {MapMsgType(response[4])} 响应")
                self.ui.log_detail("响应报文详情", response[5:])

                print("郑睿捷")
                SendAll(conn, response)
        
        except (ConnectionResetError, ConnectionError, BrokenPipeError):
            self.ui.log("INFO", f"客户端 {remote_addr} 已正常断开连接")
        except Exception as e:
            error_msg = f"与 {remote_addr} 通信异常: {str(e)}"
            self.ui.log("ERROR", error_msg)
            self.logger.write_log("ERROR", "CA_CONN", error_msg)
        finally:
            try:
                conn.close()
            except:
                pass
            with self.stats_lock:
                self.stats["active_connections"] -= 1
                self.ui.update_stats(self.stats)
            self.ui.log("INFO", f"客户端 {remote_addr} 连接已关闭 (当前在线: {self.stats['active_connections']})")
            self.logger.write_log("INFO", "CA_CONN", f"Connection closed with {remote_addr}")
    
    def _handle_cert_apply(self, payload: bytes, remote_addr: str) -> bytes:
        """处理证书申请"""
        try:
            request = json.loads(payload.decode('utf-8'))
            data = request["data"]

            if not all(k in data for k in ["machine_id", "subject_role", "public_key_hex"]):
                error_msg = "证书申请缺少必填字段(machine_id/subject_role/public_key_hex)"
                self.ui.log("ERROR", f"{error_msg} (来自 {remote_addr})")
                return self._build_error_response("CERT_APPLY_FORMAT_ERROR", error_msg)
            
            machine_id = data["machine_id"]
            subject_role = data["subject_role"]
            public_key_hex = data["public_key_hex"]

            if subject_role not in ["CLIENT", "AS", "TGS", "APP"]:
                error_msg = f"无效的主体角色: {subject_role} (允许: CLIENT/AS/TGS/APP)"
                self.ui.log("ERROR", f"{error_msg} (来自 {remote_addr})")
                return self._build_error_response("CERT_APPLY_FORMAT_ERROR", error_msg)
            
            with self.serial_lock:
                serial_number = f"{self.serial_counter:06d}"
                self.serial_counter += 1

            valid_from = datetime.datetime.now(UTC).replace(microsecond=0)
            valid_to = valid_from + datetime.timedelta(days=365)

            cert = SimpleX509Certificate(
                cert_id=machine_id,
                serial_number=serial_number,
                subject_role=subject_role,
                public_key_hex=public_key_hex,
                valid_from=valid_from,
                valid_to=valid_to
            )

            cert_body = cert.get_body_dict()
            canonical_body = CanonicalJson(cert_body).encode('utf-8')
            ca_signature = RSASign(self.ca_private_key, canonical_body)
            cert.ca_signature_hex = ca_signature.hex()

            if not self.db.persist_certificate(cert):
                error_msg = f"证书 {machine_id} 数据库保存失败"
                self.ui.log("ERROR", error_msg)
                return self._build_error_response("CERT_PERSIST_ERROR", error_msg)
            
            with self.stats_lock:
                self.stats["certs_issued"] += 1
                self.ui.update_stats(self.stats)

            self.ui.log("SUCCESS", f"成功颁发证书")
            self.ui.log("INFO", f" 证书ID: {cert.cert_id}")
            self.ui.log("INFO", f" 序列号: {cert.serial_number}")
            self.ui.log("INFO", f" 主体角色: {cert.subject_role}")
            self.ui.log("INFO", f" 有效期： {cert.valid_from.astimezone().strftime('%Y-%m-%d %H:%M:%S')} ~ {cert.valid_to.astimezone().strftime('%Y-%m-%d %H:%M:%S')}")
            self.ui.log("INFO", f" 申请来源: {remote_addr}")

            self.logger.write_log("INFO", "CA_CERT", f"Issued certificate {cert.cert_id} (serial: {serial_number}) to {remote_addr}")

            return self._build_cert_response("issued", certificate=cert)
        
        except Exception as e:
            error_msg = f"证书申请处理失败: {str(e)}"
            self.ui.log("ERROR", error_msg)
            self.logger.write_log("ERROR", "CA_CERT", error_msg, error_code="CERT_APPLY_FAILED")
            return self._build_error_response("CERT_APPLY_FAILED", str(e))
        
    def _handle_cert_renew(self, payload: bytes, remote_addr: str) -> bytes:
        """处理证书续期"""
        try:
            request = json.loads(payload.decode('utf-8'))
            data = request["data"]

            if not all(k in data for k in ["cert_id", "machine_id", "subject_role", "public_key_hex"]):
                error_msg = "证书缺少必填字段(cert_id/machine_id/subject_role/public_key_hex)"
                self.ui.log("ERROR", f"{error_msg} (来自 {remote_addr})")
                return self._build_error_response("CERT_APPLY_FORMAT_ERROR", error_msg)
            
            cert_id = data["cert_id"]
            machine_id = data["machine_id"]
            subject_role = data["subject_role"]
            public_key_hex = data["public_key_hex"]

            old_record = self.db.query_certificate_record(cert_id)
            if not old_record:
                error_msg = f"证书 {cert_id} 不存在"
                self.ui.log("ERROR", f"{error_msg} (来自 {remote_addr})")
                return self._build_error_response("CERT_NOT_FOUND", error_msg)
            
            if old_record["machine_id"] != machine_id or old_record["subject_role"] != subject_role:
                error_msg = f"证书续期主体不匹配: 期望 machine_id={old_record['machine_id']}, role={old_record['subject_role']}"
                self.ui.log("WARN", f"{error_msg} (来自 {remote_addr})")
                self.logger.write_log("WARN", "CA_CERT", f"Certificate renew mismatch: cert_id={cert_id}", error_code="CERT_MACHINE_ID_MISMATCH")
                return self._build_error_response("CERT_MACHINE_ID_MISMATCH", error_msg)
            
            with self.serial_lock:
                serial_number = f"{self.serial_counter:06d}"
                self.serial_counter += 1

            valid_from = datetime.datetime.now(UTC).replace(microsecond=0)
            valid_to = valid_from + datetime.timedelta(days=365)

            new_cert = SimpleX509Certificate(
                cert_id=cert_id,
                serial_number=serial_number,
                subject_role=subject_role,
                public_key_hex=public_key_hex,
                valid_from=valid_from,
                valid_to=valid_to
            )

            cert_body = new_cert.get_body_dict()
            canonical_body = CanonicalJson(cert_body).encode('utf-8')
            ca_signature = RSASign(self.ca_private_key, canonical_body)
            new_cert.ca_signature_hex = ca_signature.hex()

            self.db.update_certificate_status(cert_id, "expired")
            if not self.db.persist_certificate(new_cert):
                error_msg = f"新证书 {cert_id} 数据库保存失败"
                self.ui.log("ERROR", error_msg)
                return self._build_error_response("CERT_PERSIST_ERROR", error_msg)
            
            with self.stats_lock:
                self.stats["certs_renewed"] += 1
                self.ui.update_stats(self.stats)

            self.ui.log("SUCCESS", f"成功续期证书")
            self.ui.log("INFO", f" 原证书ID: {cert_id}")
            self.ui.log("INFO", f" 新证书序列号: {new_cert.serial_number}")
            self.ui.log("INFO", f" 主体角色: {new_cert.subject_role}")
            self.ui.log("INFO", f" 新有效期: {new_cert.valid_from.astimezone().strftime('%Y-%m-%d %H:%M:%S')} ~ {new_cert.valid_to.astimezone().strftime('%Y-%m-%d %H:%M:%S')}")
            self.ui.log("INFO", f" 申请来源: {remote_addr}")

            self.logger.write_log("INFO", "CA_CERT", f"Renewed certificate {cert_id} (new serial: {serial_number}) for {remote_addr}")

            return self._build_cert_response("renewed", certificate=new_cert)
        
        except Exception as e:
            error_msg = f"证书续期处理失败: {str(e)}"
            self.ui.log("ERROR", error_msg)
            self.logger.write_log("ERROR", "CA_CERT", error_msg, error_code="CERT_RENEW_FAILED")
            return self._build_error_response("CERT_RENEW_FAILED", str(e))
        

    def _build_cert_response(self, status: str, certificate: Optional[SimpleX509Certificate] = None, error_code: Optional[str] = None) -> bytes:
        """构建证书响应报文"""
        response_data = {"status": status}
        if certificate:
            response_data["certificate"] = certificate.to_dict()
        if error_code:
            response_data["error_code"] = error_code

        payload = json.dumps({"data": response_data}).encode('utf-8')
        return BuildPacket(MSG_TYPE["CERT_RESPONSE"], payload)
    
    def _build_error_response(self, error_code: str, message: str) -> bytes:
        """构建错误响应"""
        payload = json.dumps({
            "data": {
                "error_code": error_code,
                "message": message
            }
        }).encode('utf-8')
        return BuildPacket(MSG_TYPE["ERROR_RESPONSE"], payload)
    
def main():
    """入口函数"""
    try:
        config = LoadCAConfig("config/ca_server.conf")
        ui = CAUI(config)
        ca_server = CAServer("config/ca_server.conf", ui)
        ui.ca_server = ca_server
        ca_server.start()
        ui.mainloop()

    except Exception as e:
        print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] 服务器启动失败: {str(e)}")
        raise SystemExit(1)

if __name__ == "__main__":
    main()
