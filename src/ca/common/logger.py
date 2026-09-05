import queue
import threading
import datetime
from typing import Optional
from .packet import MapMsgType

class AsyncLogger:
    def __init__(self, log_path: str):
        self.log_path = log_path
        self.log_queue = queue.Queue()
        self.log_thread = threading.Thread(target=self._log_thread_main, daemon=True)
        self.running = True
        self.log_thread.start()

    def _log_thread_main(self) -> None:
        """日志线程主循环"""
        with open(self.log_path, 'a', encoding='utf-8') as f:
            while self.running or not self.log_queue.empty():
                try:
                    log_item = self.log_queue.get(timeout=1)
                    f.write(log_item + '\n')
                    f.flush()
                except queue.Empty:
                    continue

    def write_log(self, level: str, module: str, text: str, 
                  msg_type: Optional[int] = None, error_code: Optional[str] = None) -> None:
        """异步写日志(对齐3.1.5.4)"""
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"
        msg_type_str = MapMsgType(msg_type) if msg_type is not None else "N/A"
        error_str = f" error_code={error_code}" if error_code else ""
        log_line = f"[{timestamp}] [{level}] [{module}] msg_type={msg_type_str} - {text}{error_str}"
        self.log_queue.put(log_line)

    def stop(self) -> None:
        """停止日志模块"""
        self.running = False
        self.log_thread.join()

# 全局日志实例(由CA服务器初始化)
ca_logger: Optional[AsyncLogger] = None