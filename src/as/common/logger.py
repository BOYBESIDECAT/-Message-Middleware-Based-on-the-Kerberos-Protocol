import threading
import queue
from datetime import datetime
from typing import Optional
import os


class AsyncLogger:
    """异步日志模块"""

    def __init__(self, log_path: str, module: str):
        self.log_queue = queue.Queue()
        self.log_thread = None
        self.running = False
        self.log_path = log_path
        self.module = module

    def start(self):
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        self.running = True
        self.log_thread = threading.Thread(target=self._log_thread_main)
        self.log_thread.daemon = True
        self.log_thread.start()

    def stop(self):
        self.running = False
        self.log_queue.put(None)
        if self.log_thread:
            self.log_thread.join(timeout=5)

    def write(self, level: str, text: str, msg_type: Optional[int] = None, error_code: Optional[str] = None):
        log_item = {
            'time': datetime.now().isoformat(),
            'level': level,
            'module': self.module,
            'text': text,
            'msg_type': msg_type,
            'error_code': error_code
        }
        self.log_queue.put(log_item)

    def write_log(self, level: str, module: str, text: str,
                  msg_type: Optional[int] = None, error_code: Optional[str] = None):
        """兼容旧代码的写日志方法"""
        self.write(level, text, msg_type, error_code)

    def _log_thread_main(self):
        while self.running:
            try:
                log_item = self.log_queue.get(timeout=1)
                if log_item is None:
                    break
                self._write_to_file(log_item)
            except queue.Empty:
                continue

    def _write_to_file(self, log_item: dict):
        try:
            with open(self.log_path, 'a', encoding='utf-8') as f:
                log_line = f"[{log_item['time']}] [{log_item['level']}] [{log_item['module']}]"
                if log_item.get('msg_type') is not None:
                    log_line += f" [0x{log_item['msg_type']:02X}]"
                if log_item.get('error_code'):
                    log_line += f" [{log_item['error_code']}]"
                log_line += f" {log_item['text']}\n"
                f.write(log_line)
        except Exception:
            pass