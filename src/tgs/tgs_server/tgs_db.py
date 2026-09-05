import sys
import os

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.database import Database
from typing import Optional


class TGSDatabase:
    def __init__(self, db_path: str):
        self.db = Database(db_path)

    def init_tables(self) -> bool:
        if not self.db.connect():
            return False

        # 创建服务账号表
        create_service_table = """
            CREATE TABLE IF NOT EXISTS service_account (
                service_id VARCHAR(64) PRIMARY KEY,
                service_name VARCHAR(128) NOT NULL,
                service_addr VARCHAR(128) NOT NULL,
                cert_serial VARCHAR(64),
                status VARCHAR(16) NOT NULL DEFAULT 'normal',
                INDEX idx_status (status)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """
        if not self.db.execute_update(create_service_table):
            return False

        # 创建授权策略表
        create_policy_table = """
            CREATE TABLE IF NOT EXISTS tgs_policy (
                policy_id VARCHAR(64) PRIMARY KEY,
                service_id VARCHAR(64) NOT NULL,
                ticket_lifetime INT NOT NULL,
                allow_status VARCHAR(16) NOT NULL,
                update_time DATETIME NOT NULL,
                INDEX idx_service_id (service_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """
        if not self.db.execute_update(create_policy_table):
            return False

        # 插入默认服务
        self.db.execute_update(
            "INSERT IGNORE INTO service_account (service_id, service_name, service_addr, status) VALUES (%s, %s, %s, %s)",
            ("CHATSERVER-001", "ChatServer", "127.0.0.1:8002", "normal")
        )

        return True

    def check_service_exists(self, service_id: str) -> bool:
        sql = "SELECT service_id FROM service_account WHERE service_id = %s AND status = 'normal'"
        result = self.db.execute_query(sql, (service_id,))
        return len(result) > 0 if result else False

    def close(self):
        self.db.close()