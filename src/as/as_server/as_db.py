import sys
import os

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.database import Database
from typing import Optional


class ASDatabase:
    def __init__(self, db_path: str):
        self.db = Database(db_path)

    def init_tables(self) -> bool:
        if not self.db.connect():
            return False

        # 创建用户表
        create_user_table = """
            CREATE TABLE IF NOT EXISTS user_account (
                user_id VARCHAR(64) PRIMARY KEY,
                password_hash VARCHAR(64) NOT NULL,
                cert_serial VARCHAR(64),
                create_time DATETIME NOT NULL,
                status VARCHAR(16) NOT NULL DEFAULT 'normal'
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """
        if not self.db.execute_update(create_user_table):
            return False

        # 创建证书表
        create_cert_table = """
            CREATE TABLE IF NOT EXISTS client_certificate (
                cert_serial VARCHAR(64) PRIMARY KEY,
                owner_id VARCHAR(64) NOT NULL,
                public_key TEXT NOT NULL,
                issuer VARCHAR(128) NOT NULL,
                valid_from DATETIME NOT NULL,
                valid_to DATETIME NOT NULL,
                status VARCHAR(16) NOT NULL DEFAULT 'normal',
                INDEX idx_owner_id (owner_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """
        if not self.db.execute_update(create_cert_table):
            return False

        return True

    def get_user_kc(self, user_id: str) -> Optional[bytes]:
        sql = "SELECT password_hash FROM user_account WHERE user_id = %s AND status = 'normal'"
        result = self.db.execute_query(sql, (user_id,))
        if result:
            return bytes.fromhex(result[0]['password_hash'])
        return None

    def close(self):
        self.db.close()