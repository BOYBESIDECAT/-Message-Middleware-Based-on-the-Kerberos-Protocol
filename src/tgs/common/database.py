import pymysql
from typing import Optional, List, Dict


import pymysql
from typing import Optional, List, Dict


class Database:
    """数据库基类（使用PyMySQL）"""

    def __init__(self, db_name: str):
        self.db_name = db_name
        self.conn = None

    def connect(self) -> bool:
        """连接数据库"""
        try:
            self.conn = pymysql.connect(
                host='localhost',
                user='root',
                password='zjh041300',
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor,
                auth_plugin_map={
                    'sha256_password': 'mysql_native_password',
                    'caching_sha2_password': 'mysql_native_password'
                }
            )
            # 创建数据库（如果不存在）
            self._create_database_if_not_exists()
            # 切换到目标数据库
            self.conn.select_db(self.db_name)
            return True
        except Exception as e:
            print(f"Database connection failed: {e}")
            return False
    def _create_database_if_not_exists(self):
        """创建数据库（如果不存在）"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{self.db_name}`")
            self.conn.commit()
            cursor.close()
        except Exception as e:
            print(f"Failed to create database: {e}")

    def close(self):
        """关闭数据库连接"""
        if self.conn:
            self.conn.close()

    def execute_query(self, sql: str, params: tuple = ()) -> Optional[List[Dict]]:
        """执行查询语句"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(sql, params)
            result = cursor.fetchall()
            cursor.close()
            return result
        except Exception as e:
            print(f"Query failed: {e}")
            return None

    def execute_update(self, sql: str, params: tuple = ()) -> bool:
        """执行更新语句（INSERT, UPDATE, DELETE）"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(sql, params)
            self.conn.commit()
            cursor.close()
            return True
        except Exception as e:
            print(f"Update failed: {e}")
            self.conn.rollback()
            return False