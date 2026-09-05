#!/usr/bin/env python3
import pymysql
import os


def init_tgs_db():
    """初始化TGS数据库"""
    conn = pymysql.connect(
        host='localhost',
        user='root',
        password='zjh041300',
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )

    try:
        cursor = conn.cursor()

        # 创建数据库
        cursor.execute("CREATE DATABASE IF NOT EXISTS tgs_db")
        cursor.execute("USE tgs_db")

        # 创建服务账号表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS service_account (
                service_id VARCHAR(64) PRIMARY KEY,
                service_name VARCHAR(128) NOT NULL,
                service_addr VARCHAR(128) NOT NULL,
                cert_serial VARCHAR(64),
                status VARCHAR(16) NOT NULL DEFAULT 'normal',
                INDEX idx_status (status)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

        # 创建授权策略表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tgs_policy (
                policy_id VARCHAR(64) PRIMARY KEY,
                service_id VARCHAR(64) NOT NULL,
                ticket_lifetime INT NOT NULL,
                allow_status VARCHAR(16) NOT NULL,
                update_time DATETIME NOT NULL,
                INDEX idx_service_id (service_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

        # 插入默认服务
        cursor.execute("""
            INSERT IGNORE INTO service_account (service_id, service_name, service_addr, status)
            VALUES (%s, %s, %s, %s)
        """, ("CHATSERVER-001", "ChatServer", "127.0.0.1:8002", "normal"))

        # 插入默认策略
        cursor.execute("""
            INSERT IGNORE INTO tgs_policy (policy_id, service_id, ticket_lifetime, allow_status, update_time)
            VALUES (%s, %s, %s, %s, NOW())
        """, ("POLICY_001", "CHATSERVER-001", 300, "allow"))

        conn.commit()
        print("TGS database initialized successfully!")

    except Exception as e:
        print(f"Failed to initialize TGS database: {e}")
    finally:
        cursor.close()
        conn.close()


if __name__ == '__main__':
    init_tgs_db()