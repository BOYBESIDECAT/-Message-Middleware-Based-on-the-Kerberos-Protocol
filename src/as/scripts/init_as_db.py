#!/usr/bin/env python3
import pymysql
import hashlib
import os


def init_as_db():
    """初始化AS数据库"""
    # 先连接到MySQL服务器
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
        cursor.execute("CREATE DATABASE IF NOT EXISTS as_db")
        cursor.execute("USE as_db")

        # 创建用户表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_account (
                user_id VARCHAR(64) PRIMARY KEY,
                password_hash VARCHAR(64) NOT NULL,
                cert_serial VARCHAR(64),
                create_time DATETIME NOT NULL,
                status VARCHAR(16) NOT NULL DEFAULT 'normal'
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

        # 创建证书表
        cursor.execute("""
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
        """)

        # 插入测试用户（密码: test123）
        password_hash = hashlib.sha256(b"test123").digest()[:8].hex()

        test_users = [
            ('alice', password_hash),
            ('bob', password_hash),
            ('charlie', password_hash),
        ]

        for user_id, pwd_hash in test_users:
            cursor.execute("""
                INSERT IGNORE INTO user_account (user_id, password_hash, create_time, status)
                VALUES (%s, %s, NOW(), 'normal')
            """, (user_id, pwd_hash))

        conn.commit()
        print("AS database initialized successfully!")
        print("Test users: alice, bob, charlie (password: test123)")

    except Exception as e:
        print(f"Failed to initialize AS database: {e}")
    finally:
        cursor.close()
        conn.close()


if __name__ == '__main__':
    init_as_db()