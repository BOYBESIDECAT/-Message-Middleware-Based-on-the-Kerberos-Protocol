#!/usr/bin/env python3
import os
import secrets


def init_keys():
    os.makedirs('secure/keys/ktgs', exist_ok=True)
    os.makedirs('secure/keys/service', exist_ok=True)

    # 生成Ktgs密钥（8字节）
    ktgs_key = secrets.token_bytes(8)
    with open('secure/keys/ktgs/main.keyhex', 'w') as f:
        f.write(ktgs_key.hex())

    # 生成Kv密钥（8字节）
    kv_key = secrets.token_bytes(8)
    with open('secure/keys/service/chatserver.keyhex', 'w') as f:
        f.write(kv_key.hex())

    print("Keys generated successfully")
    print(f"Ktgs key: {ktgs_key.hex()}")
    print(f"Kv key: {kv_key.hex()}")


if __name__ == '__main__':
    init_keys()