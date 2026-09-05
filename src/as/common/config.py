import configparser
from dataclasses import dataclass
from typing import Optional
import os


@dataclass
class ASConfig:
    listen_host: str
    listen_port: int
    as_db_path: str
    tgs_id: str
    ktgs_ref: str
    ca_host: str
    ca_port: int
    as_machine_id: str
    identity_store_path: str
    log_path: str


@dataclass
class TGSConfig:
    listen_host: str
    listen_port: int
    tgs_db_path: str
    tgs_id: str
    service_id: str
    ktgs_ref: str
    kv_ref: str
    ca_host: str
    ca_port: int
    tgs_machine_id: str
    identity_store_path: str
    log_path: str


class ConfigLoader:

    @staticmethod
    def load_as_config(config_path: str) -> Optional[ASConfig]:
        try:
            config = configparser.ConfigParser()
            config.read(config_path)
            cfg = config['as_server.conf']
            return ASConfig(
                listen_host=cfg.get('listen_host', '0.0.0.0'),
                listen_port=cfg.getint('listen_port', 8000),
                as_db_path=cfg.get('as_db_path', 'as_db'),
                tgs_id=cfg.get('tgs_id', 'TGS-001'),
                ktgs_ref=cfg.get('ktgs_ref', 'key://ktgs/main'),
                ca_host=cfg.get('ca_host', '127.0.0.1'),
                ca_port=cfg.getint('ca_port', 8003),
                as_machine_id=cfg.get('as_machine_id', 'AS-HOST-001'),
                identity_store_path=cfg.get('identity_store_path', 'secure/as_identity'),
                log_path=cfg.get('log_path', 'logs/as.log.txt')
            )
        except Exception as e:
            print(f"Failed to load AS config: {e}")
            return None

    @staticmethod
    def load_tgs_config(config_path: str) -> Optional[TGSConfig]:
        try:
            config = configparser.ConfigParser()
            config.read(config_path)
            cfg = config['tgs_server.conf']
            return TGSConfig(
                listen_host=cfg.get('listen_host', '0.0.0.0'),
                listen_port=cfg.getint('listen_port', 8001),
                tgs_db_path=cfg.get('tgs_db_path', 'tgs_db'),
                tgs_id=cfg.get('tgs_id', 'TGS-001'),
                service_id=cfg.get('service_id', 'CHATSERVER-001'),
                ktgs_ref=cfg.get('ktgs_ref', 'key://ktgs/main'),
                kv_ref=cfg.get('kv_ref', 'key://service/chatserver'),
                ca_host=cfg.get('ca_host', '127.0.0.1'),
                ca_port=cfg.getint('ca_port', 8003),
                tgs_machine_id=cfg.get('tgs_machine_id', 'TGS-HOST-001'),
                identity_store_path=cfg.get('identity_store_path', 'secure/tgs_identity'),
                log_path=cfg.get('log_path', 'logs/tgs.log.txt')
            )
        except Exception as e:
            print(f"Failed to load TGS config: {e}")
            return None

    @staticmethod
    def load_shared_key(key_ref: str) -> Optional[bytes]:
        """加载共享密钥"""
        # 开发阶段使用固定密钥
        temp_keys = {
            "key://ktgs/main": b'\x12\x34\x56\x78\x12\x34\x56\x78',
            "key://service/chatserver": b'\x87\x65\x43\x21\x87\x65\x43\x21',
        }
        return temp_keys.get(key_ref)

        # 正式版本从文件读取
        # if key_ref.startswith('key://'):
        #     key_path = key_ref.replace('key://', 'secure/keys/') + '.keyhex'
        #     try:
        #         with open(key_path, 'r') as f:
        #             return bytes.fromhex(f.read().strip())
        #     except Exception as e:
        #         print(f"Failed to load key {key_ref}: {e}")
        #         return None
        # return None