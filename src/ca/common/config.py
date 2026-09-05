import configparser
from dataclasses import dataclass

@dataclass
class CAConfig:
    listen_host: str
    listen_port: int
    ca_db_path: str
    ca_cert_path: str
    ca_private_key_path: str
    serial_counter: int
    issued_cert_store: str
    log_path: str

def LoadCAConfig(config_path: str) -> CAConfig:
    """加载CA服务器配置(对齐3.1.5.3)"""
    config = configparser.ConfigParser()
    config.read(config_path, encoding='utf-8')
    ca_section = config['ca_server.conf']
    
    return CAConfig(
        listen_host=ca_section.get('listen_host', '0.0.0.0'),
        listen_port=ca_section.getint('listen_port', 8003),
        ca_db_path=ca_section.get('ca_db_path', 'data/ca.db'),
        ca_cert_path=ca_section.get('ca_cert_path', 'certs/ca_cert.pem'),
        ca_private_key_path=ca_section.get('ca_private_key_path', 'certs/ca_key.pem'),
        serial_counter=ca_section.getint('serial_counter', 1),
        issued_cert_store=ca_section.get('issued_cert_store', 'data/issued_certs'),
        log_path=ca_section.get('log_path', 'logs/ca.log.txt')
    )