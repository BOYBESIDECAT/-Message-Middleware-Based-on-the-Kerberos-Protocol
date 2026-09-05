import sqlite3
import datetime
from typing import Optional, List
from .certificate import SimpleX509Certificate

class CADatabase:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        """初始化CA数据库表(对齐3.2.5)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS certificate_record (
                cert_id VARCHAR(64) PRIMARY KEY NOT NULL,
                machine_id VARCHAR(64) NOT NULL,
                subject_role VARCHAR(16) NOT NULL,
                subject_public_key TEXT NOT NULL,
                serial_number VARCHAR(64) UNIQUE NOT NULL,
                valid_from DATETIME NOT NULL,
                valid_to DATETIME NOT NULL,
                status VARCHAR(16) NOT NULL DEFAULT 'normal',
                ca_signature TEXT NOT NULL,
                revoke_time DATETIME
            )
        ''')
        conn.commit()
        conn.close()

    def query_certificate_record(self, cert_id: str) -> Optional[dict]:
        """查询证书记录(对齐3.1.6.2)"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM certificate_record WHERE cert_id = ?', (cert_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def persist_certificate(self, cert: SimpleX509Certificate, status: str = "normal") -> bool:
        """保存或更新证书记录(对齐3.1.6.2)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO certificate_record 
                (cert_id, machine_id, subject_role, subject_public_key, serial_number, 
                 valid_from, valid_to, status, ca_signature)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cert.cert_id,
                cert.cert_id,  # machine_id等于cert_id
                cert.subject_role,
                cert.public_key_hex,
                cert.serial_number,
                cert.valid_from.isoformat(),
                cert.valid_to.isoformat(),
                status,
                cert.ca_signature_hex
            ))
            conn.commit()
            return True
        except sqlite3.Error:
            conn.rollback()
            return False
        finally:
            conn.close()

    def update_certificate_status(self, cert_id: str, status: str, revoke_time: Optional[datetime.datetime] = None) -> bool:
        """更新证书状态(用于吊销)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            if revoke_time:
                cursor.execute('''
                    UPDATE certificate_record 
                    SET status = ?, revoke_time = ? 
                    WHERE cert_id = ?
                ''', (status, revoke_time.isoformat(), cert_id))
            else:
                cursor.execute('''
                    UPDATE certificate_record 
                    SET status = ? 
                    WHERE cert_id = ?
                ''', (status, cert_id))
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error:
            conn.rollback()
            return False
        finally:
            conn.close()

    def get_next_serial_number(self, current_counter: int) -> int:
        """获取下一个证书序列号"""
        return current_counter + 1
    
    def get_certificate(self, cert_id: str) -> Optional[SimpleX509Certificate]:
        """从数据库获取证书并转换为SimpleX509Certificate对象"""
        record = self.query_certificate_record(cert_id)
        if not record:
            return None
        
        from .certificate import SimpleX509Certificate
        return SimpleX509Certificate(
            version="X509-SIMPLE-V1",
            cert_id=record["cert_id"],
            serial_number=record["serial_number"],
            subject_role=record["subject_role"],
            issuer="CA",
            public_key_hex=record["subject_public_key"],
            valid_from=datetime.datetime.fromisoformat(record["valid_from"]),
            valid_to=datetime.datetime.fromisoformat(record["valid_to"]),
            signature_algorithm="SHA-256/RSA2048-NOPADDING",
            ca_signature_hex=record["ca_signature"]
        )