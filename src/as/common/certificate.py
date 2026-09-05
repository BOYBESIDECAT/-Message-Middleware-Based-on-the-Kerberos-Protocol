#!/usr/bin/env python3
"""
证书模块 - 符合设计文档3.3.4节和3.1.6节要求
定义简化X.509证书结构
"""

import datetime
import json
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from Crypto.PublicKey import RSA


@dataclass
class SimpleX509Certificate:
    """
    简化X.509证书实体 (对齐设计文档3.3.4节)

    字段说明:
    - cert_id: 等于申请方运行主机的 machine_id (对齐3.1.6.1)
    - subject_role: CLIENT/AS/TGS/APP
    - issuer: 固定为 "CA"
    """
    version: str = "X509-SIMPLE-V1"
    cert_id: str = ""  # 等于machine_id
    serial_number: str = ""  # CA分配的证书序列号
    subject_role: str = ""  # CLIENT/AS/TGS/APP
    issuer: str = "CA"  # 固定为CA
    public_key_hex: str = ""  # RSA公钥十六进制字符串
    valid_from: datetime.datetime = field(default_factory=datetime.datetime.now)
    valid_to: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now() + datetime.timedelta(days=365)
    )
    signature_algorithm: str = "SHA-256/RSA2048-NOPADDING"
    ca_signature_hex: str = ""  # CA对证书的签名

    def to_dict(self) -> Dict[str, Any]:
        """
        转换为字典 (用于JSON序列化)
        对齐设计文档3.3.4节的JSON结构
        """
        return {
            "version": self.version,
            "cert_id": self.cert_id,
            "serial_number": self.serial_number,
            "subject_role": self.subject_role,
            "issuer": self.issuer,
            "public_key_hex": self.public_key_hex,
            "valid_from": self.valid_from.isoformat() + "Z",
            "valid_to": self.valid_to.isoformat() + "Z",
            "signature_algorithm": self.signature_algorithm,
            "ca_signature_hex": self.ca_signature_hex
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SimpleX509Certificate':
        """从字典反序列化"""

        def parse_date(date_str: str) -> datetime.datetime:
            if not date_str:
                return datetime.datetime.now()
            date_str = date_str.rstrip('Z')
            return datetime.datetime.fromisoformat(date_str)

        return cls(
            version=data.get("version", "X509-SIMPLE-V1"),
            cert_id=data.get("cert_id", ""),
            serial_number=data.get("serial_number", ""),
            subject_role=data.get("subject_role", ""),
            issuer=data.get("issuer", "CA"),
            public_key_hex=data.get("public_key_hex", ""),
            valid_from=parse_date(data.get("valid_from", "")),
            valid_to=parse_date(data.get("valid_to", "")),
            signature_algorithm=data.get("signature_algorithm", "SHA-256/RSA2048-NOPADDING"),
            ca_signature_hex=data.get("ca_signature_hex", "")
        )

    def to_json(self) -> str:
        """转换为JSON字符串"""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> 'SimpleX509Certificate':
        """从JSON字符串反序列化"""
        return cls.from_dict(json.loads(json_str))

    def get_body_dict(self) -> Dict[str, Any]:
        """
        获取证书主体 (不含CA签名)
        用于CA签名计算
        """
        body = self.to_dict()
        body.pop("ca_signature_hex", None)
        return body

    def get_body_json(self) -> str:
        """获取证书主体JSON字符串 (用于签名)"""
        return json.dumps(self.get_body_dict(), sort_keys=True, separators=(',', ':'))

    def is_valid(self, now: Optional[datetime.datetime] = None) -> bool:
        """
        检查证书是否在有效期内
        对齐设计文档3.1.5.3
        """
        if now is None:
            now = datetime.datetime.now()

        if self.valid_from and now < self.valid_from:
            return False
        if self.valid_to and now > self.valid_to:
            return False
        return True

    def is_expiring_soon(self, days_before: int = 7) -> bool:
        """
        检查证书是否即将过期
        用于提前续期
        """
        now = datetime.datetime.now()
        days_left = (self.valid_to - now).days
        return 0 < days_left <= days_before


class CertificateApplyRequest:
    """
    证书申请请求 (对齐设计文档3.3.5 CERT_APPLY)
    """

    def __init__(self, machine_id: str, subject_role: str, public_key_hex: str):
        self.machine_id = machine_id
        self.subject_role = subject_role
        self.public_key_hex = public_key_hex
        self.ts = datetime.datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "machine_id": self.machine_id,
            "subject_role": self.subject_role,
            "public_key_hex": self.public_key_hex,
            "ts": self.ts
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(',', ':'))


class CertificateRenewRequest:
    """
    证书续期请求 (对齐设计文档3.3.5 CERT_RENEW_REQUEST)
    """

    def __init__(self, cert_id: str, machine_id: str, subject_role: str, public_key_hex: str):
        self.cert_id = cert_id
        self.machine_id = machine_id
        self.subject_role = subject_role
        self.public_key_hex = public_key_hex
        self.ts = datetime.datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cert_id": self.cert_id,
            "machine_id": self.machine_id,
            "subject_role": self.subject_role,
            "public_key_hex": self.public_key_hex,
            "ts": self.ts
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(',', ':'))


class CertificateResponse:
    """
    证书响应 (对齐设计文档3.3.5 CERT_RESPONSE)
    """

    def __init__(self, status: str, certificate: Optional[SimpleX509Certificate] = None,
                 error_code: Optional[str] = None):
        self.status = status  # "issued" 或 "failed"
        self.certificate = certificate
        self.error_code = error_code

    def to_dict(self) -> Dict[str, Any]:
        result = {"status": self.status}
        if self.certificate:
            result["certificate"] = self.certificate.to_dict()
        if self.error_code:
            result["error_code"] = self.error_code
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CertificateResponse':
        cert = None
        if data.get("certificate"):
            cert = SimpleX509Certificate.from_dict(data["certificate"])
        return cls(
            status=data.get("status", "failed"),
            certificate=cert,
            error_code=data.get("error_code")
        )


def verify_peer_certificate(cert: SimpleX509Certificate, ca_public_key: RSA.RsaKey,
                            cert_status: str = "normal",
                            now: Optional[datetime.datetime] = None) -> bool:
    """
    验证对端证书合法性 (对齐设计文档3.1.5.3)

    验证内容:
    1. 证书状态是否为 normal
    2. 证书是否在有效期内
    3. CA签名是否正确

    Args:
        cert: 待验证的证书
        ca_public_key: CA根公钥
        cert_status: 证书状态 (normal/revoked/expired)
        now: 当前时间 (用于测试)

    Returns:
        True: 证书合法, False: 证书非法
    """
    # 1. 检查证书状态
    if cert_status != "normal":
        return False

    # 2. 检查有效期
    if not cert.is_valid(now):
        return False

    # 3. 验证CA签名
    from .crypto import verify_certificate_signature
    return verify_certificate_signature(
        cert.get_body_dict(),
        ca_public_key,
        bytes.fromhex(cert.ca_signature_hex)
    )


def check_certificate_availability(cert: Optional[SimpleX509Certificate],
                                   now: Optional[datetime.datetime] = None) -> str:
    """
    检查证书是否可继续复用 (对齐设计文档3.1.5.3)

    Returns:
        - "valid": 证书有效
        - "need_renew": 证书即将过期需要续期
        - "need_reapply": 证书已过期或无效需要重新申请
    """
    if cert is None:
        return "need_reapply"

    if now is None:
        now = datetime.datetime.now()

    if cert.is_valid(now):
        if cert.is_expiring_soon():
            return "need_renew"
        return "valid"
    else:
        return "need_reapply"