import datetime
from dataclasses import dataclass
from typing import Optional
from Crypto.PublicKey import RSA
from .crypto import CanonicalJson, VerifyCertificateSignature

@dataclass
class SimpleX509Certificate:
    """简化X.509证书实体(对齐3.3.4)"""
    version: str = "X509-SIMPLE-V1"
    cert_id: str = ""  # 等于machine_id(对齐3.1.6.1)
    serial_number: str = ""
    subject_role: str = ""  # CLIENT/AS/TGS/APP
    issuer: str = "CA"
    public_key_hex: str = ""
    valid_from: datetime.datetime = datetime.datetime.utcnow()
    valid_to: datetime.datetime = datetime.datetime.utcnow() + datetime.timedelta(days=365)
    signature_algorithm: str = "SHA-256/RSA2048-NOPADDING"
    ca_signature_hex: str = ""

    def to_dict(self) -> dict:
        """转换为字典(用于序列化)"""
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
    def from_dict(cls, data: dict) -> 'SimpleX509Certificate':
        """从字典反序列化"""
        return cls(
            version=data["version"],
            cert_id=data["cert_id"],
            serial_number=data["serial_number"],
            subject_role=data["subject_role"],
            issuer=data["issuer"],
            public_key_hex=data["public_key_hex"],
            valid_from=datetime.datetime.fromisoformat(data["valid_from"].rstrip("Z")),
            valid_to=datetime.datetime.fromisoformat(data["valid_to"].rstrip("Z")),
            signature_algorithm=data["signature_algorithm"],
            ca_signature_hex=data["ca_signature_hex"]
        )

    def get_body_dict(self) -> dict:
        """获取证书主体(不含CA签名)"""
        body = self.to_dict()
        del body["ca_signature_hex"]
        return body

    def is_valid(self, ca_public_key: RSA.RsaKey, now: Optional[datetime.datetime] = None) -> bool:
        """验证证书有效性(签名+有效期)"""
        if now is None:
            now = datetime.datetime.utcnow()
        if not (self.valid_from <= now <= self.valid_to):
            return False
        ca_signature = bytes.fromhex(self.ca_signature_hex)
        return VerifyCertificateSignature(self.get_body_dict(), ca_public_key, ca_signature)

def VerifyPeerCertificate(cert: SimpleX509Certificate, ca_public_key: RSA.RsaKey, 
                          cert_status: str = "normal", now: Optional[datetime.datetime] = None) -> bool:
    """验证对端证书合法性(对齐3.1.5.3)"""
    if cert_status != "normal":
        return False
    return cert.is_valid(ca_public_key, now)