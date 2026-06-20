from datetime import datetime
from typing import List, Optional

from OpenSSL import crypto


class CertificateInfo:
    def __init__(self):
        self.cn: str = ""
        self.san: List[str] = []
        self.issuer: str = ""
        self.not_before: Optional[datetime] = None
        self.not_after: Optional[datetime] = None
        self.serial_number: str = ""
        self.version: int = 0
        self.signature_algorithm: str = ""
        self.public_key_type: str = ""
        self.public_key_bits: int = 0

    @property
    def days_remaining(self) -> Optional[int]:
        if not self.not_after:
            return None
        delta = self.not_after - datetime.now()
        return delta.days

    @property
    def is_expired(self) -> bool:
        if not self.not_after:
            return True
        return datetime.now() > self.not_after


class CertificateParser:
    def __init__(self):
        pass

    def parse_der(self, der_data: bytes) -> CertificateInfo:
        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der_data)
        return self._parse_cert(cert)

    def parse_pem(self, pem_data: str) -> CertificateInfo:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_data)
        return self._parse_cert(cert)

    def _parse_cert(self, cert: crypto.X509) -> CertificateInfo:
        info = CertificateInfo()

        info.cn = self._get_cn(cert.get_subject())
        info.san = self._get_san(cert)
        info.issuer = self._get_issuer_str(cert.get_issuer())

        not_before = cert.get_notBefore()
        if not_before:
            info.not_before = datetime.strptime(not_before.decode(), "%Y%m%d%H%M%SZ")

        not_after = cert.get_notAfter()
        if not_after:
            info.not_after = datetime.strptime(not_after.decode(), "%Y%m%d%H%M%SZ")

        info.serial_number = str(cert.get_serial_number())
        info.version = cert.get_version()

        info.signature_algorithm = cert.get_signature_algorithm().decode() if cert.get_signature_algorithm() else ""

        pubkey = cert.get_pubkey()
        info.public_key_bits = pubkey.bits()
        key_type = pubkey.type()
        info.public_key_type = self._key_type_to_str(key_type)

        return info

    def _get_cn(self, subject: crypto.X509Name) -> str:
        cn = subject.CN
        return cn if cn else ""

    def _get_san(self, cert: crypto.X509) -> List[str]:
        san_list = []
        try:
            ext_count = cert.get_extension_count()
            for i in range(ext_count):
                ext = cert.get_extension(i)
                if ext.get_short_name() == b"subjectAltName":
                    san_str = str(ext)
                    for entry in san_str.split(","):
                        entry = entry.strip()
                        if entry.startswith("DNS:"):
                            san_list.append(entry[4:].strip())
        except Exception:
            pass
        return san_list

    def _get_issuer_str(self, issuer: crypto.X509Name) -> str:
        components = []
        for key, value in issuer.get_components():
            if isinstance(key, bytes):
                key = key.decode()
            if isinstance(value, bytes):
                value = value.decode()
            components.append(f"{key}={value}")
        return ", ".join(components)

    def _key_type_to_str(self, key_type: int) -> str:
        type_map = {
            crypto.TYPE_RSA: "RSA",
            crypto.TYPE_DSA: "DSA",
            crypto.TYPE_EC: "EC",
        }
        return type_map.get(key_type, f"Unknown({key_type})")

    def parse_file(self, file_path: str) -> CertificateInfo:
        with open(file_path, "rb") as f:
            data = f.read()

        try:
            return self.parse_pem(data.decode())
        except Exception:
            pass

        try:
            return self.parse_der(data)
        except Exception:
            raise ValueError("无法解析证书文件，既不是 PEM 也不是 DER 格式")
