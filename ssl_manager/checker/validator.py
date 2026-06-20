from enum import Enum
from typing import Optional

from ssl_manager.checker.parser import CertificateInfo


class CertStatus(Enum):
    VALID = "valid"
    WARNING = "warning"
    CRITICAL = "critical"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


class CertificateValidator:
    def __init__(self, warning_days: int = 30, critical_days: int = 7):
        self.warning_days = warning_days
        self.critical_days = critical_days

    def validate(self, cert_info: CertificateInfo) -> CertStatus:
        if not cert_info.not_after:
            return CertStatus.UNKNOWN

        if cert_info.is_expired:
            return CertStatus.EXPIRED

        days = cert_info.days_remaining

        if days is None:
            return CertStatus.UNKNOWN

        if days < 0:
            return CertStatus.EXPIRED
        elif days < self.critical_days:
            return CertStatus.CRITICAL
        elif days < self.warning_days:
            return CertStatus.WARNING
        else:
            return CertStatus.VALID

    def get_status_color(self, status: CertStatus) -> str:
        color_map = {
            CertStatus.VALID: "green",
            CertStatus.WARNING: "yellow",
            CertStatus.CRITICAL: "red",
            CertStatus.EXPIRED: "magenta",
            CertStatus.UNKNOWN: "grey",
        }
        return color_map.get(status, "white")

    def get_status_label(self, status: CertStatus) -> str:
        label_map = {
            CertStatus.VALID: "正常",
            CertStatus.WARNING: "警告",
            CertStatus.CRITICAL: "紧急",
            CertStatus.EXPIRED: "已过期",
            CertStatus.UNKNOWN: "未知",
        }
        return label_map.get(status, "未知")

    def check_trusted_issuer(self, cert_info: CertificateInfo, trusted_issuers: Optional[list] = None) -> bool:
        if trusted_issuers is None:
            trusted_issuers = [
                "Let's Encrypt",
                "ZeroSSL",
                "DigiCert",
                "Sectigo",
                "GlobalSign",
                "GeoTrust",
                "Thawte",
            ]

        issuer_lower = cert_info.issuer.lower()
        for trusted in trusted_issuers:
            if trusted.lower() in issuer_lower:
                return True
        return False

    def check_domain_match(self, cert_info: CertificateInfo, domain: str) -> bool:
        if not cert_info.cn and not cert_info.san:
            return False

        if self._match_domain(domain, cert_info.cn):
            return True

        for san in cert_info.san:
            if self._match_domain(domain, san):
                return True

        return False

    def _match_domain(self, domain: str, pattern: str) -> bool:
        domain = domain.lower()
        pattern = pattern.lower()

        if pattern == domain:
            return True

        if pattern.startswith("*."):
            suffix = pattern[1:]
            return domain.endswith(suffix) and domain.count(".") == pattern.count(".")

        return False
