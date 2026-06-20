import os
from pathlib import Path
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from ssl_manager.utils.logger import logger


class CertificateSaver:
    def __init__(self, output_dir: str = "./certs"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_csr(self, domains: list, key_path: str = None) -> Tuple[bytes, bytes]:
        logger.info(f"生成 CSR: {domains}")

        if key_path and Path(key_path).exists():
            with open(key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            logger.info(f"使用现有私钥: {key_path}")
        else:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend(),
            )

        primary_domain = domains[0]
        san_list = [x509.DNSName(domain) for domain in domains]

        builder = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, primary_domain),
                    ]
                )
            )
            .add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )
        )

        csr = builder.sign(private_key, hashes.SHA256(), default_backend())

        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return csr_pem, key_pem

    def save_certificate(self, domain: str, cert_pem: str, key_pem: bytes, chain_pem: str = "") -> dict:
        logger.info(f"保存证书到: {self.output_dir / domain}")

        cert_dir = self.output_dir / domain
        cert_dir.mkdir(parents=True, exist_ok=True)

        cert_path = cert_dir / "cert.pem"
        key_path = cert_dir / "privkey.pem"
        chain_path = cert_dir / "chain.pem"
        fullchain_path = cert_dir / "fullchain.pem"

        with open(cert_path, "w") as f:
            f.write(cert_pem)

        with open(key_path, "wb") as f:
            f.write(key_pem)
        os.chmod(key_path, 0o600)

        if chain_pem:
            with open(chain_path, "w") as f:
                f.write(chain_pem)

        fullchain = cert_pem + chain_pem if chain_pem else cert_pem
        with open(fullchain_path, "w") as f:
            f.write(fullchain)

        logger.info(f"证书保存完成: {cert_path}")

        return {
            "domain": domain,
            "cert_path": str(cert_path),
            "key_path": str(key_path),
            "chain_path": str(chain_path) if chain_pem else "",
            "fullchain_path": str(fullchain_path),
        }

    def parse_certificate_chain(self, fullchain_pem: str) -> dict:
        certs = []
        current_cert = []

        for line in fullchain_pem.splitlines():
            current_cert.append(line)
            if line.strip() == "-----END CERTIFICATE-----":
                certs.append("\n".join(current_cert) + "\n")
                current_cert = []

        if not certs:
            return {"cert": fullchain_pem, "chain": ""}

        leaf_cert = certs[0]
        chain_certs = "\n".join(certs[1:]) if len(certs) > 1 else ""

        return {
            "cert": leaf_cert,
            "chain": chain_certs,
        }

    def load_existing_key(self, domain: str) -> bytes:
        key_path = self.output_dir / domain / "privkey.pem"
        if key_path.exists():
            with open(key_path, "rb") as f:
                return f.read()
        return b""
