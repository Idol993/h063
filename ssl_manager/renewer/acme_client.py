import json
import os
import time
from pathlib import Path
from typing import List, Optional, Tuple

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64

from ssl_manager.utils.logger import logger


class ACMEClient:
    def __init__(
        self,
        directory_url: str = "https://acme-v02.api.letsencrypt.org/directory",
        email: str = "",
        account_key_path: str = "./data/account.key",
        staging: bool = False,
    ):
        if staging and directory_url == "https://acme-v02.api.letsencrypt.org/directory":
            directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"

        self.directory_url = directory_url
        self.email = email
        self.account_key_path = Path(account_key_path)
        self.account_key: Optional[rsa.RSAPrivateKey] = None
        self.kid: Optional[str] = None
        self.directory: dict = {}
        self.session = requests.Session()
        self._nonce: Optional[str] = None

    def _b64url(self, data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def _b64url_to_int(self, data: str) -> int:
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return int.from_bytes(base64.urlsafe_b64decode(data), "big")

    def initialize(self):
        logger.info(f"初始化 ACME 客户端: {self.directory_url}")
        self._load_directory()
        self._load_or_create_account_key()
        self._get_nonce()
        self._create_or_get_account()

    def _load_directory(self):
        resp = self.session.get(self.directory_url)
        resp.raise_for_status()
        self.directory = resp.json()
        logger.debug("ACME 目录加载成功")

    def _load_or_create_account_key(self):
        if self.account_key_path.exists():
            with open(self.account_key_path, "rb") as f:
                self.account_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            logger.info(f"加载账户私钥: {self.account_key_path}")
        else:
            self.account_key_path.parent.mkdir(parents=True, exist_ok=True)
            self.account_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend(),
            )
            with open(self.account_key_path, "wb") as f:
                f.write(
                    self.account_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )
            logger.info(f"生成新账户私钥: {self.account_key_path}")

    def _get_nonce(self):
        new_nonce_url = self.directory["newNonce"]
        resp = self.session.head(new_nonce_url)
        resp.raise_for_status()
        self._nonce = resp.headers.get("Replay-Nonce")
        logger.debug("获取 nonce 成功")

    def _signed_jwk(self, payload: dict) -> dict:
        if not self.account_key:
            raise ValueError("账户密钥未初始化")

        public_numbers = self.account_key.public_key().public_numbers()
        jwk = {
            "kty": "RSA",
            "e": self._b64url(public_numbers.e.to_bytes(3, "big")),
            "n": self._b64url(public_numbers.n.to_bytes(256, "big")),
        }

        protected = {
            "alg": "RS256",
            "jwk": jwk,
            "nonce": self._nonce,
            "url": "",
        }

        return self._sign(protected, payload, jwk)

    def _signed_kid(self, payload: dict, url: str) -> dict:
        if not self.kid:
            raise ValueError("账户 KID 未设置")

        protected = {
            "alg": "RS256",
            "kid": self.kid,
            "nonce": self._nonce,
            "url": url,
        }

        return self._sign(protected, payload, None)

    def _sign(self, protected: dict, payload: dict, jwk: Optional[dict]) -> dict:
        from cryptography.hazmat.primitives.asymmetric import padding

        protected64 = self._b64url(json.dumps(protected, separators=(",", ":")).encode())

        if payload == {}:
            payload64 = ""
        else:
            payload64 = self._b64url(json.dumps(payload, separators=(",", ":")).encode())

        signing_input = f"{protected64}.{payload64}".encode()

        signature = self.account_key.sign(
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

        signature64 = self._b64url(signature)

        return {
            "protected": protected64,
            "payload": payload64,
            "signature": signature64,
        }

    def _create_or_get_account(self):
        new_account_url = self.directory["newAccount"]

        payload = {
            "termsOfServiceAgreed": True,
        }
        if self.email:
            payload["contact"] = [f"mailto:{self.email}"]

        signed = self._signed_jwk(payload)
        signed["protected"] = json.loads(base64.urlsafe_b64decode(signed["protected"] + "==").decode()) if False else signed["protected"]

        protected_dict = json.loads(
            base64.urlsafe_b64decode(
                signed["protected"] + "=" * (-len(signed["protected"]) % 4)
            ).decode()
        )
        protected_dict["url"] = new_account_url
        protected_encoded = self._b64url(
            json.dumps(protected_dict, separators=(",", ":")).encode()
        )
        signed["protected"] = protected_encoded

        resp = self.session.post(new_account_url, json=signed)
        if resp.status_code == 201:
            self.kid = resp.headers.get("Location")
            logger.info(f"创建新账户成功: {self.kid}")
        elif resp.status_code == 200:
            self.kid = resp.headers.get("Location")
            logger.info(f"账户已存在: {self.kid}")
        else:
            raise ValueError(f"创建账户失败: {resp.status_code} {resp.text}")

        self._nonce = resp.headers.get("Replay-Nonce")

    def new_order(self, domains: List[str]) -> dict:
        logger.info(f"创建新订单: {domains}")
        new_order_url = self.directory["newOrder"]

        identifiers = [{"type": "dns", "value": domain} for domain in domains]
        payload = {"identifiers": identifiers}

        protected_dict = {
            "alg": "RS256",
            "kid": self.kid,
            "nonce": self._nonce,
            "url": new_order_url,
        }
        protected64 = self._b64url(json.dumps(protected_dict, separators=(",", ":")).encode())
        payload64 = self._b64url(json.dumps(payload, separators=(",", ":")).encode())

        signing_input = f"{protected64}.{payload64}".encode()
        from cryptography.hazmat.primitives.asymmetric import padding
        signature = self.account_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        signature64 = self._b64url(signature)

        signed = {
            "protected": protected64,
            "payload": payload64,
            "signature": signature64,
        }

        resp = self.session.post(new_order_url, json=signed)
        resp.raise_for_status()
        self._nonce = resp.headers.get("Replay-Nonce")

        order = resp.json()
        order["order_url"] = resp.headers.get("Location")
        logger.info(f"订单创建成功: {order['order_url']}")
        return order

    def get_authorization(self, auth_url: str) -> dict:
        protected_dict = {
            "alg": "RS256",
            "kid": self.kid,
            "nonce": self._nonce,
            "url": auth_url,
        }
        protected64 = self._b64url(json.dumps(protected_dict, separators=(",", ":")).encode())
        payload64 = ""

        signing_input = f"{protected64}.{payload64}".encode()
        from cryptography.hazmat.primitives.asymmetric import padding
        signature = self.account_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        signature64 = self._b64url(signature)

        signed = {
            "protected": protected64,
            "payload": payload64,
            "signature": signature64,
        }

        resp = self.session.post(auth_url, json=signed)
        resp.raise_for_status()
        self._nonce = resp.headers.get("Replay-Nonce")
        return resp.json()

    def get_dns_challenge(self, auth: dict) -> Tuple[Optional[dict], str]:
        for challenge in auth.get("challenges", []):
            if challenge["type"] == "dns-01":
                identifier = auth["identifier"]["value"]

                public_numbers = self.account_key.public_key().public_numbers()
                jwk = {
                    "kty": "RSA",
                    "e": self._b64url(public_numbers.e.to_bytes(3, "big")),
                    "n": self._b64url(public_numbers.n.to_bytes(256, "big")),
                }
                jwk_json = json.dumps(jwk, separators=(",", ":"), sort_keys=True)
                thumbprint = self._b64url(hashes.Hash(hashes.SHA256()).update(jwk_json.encode()).finalize())

                token = challenge["token"]
                key_authorization = f"{token}.{thumbprint}"
                txt_value = self._b64url(
                    hashes.Hash(hashes.SHA256()).update(key_authorization.encode()).finalize()
                )

                return challenge, txt_value

        return None, ""

    def answer_challenge(self, challenge_url: str) -> dict:
        logger.info(f"应答挑战: {challenge_url}")

        protected_dict = {
            "alg": "RS256",
            "kid": self.kid,
            "nonce": self._nonce,
            "url": challenge_url,
        }
        protected64 = self._b64url(json.dumps(protected_dict, separators=(",", ":")).encode())
        payload64 = self._b64url("{}".encode())

        signing_input = f"{protected64}.{payload64}".encode()
        from cryptography.hazmat.primitives.asymmetric import padding
        signature = self.account_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        signature64 = self._b64url(signature)

        signed = {
            "protected": protected64,
            "payload": payload64,
            "signature": signature64,
        }

        resp = self.session.post(challenge_url, json=signed)
        resp.raise_for_status()
        self._nonce = resp.headers.get("Replay-Nonce")
        return resp.json()

    def poll_for_status(self, url: str, expected_status: str, timeout: int = 300, interval: int = 5) -> dict:
        logger.info(f"轮询状态: {url}, 期望状态: {expected_status}")
        elapsed = 0

        while elapsed < timeout:
            protected_dict = {
                "alg": "RS256",
                "kid": self.kid,
                "nonce": self._nonce,
                "url": url,
            }
            protected64 = self._b64url(json.dumps(protected_dict, separators=(",", ":")).encode())
            payload64 = ""

            signing_input = f"{protected64}.{payload64}".encode()
            from cryptography.hazmat.primitives.asymmetric import padding
            signature = self.account_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
            signature64 = self._b64url(signature)

            signed = {
                "protected": protected64,
                "payload": payload64,
                "signature": signature64,
            }

            resp = self.session.post(url, json=signed)
            resp.raise_for_status()
            self._nonce = resp.headers.get("Replay-Nonce")

            data = resp.json()
            status = data.get("status")

            if status == expected_status:
                logger.info(f"状态已更新为: {expected_status}")
                return data
            elif status in ("invalid", "revoked", "deactivated"):
                raise ValueError(f"验证失败: {status}, 详情: {data.get('error')}")

            logger.debug(f"当前状态: {status}, 等待中...")
            time.sleep(interval)
            elapsed += interval

        raise TimeoutError(f"轮询超时 ({timeout}s)，状态未变为 {expected_status}")

    def finalize_order(self, finalize_url: str, csr_pem: bytes) -> dict:
        logger.info("完成订单（提交 CSR）")

        csr = x509.load_pem_x509_csr(csr_pem, default_backend())
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        csr_b64 = self._b64url(csr_der)

        payload = {"csr": csr_b64}

        protected_dict = {
            "alg": "RS256",
            "kid": self.kid,
            "nonce": self._nonce,
            "url": finalize_url,
        }
        protected64 = self._b64url(json.dumps(protected_dict, separators=(",", ":")).encode())
        payload64 = self._b64url(json.dumps(payload, separators=(",", ":")).encode())

        signing_input = f"{protected64}.{payload64}".encode()
        from cryptography.hazmat.primitives.asymmetric import padding
        signature = self.account_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        signature64 = self._b64url(signature)

        signed = {
            "protected": protected64,
            "payload": payload64,
            "signature": signature64,
        }

        resp = self.session.post(finalize_url, json=signed)
        resp.raise_for_status()
        self._nonce = resp.headers.get("Replay-Nonce")
        return resp.json()

    def download_certificate(self, cert_url: str) -> str:
        logger.info(f"下载证书: {cert_url}")

        protected_dict = {
            "alg": "RS256",
            "kid": self.kid,
            "nonce": self._nonce,
            "url": cert_url,
        }
        protected64 = self._b64url(json.dumps(protected_dict, separators=(",", ":")).encode())
        payload64 = ""

        signing_input = f"{protected64}.{payload64}".encode()
        from cryptography.hazmat.primitives.asymmetric import padding
        signature = self.account_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        signature64 = self._b64url(signature)

        signed = {
            "protected": protected64,
            "payload": payload64,
            "signature": signature64,
        }

        resp = self.session.post(cert_url, json=signed)
        resp.raise_for_status()
        self._nonce = resp.headers.get("Replay-Nonce")
        return resp.text
