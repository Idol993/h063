import json
import time
from pathlib import Path
from typing import List, Optional, Tuple

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend
import base64

from ssl_manager.utils.logger import logger


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class ACMEClientError(Exception):
    pass


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
        self._jwk_thumbprint: Optional[str] = None

    def initialize(self):
        logger.info(f"初始化 ACME 客户端: {self.directory_url}")
        self._load_directory()
        self._load_or_create_account_key()
        self._compute_jwk_thumbprint()
        self._get_nonce()
        self._create_or_get_account()

    def _load_directory(self):
        try:
            resp = self.session.get(self.directory_url, timeout=30)
            resp.raise_for_status()
            self.directory = resp.json()
            logger.debug("ACME 目录加载成功")
        except Exception as e:
            raise ACMEClientError(f"加载 ACME 目录失败 ({self.directory_url}) 失败: {e}") from e

    def _load_or_create_account_key(self):
        self.account_key_path.parent.mkdir(parents=True, exist_ok=True)

        if self.account_key_path.exists():
            try:
                with open(self.account_key_path, "rb") as f:
                    self.account_key = serialization.load_pem_private_key(
                        f.read(), password=None, backend=default_backend()
                    )
                if not isinstance(self.account_key, rsa.RSAPrivateKey):
                    raise ValueError("账户私钥不是 RSA 密钥")
                logger.info(f"加载账户私钥: {self.account_key_path}")
            except Exception as e:
                logger.warning(f"加载现有账户私钥失败，将重新生成: {e}")
                self.account_key = None

        if self.account_key is None:
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

    def _compute_jwk_thumbprint(self):
        if self.account_key is None:
            raise ACMEClientError("账户私钥未初始化")

        public_numbers = self.account_key.public_key().public_numbers()

        e_bytes = public_numbers.e.to_bytes(
            (public_numbers.e.bit_length() + 7) // 8, "big")
        n_bytes = public_numbers.n.to_bytes(
            (public_numbers.n.bit_length() + 7) // 8, "big")

        jwk = {
            "e": _b64url(e_bytes),
            "kty": "RSA",
            "n": _b64url(n_bytes),
        }
        jwk_json = json.dumps(jwk, separators=(",", ":"), sort_keys=True)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(jwk_json.encode("utf-8"))
        self._jwk_thumbprint = _b64url(digest.finalize())
        logger.debug("JWK thumbprint 计算完成")

    def _get_jwk_dict(self) -> dict:
        if self.account_key is None:
            raise ACMEClientError("账户私钥未初始化")
        public_numbers = self.account_key.public_key().public_numbers()
        e_bytes = public_numbers.e.to_bytes(
            (public_numbers.e.bit_length() + 7) // 8, "big")
        n_bytes = public_numbers.n.to_bytes(
            (public_numbers.n.bit_length() + 7) // 8, "big")
        return {
            "kty": "RSA",
            "e": _b64url(e_bytes),
            "n": _b64url(n_bytes),
        }

    def _get_nonce(self):
        new_nonce_url = self.directory.get("newNonce")
        if not new_nonce_url:
            raise ACMEClientError("ACME 目录中缺少 newNonce 端点")
        try:
            resp = self.session.head(new_nonce_url, timeout=10)
            resp.raise_for_status()
            self._nonce = resp.headers.get("Replay-Nonce")
            logger.debug("获取 nonce 成功")
        except Exception as e:
            raise ACMEClientError(f"获取 nonce 失败: {e}") from e

    def _sign(self, protected: dict, payload: dict) -> dict:
        if self.account_key is None:
            raise ACMEClientError("账户私钥未初始化")
        if not self._nonce:
            raise ACMEClientError("缺少 nonce")

        protected64 = _b64url(json.dumps(protected, separators=(",", ":")).encode())

        if payload is None:
            payload64 = ""
        else:
            payload64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())

        signing_input = f"{protected64}.{payload64}".encode("ascii")

        signature = self.account_key.sign(
            signing_input,
            asym_padding.PKCS1v15(),
            hashes.SHA256(),
        )
        signature64 = _b64url(signature)

        return {
            "protected": protected64,
            "payload": payload64,
            "signature": signature64,
        }

    def _signed_request(self, url: str, payload: dict, use_jwk: bool = False) -> requests.Response:
        protected = {
            "alg": "RS256",
            "nonce": self._nonce,
            "url": url,
        }
        if use_jwk:
            protected["jwk"] = self._get_jwk_dict()
        else:
            if self.kid is None:
                raise ACMEClientError("账户 KID 未设置，请先调用 initialize()")
            protected["kid"] = self.kid

        signed = self._sign(protected, payload)

        headers = {
            "Content-Type": "application/jose+json",
            "Accept": "application/json",
        }

        try:
            resp = self.session.post(url, json=signed, headers=headers, timeout=30)
        except requests.RequestException as e:
            raise ACMEClientError(f"请求 ACME API 失败: {e}") from e

        new_nonce = resp.headers.get("Replay-Nonce")
        if new_nonce:
            self._nonce = new_nonce

        return resp

    def _create_or_get_account(self):
        new_account_url = self.directory.get("newAccount")
        if not new_account_url:
            raise ACMEClientError("ACME 目录中缺少 newAccount 端点")

        payload = {"termsOfServiceAgreed": True}
        if self.email:
            payload["contact"] = [f"mailto:{self.email}"]

        resp = self._signed_request(new_account_url, payload, use_jwk=True)

        if resp.status_code in (200, 201):
            self.kid = resp.headers.get("Location")
            if resp.status_code == 201:
                logger.info(f"创建新账户成功: {self.kid}")
            else:
                logger.info(f"账户已存在: {self.kid}")
        else:
            error_detail = ""
            try:
                error_detail = resp.text
            except Exception:
                pass
            raise ACMEClientError(
                    f"创建/获取账户失败: HTTP {resp.status_code} {error_detail}"
                )

    def new_order(self, domains: List[str]) -> dict:
        logger.info(f"创建新订单: {domains}")
        new_order_url = self.directory.get("newOrder")
        if not new_order_url:
            raise ACMEClientError("ACME 目录中缺少 newOrder 端点")

        identifiers = [{"type": "dns", "value": domain} for domain in domains]
        payload = {"identifiers": identifiers}

        resp = self._signed_request(new_order_url, payload)
        if resp.status_code != 201:
            raise ACMEClientError(
                f"创建订单失败: HTTP {resp.status_code} {resp.text}"
            )

        order = resp.json()
        order["order_url"] = resp.headers.get("Location")
        logger.info(f"订单创建成功: {order['order_url']}")
        return order

    def get_authorization(self, auth_url: str) -> dict:
        resp = self._signed_request(auth_url, None)
        if resp.status_code != 200:
            raise ACMEClientError(
                f"获取授权信息失败: HTTP {resp.status_code} {resp.text}"
            )
        return resp.json()

    def get_dns_challenge(self, auth: dict) -> Tuple[Optional[dict], str, str]:
        """
        返回 (challenge对象, TXT记录的完整域名(不含_acme-challenge前缀), TXT值)

        对于 *.example.com 和 example.com，clean_domain 都是 example.com，
        record_name 始终是 _acme-challenge，拼出来的完整域名为 _acme-challenge.example.com
        """
        identifier = auth["identifier"]["value"]

        for challenge in auth.get("challenges", []):
            if challenge["type"] == "dns-01":
                token = challenge["token"]
                if not token:
                    continue

                key_authorization = f"{token}.{self._jwk_thumbprint}"
                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest.update(key_authorization.encode("utf-8"))
                txt_value = _b64url(digest.finalize())

                if identifier.startswith("*."):
                    clean_domain = identifier[2:]
                else:
                    clean_domain = identifier

                record_name = "_acme-challenge"

                logger.info(
                    f"DNS-01 挑战计算完成: 域名={identifier}, "
                    f"TXT记录={record_name}.{clean_domain}, 值={txt_value}"
                )

                return challenge, clean_domain, txt_value

        return None, "", ""

    def answer_challenge(self, challenge_url: str) -> dict:
        logger.info(f"应答挑战: {challenge_url}")
        resp = self._signed_request(challenge_url, {})
        if resp.status_code != 200:
            raise ACMEClientError(
                f"应答挑战失败: HTTP {resp.status_code} {resp.text}"
            )
        return resp.json()

    def poll_for_status(self, url: str, expected_status: str, timeout: int = 300, interval: int = 5) -> dict:
        logger.info(f"轮询状态: {url}, 期望状态: {expected_status}")
        elapsed = 0

        while elapsed < timeout:
            resp = self._signed_request(url, None)
            if resp.status_code != 200:
                raise ACMEClientError(
                    f"轮询状态失败: HTTP {resp.status_code} {resp.text}"
                )

            data = resp.json()
            status = data.get("status")

            if status == expected_status:
                logger.info(f"状态已更新为: {expected_status}")
                return data
            elif status in ("invalid", "revoked", "deactivated"):
                error_detail = data.get("error")
                raise ACMEClientError(f"验证失败，状态={status}, 详情={error_detail}")

            logger.debug(f"当前状态: {status}, 等待中...")
            time.sleep(interval)
            elapsed += interval

        raise TimeoutError(f"轮询超时 ({timeout}s)，状态未变为 {expected_status}")

    def finalize_order(self, finalize_url: str, csr_pem: bytes) -> dict:
        logger.info("完成订单（提交 CSR）")

        csr = x509.load_pem_x509_csr(csr_pem, default_backend())
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        csr_b64 = _b64url(csr_der)

        payload = {"csr": csr_b64}
        resp = self._signed_request(finalize_url, payload)
        if resp.status_code != 200:
            raise ACMEClientError(
                f"完成订单失败: HTTP {resp.status_code} {resp.text}"
            )
        return resp.json()

    def download_certificate(self, cert_url: str) -> str:
        logger.info(f"下载证书: {cert_url}")
        resp = self._signed_request(cert_url, None)
        if resp.status_code != 200:
            raise ACMEClientError(
                f"下载证书失败: HTTP {resp.status_code} {resp.text}"
            )
        return resp.text
