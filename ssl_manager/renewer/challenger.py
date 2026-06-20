from typing import List, Tuple

from ssl_manager.renewer.acme_client import ACMEClient, ACMEClientError
from ssl_manager.utils.dns_provider import DNSProvider, DNSProviderError
from ssl_manager.utils.logger import logger


class ChallengerError(Exception):
    def __init__(self, message: str, provider_name: str = "", record: str = "", reason: str = ""):
        super().__init__(message)
        self.provider_name = provider_name
        self.record = record
        self.reason = reason


class Challenger:
    RECORD_NAME = "_acme-challenge"

    def __init__(self, acme_client: ACMEClient, dns_provider: DNSProvider):
        self.acme_client = acme_client
        self.dns_provider = dns_provider

    def _get_provider_name(self) -> str:
        cls = type(self.dns_provider)
        name_map = {
            "AliyunDNSProvider": "阿里云",
            "TencentDNSProvider": "腾讯云",
            "CloudflareDNSProvider": "Cloudflare",
        }
        return name_map.get(cls.__name__, cls.__name__)

    def perform_dns_challenges(self, order: dict) -> bool:
        auth_urls = order.get("authorizations", [])
        success_count = 0
        total = len(auth_urls)
        cleanup_stack: List[Tuple[str, str]] = []
        errors: List[str] = []

        for auth_url in auth_urls:
            identifier = ""
            try:
                logger.info(f"处理授权: {auth_url}")
                auth = self.acme_client.get_authorization(auth_url)
                identifier = auth["identifier"]["value"]

                challenge, clean_domain, txt_value = self.acme_client.get_dns_challenge(auth)
                if not challenge:
                    logger.warning(f"域名 {identifier} 没有 DNS-01 挑战，跳过")
                    continue

                full_record = f"{self.RECORD_NAME}.{clean_domain}"
                provider_name = self._get_provider_name()
                logger.info(
                    f"[{provider_name}] 添加 DNS TXT 记录: {full_record} = {txt_value}"
                )

                try:
                    added = self.dns_provider.add_txt_record(
                        clean_domain, self.RECORD_NAME, txt_value
                    )
                    if not added:
                        msg = f"[{provider_name}] 添加 DNS TXT 记录返回失败: {full_record}"
                        logger.error(msg)
                        errors.append(msg)
                        continue
                except DNSProviderError as e:
                    msg = f"[{provider_name}] 添加 DNS TXT 记录失败: {full_record}, 原因: {e}"
                    logger.error(msg)
                    errors.append(msg)
                    continue

                cleanup_stack.append((clean_domain, self.RECORD_NAME))

                try:
                    propagated = self.dns_provider.wait_for_propagation(
                        clean_domain, self.RECORD_NAME, txt_value
                    )
                    if not propagated:
                        logger.warning(
                            f"DNS 记录未检测到传播，但将继续尝试应答 (ACME 可能自行 DNS 已能查到)"
                        )

                    logger.info("应答挑战...")
                    self.acme_client.answer_challenge(challenge["url"])

                    logger.info("等待验证完成...")
                    self.acme_client.poll_for_status(auth_url, "valid")

                    success_count += 1
                    logger.info(f"域名 {identifier} 验证成功")

                except ACMEClientError as e:
                    msg = f"域名 {identifier} ACME 验证失败: {e}"
                    logger.error(msg)
                    errors.append(msg)

            except ACMEClientError as e:
                msg = f"域名 {identifier} ACME 错误: {e}"
                logger.error(msg)
                errors.append(msg)
            except DNSProviderError as e:
                provider_name = self._get_provider_name()
                msg = f"[{provider_name}] DNS 操作失败 (域名 {identifier}): {e}"
                logger.error(msg)
                errors.append(msg)
            except Exception as e:
                msg = f"域名 {identifier} 验证出现未知错误: {e}"
                logger.error(msg)
                errors.append(msg)

        for clean_domain, record_name in reversed(cleanup_stack):
            try:
                logger.info(f"清理 DNS TXT 记录: {record_name}.{clean_domain}")
                self.dns_provider.delete_txt_record(clean_domain, record_name)
            except Exception as e:
                logger.warning(f"清理 DNS 记录失败 {record_name}.{clean_domain}: {e}")

        logger.info(f"DNS 挑战完成: {success_count}/{total} 成功")

        if errors:
            logger.error(f"DNS-01 验证失败详情:")
            for err in errors:
                logger.error(f"  - {err}")

        return success_count == total

    def cleanup_all_challenges(self, order: dict):
        auth_urls = order.get("authorizations", [])

        for auth_url in auth_urls:
            try:
                auth = self.acme_client.get_authorization(auth_url)
                identifier = auth["identifier"]["value"]
                challenge, clean_domain, _ = self.acme_client.get_dns_challenge(auth)

                if challenge and clean_domain:
                    logger.info(f"清理 DNS TXT 记录: {self.RECORD_NAME}.{clean_domain}")
                    self.dns_provider.delete_txt_record(clean_domain, self.RECORD_NAME)
            except Exception as e:
                logger.warning(f"清理挑战记录失败: {e}")
