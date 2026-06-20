from typing import List

from ssl_manager.renewer.acme_client import ACMEClient, ACMEClientError
from ssl_manager.utils.dns_provider import DNSProvider, DNSProviderError
from ssl_manager.utils.logger import logger


class ChallengerError(Exception):
    pass


class Challenger:
    RECORD_NAME = "_acme-challenge"

    def __init__(self, acme_client: ACMEClient, dns_provider: DNSProvider):
        self.acme_client = acme_client
        self.dns_provider = dns_provider

    def perform_dns_challenges(self, order: dict) -> bool:
        auth_urls = order.get("authorizations", [])
        success_count = 0
        total = len(auth_urls)
        cleanup_stack: List[tuple] = []

        for auth_url in auth_urls:
            try:
                logger.info(f"处理授权: {auth_url}")
                auth = self.acme_client.get_authorization(auth_url)
                identifier = auth["identifier"]["value"]

                challenge, clean_domain, txt_value = self.acme_client.get_dns_challenge(auth)
                if not challenge:
                    logger.warning(f"域名 {identifier} 没有 DNS-01 挑战，跳过")
                    continue

                full_record = f"{self.RECORD_NAME}.{clean_domain}"
                logger.info(
                    f"添加 DNS TXT 记录: {full_record} = {txt_value}"
                )

                added = self.dns_provider.add_txt_record(
                    clean_domain, self.RECORD_NAME, txt_value
                )
                if not added:
                    logger.error(f"添加 DNS 记录失败: {full_record}")
                    continue

                cleanup_stack.append((clean_domain, self.RECORD_NAME))

                try:
                    propagated = self.dns_provider.wait_for_propagation(
                        clean_domain, self.RECORD_NAME, txt_value
                    )
                    if not propagated:
                        logger.warning(
                            f"DNS 记录未检测到传播，但将继续尝试应答 (ACME 可能自行 DNS 已能查到")

                    logger.info("应答挑战...")
                    self.acme_client.answer_challenge(challenge["url"])

                    logger.info("等待验证完成...")
                    self.acme_client.poll_for_status(auth_url, "valid")

                    success_count += 1
                    logger.info(f"域名 {identifier} 验证成功")

                finally:
                    pass

            except ACMEClientError as e:
                logger.error(f"域名 {identifier} ACME 验证失败: {e}")
            except DNSProviderError as e:
                logger.error(f"域名 {identifier} DNS 操作失败: {e}")
            except Exception as e:
                logger.error(f"域名 {identifier} 验证出现未知错误: {e}")

        for clean_domain, record_name in reversed(cleanup_stack):
            try:
                logger.info(f"清理 DNS TXT 记录: {record_name}.{clean_domain}")
                self.dns_provider.delete_txt_record(clean_domain, record_name)
            except Exception as e:
                logger.warning(f"清理 DNS 记录失败 {record_name}.{clean_domain}: {e}")

        logger.info(f"DNS 挑战完成: {success_count}/{total} 成功")
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
                logger.warning(f"清理 {identifier} 挑战记录失败: {e}")
