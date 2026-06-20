from typing import List, Tuple

from ssl_manager.renewer.acme_client import ACMEClient
from ssl_manager.utils.dns_provider import DNSProvider
from ssl_manager.utils.logger import logger


class Challenger:
    def __init__(self, acme_client: ACMEClient, dns_provider: DNSProvider):
        self.acme_client = acme_client
        self.dns_provider = dns_provider

    def perform_dns_challenges(self, order: dict) -> bool:
        auth_urls = order.get("authorizations", [])
        success_count = 0
        total = len(auth_urls)

        for auth_url in auth_urls:
            try:
                logger.info(f"处理授权: {auth_url}")
                auth = self.acme_client.get_authorization(auth_url)
                domain = auth["identifier"]["value"]

                challenge, txt_value = self.acme_client.get_dns_challenge(auth)
                if not challenge:
                    logger.warning(f"域名 {domain} 没有 DNS-01 挑战")
                    continue

                record_name = f"_acme-challenge"
                if domain.startswith("*."):
                    base_domain = domain[2:]
                    clean_domain = base_domain
                else:
                    clean_domain = domain

                logger.info(f"添加 DNS TXT 记录: _acme-challenge.{clean_domain} = {txt_value}")
                added = self.dns_provider.add_txt_record(clean_domain, record_name, txt_value)

                if not added:
                    logger.error(f"添加 DNS 记录失败: {clean_domain}")
                    continue

                try:
                    self.dns_provider.wait_for_propagation(clean_domain, record_name, txt_value)

                    logger.info("应答挑战...")
                    self.acme_client.answer_challenge(challenge["url"])

                    logger.info("等待验证完成...")
                    self.acme_client.poll_for_status(auth_url, "valid")

                    success_count += 1
                    logger.info(f"域名 {domain} 验证成功")

                finally:
                    logger.info(f"清理 DNS TXT 记录: _acme-challenge.{clean_domain}")
                    self.dns_provider.delete_txt_record(clean_domain, record_name)

            except Exception as e:
                logger.error(f"域名验证失败: {e}")

        logger.info(f"DNS 挑战完成: {success_count}/{total} 成功")
        return success_count == total

    def cleanup_all_challenges(self, order: dict):
        auth_urls = order.get("authorizations", [])

        for auth_url in auth_urls:
            try:
                auth = self.acme_client.get_authorization(auth_url)
                domain = auth["identifier"]["value"]
                challenge, _ = self.acme_client.get_dns_challenge(auth)

                if challenge:
                    if domain.startswith("*."):
                        clean_domain = domain[2:]
                    else:
                        clean_domain = domain

                    record_name = "_acme-challenge"
                    self.dns_provider.delete_txt_record(clean_domain, record_name)
            except Exception as e:
                logger.warning(f"清理挑战记录失败: {e}")
