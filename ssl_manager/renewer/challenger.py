from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from ssl_manager.renewer.acme_client import ACMEClient, ACMEClientError
from ssl_manager.utils.dns_provider import DNSProvider, DNSProviderError
from ssl_manager.utils.logger import logger


class ChallengerError(Exception):
    def __init__(self, message: str, provider_name: str = "", record: str = "", reason: str = ""):
        super().__init__(message)
        self.provider_name = provider_name
        self.record = record
        self.reason = reason


@dataclass
class DnsChallengeError:
    """DNS-01 挑战失败的结构化信息"""
    identifier: str = ""
    provider_name: str = ""
    record_name: str = ""
    txt_value: str = ""
    error_type: str = ""
    error_detail: str = ""

    def format(self) -> str:
        lines = [f"  域名: {self.identifier}"]
        if self.provider_name:
            lines.append(f"  DNS 服务商: {self.provider_name}")
        if self.record_name:
            lines.append(f"  TXT 记录: {self.record_name}")
        if self.txt_value:
            lines.append(f"  TXT 值: {self.txt_value}")
        if self.error_type:
            lines.append(f"  失败类型: {self.error_type}")
        if self.error_detail:
            lines.append(f"  失败原因: {self.error_detail}")
        return "\n".join(lines)


@dataclass
class ChallengerResult:
    """perform_dns_challenges 返回的结构化结果"""
    success: bool
    success_count: int
    total_count: int
    errors: List[DnsChallengeError] = field(default_factory=list)


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

    def perform_dns_challenges(self, order: dict) -> ChallengerResult:
        auth_urls = order.get("authorizations", [])
        success_count = 0
        total = len(auth_urls)
        cleanup_stack: List[Tuple[str, str]] = []
        errors: List[DnsChallengeError] = []
        provider_name = self._get_provider_name()

        for auth_url in auth_urls:
            identifier = ""
            current_err = DnsChallengeError(provider_name=provider_name)
            try:
                logger.info(f"处理授权: {auth_url}")
                auth = self.acme_client.get_authorization(auth_url)
                identifier = auth["identifier"]["value"]
                current_err.identifier = identifier

                challenge, clean_domain, txt_value = self.acme_client.get_dns_challenge(auth)
                if not challenge:
                    logger.warning(f"域名 {identifier} 没有 DNS-01 挑战，跳过")
                    continue

                full_record = f"{self.RECORD_NAME}.{clean_domain}"
                current_err.record_name = full_record
                current_err.txt_value = txt_value
                logger.info(
                    f"[{provider_name}] 添加 DNS TXT 记录: {full_record} = {txt_value}"
                )

                try:
                    added = self.dns_provider.add_txt_record(
                        clean_domain, self.RECORD_NAME, txt_value
                    )
                    if not added:
                        current_err.error_type = "DNS 记录添加返回失败"
                        current_err.error_detail = (
                            f"{provider_name} add_txt_record 返回 False，"
                            f"请检查该域名是否在该服务商账号下、以及记录是否已存在"
                        )
                        errors.append(current_err)
                        continue
                except DNSProviderError as e:
                    current_err.error_type = "DNS 记录添加异常"
                    current_err.error_detail = str(e)
                    errors.append(current_err)
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
                    current_err.error_type = "ACME 应答/验证失败"
                    current_err.error_detail = str(e)
                    errors.append(current_err)

            except ACMEClientError as e:
                current_err.identifier = current_err.identifier or identifier or "<unknown>"
                current_err.error_type = "ACME 授权信息获取失败"
                current_err.error_detail = str(e)
                errors.append(current_err)
            except DNSProviderError as e:
                current_err.identifier = current_err.identifier or identifier or "<unknown>"
                current_err.error_type = "DNS 操作异常"
                current_err.error_detail = str(e)
                errors.append(current_err)
            except Exception as e:
                current_err.identifier = current_err.identifier or identifier or "<unknown>"
                current_err.error_type = "未知错误"
                current_err.error_detail = str(e)
                errors.append(current_err)

        for clean_domain, record_name in reversed(cleanup_stack):
            try:
                logger.info(f"清理 DNS TXT 记录: {record_name}.{clean_domain}")
                self.dns_provider.delete_txt_record(clean_domain, record_name)
            except Exception as e:
                logger.warning(f"清理 DNS 记录失败 {record_name}.{clean_domain}: {e}")

        logger.info(f"DNS 挑战完成: {success_count}/{total} 成功")

        if errors:
            logger.error(f"DNS-01 验证失败详情 ({len(errors)} 条):")
            for err in errors:
                logger.error(f"\n{err.format()}")

        return ChallengerResult(
            success=(success_count == total),
            success_count=success_count,
            total_count=total,
            errors=errors,
        )

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
