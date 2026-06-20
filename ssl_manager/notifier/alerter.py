import hashlib
import hmac
import base64
import time
import urllib.parse
from typing import List, Optional

import requests
from rich.console import Console
from rich.table import Table

from ssl_manager.checker.parser import CertificateInfo
from ssl_manager.checker.validator import CertificateValidator, CertStatus
from ssl_manager.config.schema import WebhookConfig
from ssl_manager.utils.logger import logger

console = Console()


class Alerter:
    def __init__(
        self,
        webhooks: Optional[List[WebhookConfig]] = None,
        warning_days: int = 30,
        critical_days: int = 7,
    ):
        self.webhooks = webhooks or []
        self.validator = CertificateValidator(warning_days, critical_days)

    def alert_if_needed(self, domain: str, cert_info: CertificateInfo) -> CertStatus:
        status = self.validator.validate(cert_info)

        if status in (CertStatus.WARNING, CertStatus.CRITICAL, CertStatus.EXPIRED):
            self._send_alert(domain, cert_info, status)

        return status

    def _send_alert(self, domain: str, cert_info: CertificateInfo, status: CertStatus):
        message = self._format_message(domain, cert_info, status)
        self._print_alert(message, status)
        self._send_webhooks(message, status)

    def _format_message(self, domain: str, cert_info: CertificateInfo, status: CertStatus) -> str:
        days = cert_info.days_remaining
        expiry_date = cert_info.not_after.strftime("%Y-%m-%d") if cert_info.not_after else "未知"

        if status == CertStatus.EXPIRED:
            prefix = "[已过期]"
            return f"{prefix} 域名 {domain} 证书已过期（到期日 {expiry_date}）"
        elif status == CertStatus.CRITICAL:
            prefix = "[紧急]"
        else:
            prefix = "[警告]"

        return f"{prefix} 域名 {domain} 证书将于 {days} 天后过期（到期日 {expiry_date}）"

    def _print_alert(self, message: str, status: CertStatus):
        color = self.validator.get_status_color(status)
        console.print(f"[{color}]{message}[/{color}]")
        logger.warning(message)

    def _send_webhooks(self, message: str, status: CertStatus):
        for webhook in self.webhooks:
            try:
                if webhook.type.lower() == "dingtalk":
                    self._send_dingtalk(webhook, message)
                elif webhook.type.lower() == "wecom":
                    self._send_wecom(webhook, message)
                else:
                    self._send_custom(webhook, message)
            except Exception as e:
                logger.error(f"发送 Webhook 失败 ({webhook.type}): {e}")

    def _send_dingtalk(self, webhook: WebhookConfig, message: str):
        url = webhook.url
        if webhook.secret:
            timestamp = str(round(time.time() * 1000))
            string_to_sign = f"{timestamp}\n{webhook.secret}"
            hmac_code = hmac.new(
                webhook.secret.encode("utf-8"),
                string_to_sign.encode("utf-8"),
                digestmod=hashlib.sha256,
            ).digest()
            sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
            url = f"{url}&timestamp={timestamp}&sign={sign}"

        data = {
            "msgtype": "text",
            "text": {
                "content": f"【SSL 证书告警】\n{message}",
            },
        }

        response = requests.post(url, json=data, timeout=10)
        result = response.json()
        if result.get("errcode") != 0:
            raise ValueError(f"钉钉推送失败: {result.get('errmsg')}")
        logger.info("钉钉告警推送成功")

    def _send_wecom(self, webhook: WebhookConfig, message: str):
        data = {
            "msgtype": "text",
            "text": {
                "content": f"【SSL 证书告警】\n{message}",
            },
        }

        response = requests.post(webhook.url, json=data, timeout=10)
        result = response.json()
        if result.get("errcode") != 0:
            raise ValueError(f"企业微信推送失败: {result.get('errmsg')}")
        logger.info("企业微信告警推送成功")

    def _send_custom(self, webhook: WebhookConfig, message: str):
        data = {
            "type": "ssl_alert",
            "message": message,
            "timestamp": int(time.time()),
        }

        response = requests.post(webhook.url, json=data, timeout=10)
        response.raise_for_status()
        logger.info("自定义 Webhook 推送成功")

    def print_summary_table(self, results: List[dict]):
        table = Table(title="SSL 证书检查结果", show_lines=True)
        table.add_column("域名", style="cyan", no_wrap=True)
        table.add_column("状态", style="bold", justify="center")
        table.add_column("剩余天数", justify="right")
        table.add_column("到期日期", justify="center")
        table.add_column("颁发者", style="white")

        for result in results:
            domain = result["domain"]
            cert_info = result.get("cert_info")
            status = result.get("status", CertStatus.UNKNOWN)

            if cert_info:
                days = cert_info.days_remaining
                expiry = cert_info.not_after.strftime("%Y-%m-%d") if cert_info.not_after else "未知"
                issuer = cert_info.issuer.split(",")[0] if cert_info.issuer else "未知"
                days_str = f"{days} 天" if days is not None else "未知"
            else:
                days_str = "获取失败"
                expiry = "获取失败"
                issuer = "获取失败"

            status_color = self.validator.get_status_color(status)
            status_label = self.validator.get_status_label(status)

            table.add_row(
                domain,
                f"[{status_color}]{status_label}[/{status_color}]",
                days_str,
                expiry,
                issuer,
            )

        console.print(table)
