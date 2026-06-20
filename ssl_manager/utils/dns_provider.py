from abc import ABC, abstractmethod
from typing import Optional

import requests

from ssl_manager.utils.logger import logger


class DNSProviderError(Exception):
    pass


class DNSProvider(ABC):
    @abstractmethod
    def add_txt_record(self, domain: str, record_name: str, record_value: str) -> bool:
        pass

    @abstractmethod
    def delete_txt_record(self, domain: str, record_name: str) -> bool:
        pass

    @abstractmethod
    def wait_for_propagation(self, domain: str, record_name: str, expected_value: str, timeout: int = 120) -> bool:
        pass


def _validate_required_credentials(creds: dict, provider_name: str):
    missing = [k for k, v in creds.items() if not v]
    if missing:
        raise DNSProviderError(
            f"{provider_name} DNS 配置缺少必要凭据: {', '.join(missing)}。"
            f"请在配置文件 acme.dns_provider.config 中填写完整。"
        )


class AliyunDNSProvider(DNSProvider):
    def __init__(self, access_key_id: str, access_key_secret: str):
        _validate_required_credentials(
            {"access_key_id": access_key_id, "access_key_secret": access_key_secret},
            "阿里云",
        )
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.endpoint = "https://alidns.aliyuncs.com"
        self._sdk_available = self._check_sdk()

    def _check_sdk(self) -> bool:
        try:
            from aliyunsdkcore.client import AcsClient
            from aliyunsdkcore.request import CommonRequest
            return True
        except ImportError:
            raise DNSProviderError(
                "阿里云 DNS SDK 未安装。请执行: pip install aliyun-python-sdk-core-v3 aliyun-python-sdk-alidns"
            )

    def add_txt_record(self, domain: str, record_name: str, record_value: str) -> bool:
        logger.info(f"阿里云 DNS: 添加 TXT 记录 {record_name}.{domain} = {record_value}")
        if not self._sdk_available:
            return False
        try:
            from aliyunsdkcore.client import AcsClient
            from aliyunsdkcore.request import CommonRequest

            client = AcsClient(self.access_key_id, self.access_key_secret, "cn-hangzhou")
            request = CommonRequest()
            request.set_accept_format("json")
            request.set_domain("alidns.aliyuncs.com")
            request.set_method("POST")
            request.set_protocol_type("https")
            request.set_version("2015-01-09")
            request.set_action_name("AddDomainRecord")

            request.add_query_param("DomainName", domain)
            request.add_query_param("RR", record_name)
            request.add_query_param("Type", "TXT")
            request.add_query_param("Value", record_value)

            response = client.do_action_with_exception(request)
            logger.info(f"阿里云 DNS: TXT 记录添加成功: {response}")
            return True
        except Exception as e:
            error_msg = str(e)
            logger.error(f"阿里云 DNS: 添加 TXT 记录失败: {error_msg}")
            if "InvalidAccessKeyId" in error_msg or "SignatureDoesNotMatch" in error_msg:
                raise DNSProviderError(
                    "阿里云 DNS 凭据无效 (InvalidAccessKeyId/SignatureDoesNotMatch)，"
                    "请检查 access_key_id 和 access_key_secret 是否正确。"
                ) from e
            raise DNSProviderError(f"阿里云 DNS 添加 TXT 记录失败: {error_msg}") from e

    def delete_txt_record(self, domain: str, record_name: str) -> bool:
        logger.info(f"阿里云 DNS: 删除 TXT 记录 {record_name}.{domain}")
        if not self._sdk_available:
            return False
        try:
            from aliyunsdkcore.client import AcsClient
            from aliyunsdkcore.request import CommonRequest

            client = AcsClient(self.access_key_id, self.access_key_secret, "cn-hangzhou")

            describe_request = CommonRequest()
            describe_request.set_accept_format("json")
            describe_request.set_domain("alidns.aliyuncs.com")
            describe_request.set_method("POST")
            describe_request.set_protocol_type("https")
            describe_request.set_version("2015-01-09")
            describe_request.set_action_name("DescribeDomainRecords")
            describe_request.add_query_param("DomainName", domain)
            describe_request.add_query_param("RRKeyWord", record_name)
            describe_request.add_query_param("Type", "TXT")

            import json
            response = client.do_action_with_exception(describe_request)
            records = json.loads(response)
            record_list = records.get("DomainRecords", {}).get("Record", [])

            if record_list:
                record_id = record_list[0]["RecordId"]
                delete_request = CommonRequest()
                delete_request.set_accept_format("json")
                delete_request.set_domain("alidns.aliyuncs.com")
                delete_request.set_method("POST")
                delete_request.set_protocol_type("https")
                delete_request.set_version("2015-01-09")
                delete_request.set_action_name("DeleteDomainRecord")
                delete_request.add_query_param("RecordId", record_id)
                client.do_action_with_exception(delete_request)
                logger.info(f"阿里云 DNS: TXT 记录删除成功")
            return True
        except Exception as e:
            logger.error(f"阿里云 DNS: 删除 TXT 记录失败: {e}")
            return False

    def wait_for_propagation(self, domain: str, record_name: str, expected_value: str, timeout: int = 120) -> bool:
        import time
        logger.info(f"等待 DNS 记录传播: {record_name}.{domain}")
        elapsed = 0
        while elapsed < timeout:
            try:
                import dns.resolver
                answers = dns.resolver.resolve(f"{record_name}.{domain}", "TXT")
                for rdata in answers:
                    for txt_string in rdata.strings:
                        if txt_string.decode() == expected_value:
                            logger.info(f"DNS 记录已传播")
                            return True
            except Exception:
                pass
            time.sleep(5)
            elapsed += 5
        logger.warning(f"DNS 记录传播超时 ({timeout}s)")
        return False


class TencentDNSProvider(DNSProvider):
    def __init__(self, secret_id: str, secret_key: str):
        _validate_required_credentials(
            {"secret_id": secret_id, "secret_key": secret_key},
            "腾讯云",
        )
        self.secret_id = secret_id
        self.secret_key = secret_key
        self._sdk_available = self._check_sdk()

    def _check_sdk(self) -> bool:
        try:
            from tencentcloud.common import credential
            from tencentcloud.dnspod.v20210323 import dnspod_client
            return True
        except ImportError:
            raise DNSProviderError(
                "腾讯云 DNS SDK 未安装。请执行: pip install tencentcloud-sdk-python"
            )

    def add_txt_record(self, domain: str, record_name: str, record_value: str) -> bool:
        logger.info(f"腾讯云 DNS: 添加 TXT 记录 {record_name}.{domain} = {record_value}")
        if not self._sdk_available:
            return False
        try:
            from tencentcloud.common import credential
            from tencentcloud.dnspod.v20210323 import dnspod_client, models

            cred = credential.Credential(self.secret_id, self.secret_key)
            client = dnspod_client.DnspodClient(cred, "")
            req = models.CreateRecordRequest()
            req.Domain = domain
            req.SubDomain = record_name
            req.RecordType = "TXT"
            req.RecordLine = "默认"
            req.Value = record_value
            client.CreateRecord(req)
            logger.info(f"腾讯云 DNS: TXT 记录添加成功")
            return True
        except Exception as e:
            error_msg = str(e)
            logger.error(f"腾讯云 DNS: 添加 TXT 记录失败: {error_msg}")
            if "AuthFailure" in error_msg or "InvalidSecretId" in error_msg:
                raise DNSProviderError(
                    "腾讯云 DNS 凭据无效 (AuthFailure/InvalidSecretId)，"
                    "请检查 secret_id 和 secret_key 是否正确。"
                ) from e
            raise DNSProviderError(f"腾讯云 DNS 添加 TXT 记录失败: {error_msg}") from e

    def delete_txt_record(self, domain: str, record_name: str) -> bool:
        logger.info(f"腾讯云 DNS: 删除 TXT 记录 {record_name}.{domain}")
        if not self._sdk_available:
            return False
        try:
            from tencentcloud.common import credential
            from tencentcloud.dnspod.v20210323 import dnspod_client, models

            cred = credential.Credential(self.secret_id, self.secret_key)
            client = dnspod_client.DnspodClient(cred, "")

            list_req = models.DescribeRecordListRequest()
            list_req.Domain = domain
            list_req.Subdomain = record_name
            list_req.RecordType = "TXT"
            resp = client.DescribeRecordList(list_req)

            if resp.RecordList:
                record_id = resp.RecordList[0].RecordId
                delete_req = models.DeleteRecordRequest()
                delete_req.Domain = domain
                delete_req.RecordId = record_id
                client.DeleteRecord(delete_req)
                logger.info(f"腾讯云 DNS: TXT 记录删除成功")
            return True
        except Exception as e:
            logger.error(f"腾讯云 DNS: 删除 TXT 记录失败: {e}")
            return False

    def wait_for_propagation(self, domain: str, record_name: str, expected_value: str, timeout: int = 120) -> bool:
        import time
        logger.info(f"等待 DNS 记录传播: {record_name}.{domain}")
        elapsed = 0
        while elapsed < timeout:
            try:
                import dns.resolver
                answers = dns.resolver.resolve(f"{record_name}.{domain}", "TXT")
                for rdata in answers:
                    for txt_string in rdata.strings:
                        if txt_string.decode() == expected_value:
                            logger.info(f"DNS 记录已传播")
                            return True
            except Exception:
                pass
            time.sleep(5)
            elapsed += 5
        logger.warning(f"DNS 记录传播超时 ({timeout}s)")
        return False


class CloudflareDNSProvider(DNSProvider):
    def __init__(self, api_token: str, zone_id: Optional[str] = None):
        _validate_required_credentials(
            {"api_token": api_token},
            "Cloudflare",
        )
        self.api_token = api_token
        self.zone_id = zone_id
        self.base_url = "https://api.cloudflare.com/client/v4"
        self._validate_token()

    def _validate_token(self):
        try:
            url = f"{self.base_url}/user/tokens/verify"
            headers = {
                "Authorization": f"Bearer {self.api_token}",
                "Content-Type": "application/json",
            }
            response = requests.get(url, headers=headers, timeout=10)
            result = response.json()
            if not result.get("success"):
                errors = result.get("errors", [])
                error_msgs = "; ".join([e.get("message", str(e)) for e in errors])
                raise DNSProviderError(
                    f"Cloudflare API Token 验证失败: {error_msgs}。"
                    f"请检查 api_token 是否正确且具有 DNS:Edit 权限。"
                )
            logger.info("Cloudflare API Token 验证通过")
        except DNSProviderError:
            raise
        except requests.RequestException as e:
            raise DNSProviderError(f"Cloudflare API 连接失败: {e}") from e
        except Exception as e:
            raise DNSProviderError(f"Cloudflare DNS 初始化失败: {e}") from e

    def _get_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }

    def _get_zone_id(self, domain: str) -> str:
        if self.zone_id:
            return self.zone_id

        url = f"{self.base_url}/zones"
        params = {"name": domain}
        response = requests.get(url, headers=self._get_headers(), params=params)
        result = response.json()
        if result.get("success") and result.get("result"):
            return result["result"][0]["id"]
        raise DNSProviderError(
            f"未在 Cloudflare 找到域名 {domain} 的 Zone。请确认域名已添加到 Cloudflare，"
            f"或在配置中显式指定 zone_id。"
        )

    def add_txt_record(self, domain: str, record_name: str, record_value: str) -> bool:
        logger.info(f"Cloudflare DNS: 添加 TXT 记录 {record_name}.{domain} = {record_value}")
        try:
            zone_id = self._get_zone_id(domain)
            url = f"{self.base_url}/zones/{zone_id}/dns_records"
            data = {
                "type": "TXT",
                "name": f"{record_name}.{domain}",
                "content": record_value,
                "ttl": 120,
            }
            response = requests.post(url, headers=self._get_headers(), json=data)
            result = response.json()
            if result.get("success"):
                logger.info("Cloudflare DNS: TXT 记录添加成功")
                return True
            errors = result.get("errors", [])
            error_msgs = "; ".join([e.get("message", str(e)) for e in errors])
            logger.error(f"Cloudflare DNS: 添加失败 - {error_msgs}")
            raise DNSProviderError(f"Cloudflare DNS 添加 TXT 记录失败: {error_msgs}")
        except DNSProviderError:
            raise
        except Exception as e:
            logger.error(f"Cloudflare DNS: 添加 TXT 记录失败: {e}")
            raise DNSProviderError(f"Cloudflare DNS 添加 TXT 记录失败: {e}") from e

    def delete_txt_record(self, domain: str, record_name: str) -> bool:
        logger.info(f"Cloudflare DNS: 删除 TXT 记录 {record_name}.{domain}")
        try:
            zone_id = self._get_zone_id(domain)
            list_url = f"{self.base_url}/zones/{zone_id}/dns_records"
            params = {"type": "TXT", "name": f"{record_name}.{domain}"}
            list_resp = requests.get(list_url, headers=self._get_headers(), params=params)
            list_result = list_resp.json()

            if list_result.get("success") and list_result.get("result"):
                record_id = list_result["result"][0]["id"]
                delete_url = f"{self.base_url}/zones/{zone_id}/dns_records/{record_id}"
                delete_resp = requests.delete(delete_url, headers=self._get_headers())
                if delete_resp.json().get("success"):
                    logger.info("Cloudflare DNS: TXT 记录删除成功")
                    return True
            return True
        except Exception as e:
            logger.error(f"Cloudflare DNS: 删除 TXT 记录失败: {e}")
            return False

    def wait_for_propagation(self, domain: str, record_name: str, expected_value: str, timeout: int = 120) -> bool:
        import time
        logger.info(f"等待 DNS 记录传播: {record_name}.{domain}")
        elapsed = 0
        while elapsed < timeout:
            try:
                import dns.resolver
                answers = dns.resolver.resolve(f"{record_name}.{domain}", "TXT")
                for rdata in answers:
                    for txt_string in rdata.strings:
                        if txt_string.decode() == expected_value:
                            logger.info(f"DNS 记录已传播")
                            return True
            except Exception:
                pass
            time.sleep(5)
            elapsed += 5
        logger.warning(f"DNS 记录传播超时 ({timeout}s)")
        return False


def create_dns_provider(provider_type: str, **kwargs) -> DNSProvider:
    providers = {
        "aliyun": AliyunDNSProvider,
        "tencent": TencentDNSProvider,
        "cloudflare": CloudflareDNSProvider,
    }
    provider_class = providers.get(provider_type.lower())
    if not provider_class:
        raise ValueError(
            f"不支持的 DNS 服务商: {provider_type}。"
            f"支持的服务商: {', '.join(providers.keys())}"
        )

    required_params_map = {
        "aliyun": ["access_key_id", "access_key_secret"],
        "tencent": ["secret_id", "secret_key"],
        "cloudflare": ["api_token"],
    }
    required = required_params_map.get(provider_type.lower(), [])
    missing = [p for p in required if p not in kwargs or not kwargs.get(p)]
    if missing:
        raise ValueError(
            f"DNS 服务商 {provider_type} 缺少必要配置参数: {', '.join(missing)}。"
            f"请在 config.yaml 的 acme.dns_provider.config 中填写。"
        )

    return provider_class(**kwargs)
