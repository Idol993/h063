from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator


class AlertThresholdConfig(BaseModel):
    warning_days: int = Field(default=30, description="警告阈值天数")
    critical_days: int = Field(default=7, description="紧急阈值天数")


class WebhookConfig(BaseModel):
    url: str = Field(description="Webhook 地址")
    type: str = Field(default="dingtalk", description="Webhook 类型: dingtalk / wecom / custom")
    secret: Optional[str] = Field(default=None, description="签名密钥（可选）")


class NotifierConfig(BaseModel):
    webhooks: List[WebhookConfig] = Field(default_factory=list)
    threshold: AlertThresholdConfig = Field(default_factory=AlertThresholdConfig)


class DNSProviderConfig(BaseModel):
    type: str = Field(description="DNS 服务商类型: aliyun / tencent / cloudflare")
    config: Dict[str, Any] = Field(default_factory=dict, description="DNS 服务商配置")


class ACMEConfig(BaseModel):
    directory_url: str = Field(
        default="https://acme-v02.api.letsencrypt.org/directory",
        description="ACME 目录 URL",
    )
    email: str = Field(description="注册邮箱")
    account_key_path: str = Field(default="./data/account.key", description="账户私钥路径")
    challenge_type: str = Field(default="dns-01", description="验证方式: dns-01 / http-01")
    dns_provider: Optional[DNSProviderConfig] = Field(default=None, description="DNS 服务商配置")
    staging: bool = Field(default=False, description="是否使用测试环境")


class DomainConfig(BaseModel):
    domain: str = Field(description="域名（支持通配符 *.example.com）")
    port: int = Field(default=443, description="SSL 端口")
    deploy_method: Optional[str] = Field(default=None, description="部署方式: nginx / apache")
    cert_path: Optional[str] = Field(default=None, description="证书文件路径")
    key_path: Optional[str] = Field(default=None, description="私钥文件路径")
    auto_renew: bool = Field(default=True, description="是否自动续期")


class NginxDeployConfig(BaseModel):
    nginx_bin: str = Field(default="nginx", description="Nginx 可执行文件路径")
    reload_command: str = Field(default="nginx -s reload", description="热重载命令")


class ApacheDeployConfig(BaseModel):
    apachectl_bin: str = Field(default="apachectl", description="Apache 控制命令路径")
    reload_command: str = Field(default="apachectl graceful", description="热重载命令")


class DeployConfig(BaseModel):
    nginx: NginxDeployConfig = Field(default_factory=NginxDeployConfig)
    apache: ApacheDeployConfig = Field(default_factory=ApacheDeployConfig)
    backup_dir: str = Field(default="./backups", description="备份目录")
    backup_count: int = Field(default=5, description="保留备份数量")


class MonitorConfig(BaseModel):
    check_time: str = Field(default="09:00", description="每日检查时间 HH:MM")
    check_interval_hours: Optional[int] = Field(default=None, description="检查间隔小时数（可选）")
    daemon: bool = Field(default=False, description="是否以守护进程运行")


class AppConfig(BaseModel):
    domains: List[DomainConfig] = Field(description="域名列表")
    notifier: NotifierConfig = Field(default_factory=NotifierConfig)
    acme: Optional[ACMEConfig] = Field(default=None)
    deploy: DeployConfig = Field(default_factory=DeployConfig)
    monitor: MonitorConfig = Field(default_factory=MonitorConfig)
    timeout: int = Field(default=10, description="连接超时时间（秒）")
    max_workers: int = Field(default=20, description="最大并发线程数")
    proxy: Optional[str] = Field(default=None, description="代理地址")

    @field_validator("domains")
    @classmethod
    def domains_not_empty(cls, v):
        if not v:
            raise ValueError("域名列表不能为空")
        return v
