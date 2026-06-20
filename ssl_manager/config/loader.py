import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import ValidationError

from ssl_manager.config.schema import AppConfig, DomainConfig
from ssl_manager.utils.logger import logger


class ConfigLoader:
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)

    def load(self) -> AppConfig:
        if not self.config_path.exists():
            raise FileNotFoundError(f"配置文件不存在: {self.config_path}")

        logger.info(f"加载配置文件: {self.config_path}")

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                config_data = yaml.safe_load(f)

            if not config_data:
                raise ValueError("配置文件为空")

            app_config = AppConfig(**config_data)
            logger.info(f"配置加载成功，共 {len(app_config.domains)} 个域名")
            return app_config

        except yaml.YAMLError as e:
            logger.error(f"YAML 解析失败: {e}")
            raise
        except ValidationError as e:
            logger.error(f"配置校验失败: {e}")
            raise

    def save(self, config: AppConfig) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)

        config_dict = config.model_dump()

        with open(self.config_path, "w", encoding="utf-8") as f:
            yaml.dump(config_dict, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

        logger.info(f"配置已保存到: {self.config_path}")


def load_config(config_path: Optional[str] = None) -> AppConfig:
    if config_path is None:
        config_path = os.environ.get("SSL_MANAGER_CONFIG", "config.yaml")

    loader = ConfigLoader(config_path)
    return loader.load()


def add_domain(config_path: str, domain: str, port: int = 443, deploy_method: Optional[str] = None) -> None:
    loader = ConfigLoader(config_path)
    config = loader.load()

    new_domain = DomainConfig(domain=domain, port=port, deploy_method=deploy_method)
    config.domains.append(new_domain)

    loader.save(config)
    logger.info(f"已添加域名: {domain}")
