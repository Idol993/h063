import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from ssl_manager.deployer.backup import BackupManager
from ssl_manager.utils.logger import logger


class NginxDeployer:
    def __init__(
        self,
        nginx_bin: str = "nginx",
        reload_command: str = "nginx -s reload",
        backup_dir: str = "./backups",
        backup_count: int = 5,
    ):
        self.nginx_bin = nginx_bin
        self.reload_command = reload_command
        self.backup_manager = BackupManager(backup_dir, backup_count)

    def deploy(self, domain: str, cert_path: str, key_path: str, target_cert_path: str, target_key_path: str) -> bool:
        logger.info(f"部署 Nginx 证书: {domain}")

        try:
            self._backup_existing_certs(domain, target_cert_path, target_key_path)
            self._copy_certificates(cert_path, key_path, target_cert_path, target_key_path)

            if self._test_config():
                self._reload_nginx()
                logger.info(f"Nginx 证书部署成功: {domain}")
                return True
            else:
                logger.error(f"Nginx 配置测试失败，回滚中...")
                self._rollback(domain, target_cert_path, target_key_path)
                return False

        except Exception as e:
            logger.error(f"Nginx 部署失败: {e}")
            return False

    def _backup_existing_certs(self, domain: str, cert_path: str, key_path: str):
        files_to_backup = []
        if Path(cert_path).exists():
            files_to_backup.append(cert_path)
        if Path(key_path).exists():
            files_to_backup.append(key_path)

        if files_to_backup:
            self.backup_manager.create_file_backup(files_to_backup, domain)

    def _copy_certificates(self, src_cert: str, src_key: str, dst_cert: str, dst_key: str):
        dst_cert_path = Path(dst_cert)
        dst_key_path = Path(dst_key)

        dst_cert_path.parent.mkdir(parents=True, exist_ok=True)
        dst_key_path.parent.mkdir(parents=True, exist_ok=True)

        shutil.copy2(src_cert, dst_cert)
        shutil.copy2(src_key, dst_key)

        os.chmod(dst_cert, 0o644)
        os.chmod(dst_key, 0o600)

        logger.info(f"证书文件已复制: {dst_cert}, {dst_key}")

    def _test_config(self) -> bool:
        try:
            result = subprocess.run(
                [self.nginx_bin, "-t"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                logger.info("Nginx 配置测试通过")
                return True
            else:
                logger.error(f"Nginx 配置测试失败: {result.stderr}")
                return False
        except FileNotFoundError:
            logger.warning("nginx 命令未找到，跳过配置测试")
            return True
        except Exception as e:
            logger.error(f"Nginx 配置测试异常: {e}")
            return False

    def _reload_nginx(self):
        try:
            result = subprocess.run(
                self.reload_command.split(),
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                logger.info("Nginx 热重载成功")
            else:
                raise RuntimeError(f"Nginx 热重载失败: {result.stderr}")
        except FileNotFoundError:
            logger.warning("nginx 命令未找到，跳过热重载")

    def _rollback(self, domain: str, cert_path: str, key_path: str):
        backups = self.backup_manager.list_backups(domain)
        if backups:
            latest_backup = backups[0]
            target_dir = str(Path(cert_path).parent)
            self.backup_manager.restore_backup(str(latest_backup), target_dir)
            logger.info(f"已回滚到备份: {latest_backup}")
            self._reload_nginx()
        else:
            logger.warning("没有可用的备份，无法回滚")

    def get_cert_paths(self, domain: str, base_path: Optional[str] = None) -> tuple:
        if base_path:
            base = Path(base_path)
        else:
            base = Path(f"/etc/nginx/certs")

        cert_path = base / domain / "fullchain.pem"
        key_path = base / domain / "privkey.pem"
        return str(cert_path), str(key_path)
