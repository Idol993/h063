import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Optional

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

            test_ok = self._test_config()
            if not test_ok:
                logger.error(f"Nginx 配置测试未通过 (可能 nginx 未安装或配置有误)，回滚中...")
                rollback_ok = self._rollback(domain, target_cert_path, target_key_path)
                if not rollback_ok:
                    logger.error(f"回滚失败: 无法恢复原始证书文件到 {target_cert_path}, {target_key_path}")
                return False

            reload_ok = self._reload_nginx()
            if not reload_ok:
                logger.error(f"Nginx 热重载失败，回滚中...")
                rollback_ok = self._rollback(domain, target_cert_path, target_key_path)
                if not rollback_ok:
                    logger.error(f"回滚失败: 无法恢复原始证书文件到 {target_cert_path}, {target_key_path}")
                return False

            logger.info(f"Nginx 证书部署成功: {domain}")
            return True

        except Exception as e:
            logger.error(f"Nginx 部署异常: {e}")
            try:
                self._rollback(domain, target_cert_path, target_key_path)
            except Exception as rb_e:
                logger.error(f"回滚也失败: {rb_e}")
            return False

    def _backup_existing_certs(self, domain: str, cert_path: str, key_path: str):
        files_to_backup = []
        if Path(cert_path).exists():
            files_to_backup.append(cert_path)
        if Path(key_path).exists():
            files_to_backup.append(key_path)

        if files_to_backup:
            self.backup_manager.create_file_backup(files_to_backup, domain)
        else:
            logger.info("目标位置无现有证书文件，跳过备份")

    def _copy_certificates(self, src_cert: str, src_key: str, dst_cert: str, dst_key: str):
        dst_cert_path = Path(dst_cert)
        dst_key_path = Path(dst_key)

        dst_cert_path.parent.mkdir(parents=True, exist_ok=True)
        dst_key_path.parent.mkdir(parents=True, exist_ok=True)

        shutil.copy2(src_cert, dst_cert)
        shutil.copy2(src_key, dst_key)

        try:
            os.chmod(dst_cert, 0o644)
            os.chmod(dst_key, 0o600)
        except OSError:
            pass

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
                logger.error(f"Nginx 配置测试失败: {result.stderr.strip()}")
                return False
        except FileNotFoundError:
            logger.error(f"Nginx 命令未找到: {self.nginx_bin}，部署失败")
            return False
        except subprocess.TimeoutExpired:
            logger.error("Nginx 配置测试超时")
            return False
        except Exception as e:
            logger.error(f"Nginx 配置测试异常: {e}")
            return False

    def _reload_nginx(self) -> bool:
        try:
            result = subprocess.run(
                self.reload_command.split(),
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                logger.info("Nginx 热重载成功")
                return True
            else:
                logger.error(f"Nginx 热重载失败: {result.stderr.strip()}")
                return False
        except FileNotFoundError:
            logger.error(f"热重载命令未找到: {self.reload_command}")
            return False
        except subprocess.TimeoutExpired:
            logger.error("Nginx 热重载超时")
            return False
        except Exception as e:
            logger.error(f"Nginx 热重载异常: {e}")
            return False

    def _rollback(self, domain: str, cert_path: str, key_path: str) -> bool:
        backups = self.backup_manager.list_backups(domain)
        if not backups:
            logger.warning("没有可用的备份，无法回滚")
            return False

        latest_backup = backups[0]
        target_path_map: Dict[str, str] = {}
        cert_name = Path(cert_path).name
        key_name = Path(key_path).name

        backup_contents = self.backup_manager.list_backup_contents(str(latest_backup))

        for name in backup_contents:
            if name == cert_name:
                target_path_map[name] = cert_path
            elif name == key_name:
                target_path_map[name] = key_path

        if not target_path_map:
            logger.warning(f"备份中未找到可恢复的证书文件 (期望: {cert_name}, {key_name})，尝试目录恢复")
            target_dir = str(Path(cert_path).parent)
            return self.backup_manager.restore_backup(str(latest_backup), target_dir)

        ok = self.backup_manager.restore_files_to_paths(str(latest_backup), target_path_map)
        if ok:
            logger.info(f"已回滚到备份: {latest_backup}，文件已恢复到原始目标路径")
            self._reload_nginx()
        else:
            logger.error(f"回滚失败: 文件未能恢复到目标路径 {cert_path}, {key_path}")

        return ok

    def get_cert_paths(self, domain: str, base_path: Optional[str] = None) -> tuple:
        if base_path:
            base = Path(base_path)
        else:
            base = Path("/etc/nginx/certs")

        cert_path = base / domain / "fullchain.pem"
        key_path = base / domain / "privkey.pem"
        return str(cert_path), str(key_path)
