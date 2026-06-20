from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ssl_manager.deployer.backup import BackupManager
from ssl_manager.utils.logger import logger


@dataclass
class RollbackResult:
    """回滚操作结果"""
    success: bool
    # 已恢复到目标路径的文件: {备份文件名: 目标绝对路径}
    restored_files: Dict[str, str] = field(default_factory=dict)
    # 未恢复的文件: {备份文件名: 目标绝对路径}
    missing_files: Dict[str, str] = field(default_factory=dict)
    # 原无备份时，已删除的新文件
    deleted_new_files: List[str] = field(default_factory=list)
    # 原无备份时，删除失败还残留的新文件
    leftover_new_files: List[str] = field(default_factory=list)
    detail: str = ""

    def format_lines(self) -> List[str]:
        lines = []
        if self.success:
            if self.restored_files:
                lines.append(f"    已恢复的目标文件:")
                for arc_name, target in self.restored_files.items():
                    lines.append(f"      - {target} (来源: {arc_name})")
            if self.deleted_new_files:
                lines.append(f"    已清理的新文件:")
                for f in self.deleted_new_files:
                    lines.append(f"      - {f}")
            lines.append(f"    回滚成功")
        else:
            if self.restored_files:
                lines.append(f"    已恢复的目标文件:")
                for arc_name, target in self.restored_files.items():
                    lines.append(f"      - {target} (来源: {arc_name})")
            if self.missing_files:
                lines.append(f"    未恢复的目标文件 (备份中缺失):")
                for arc_name, target in self.missing_files.items():
                    lines.append(f"      - {target} (期望备份内文件名: {arc_name})")
            if self.deleted_new_files:
                lines.append(f"    已清理的新文件:")
                for f in self.deleted_new_files:
                    lines.append(f"      - {f}")
            if self.leftover_new_files:
                lines.append(f"    [警告] 残留未清理的新文件 (请手动删除):")
                for f in self.leftover_new_files:
                    lines.append(f"      - {f}")
            if self.detail:
                lines.append(f"    回滚详情: {self.detail}")
        return lines


@dataclass
class DeployResult:
    """部署操作结果"""
    success: bool
    failure_type: str = ""
    # 失败原因: not_found_cmd / config_test_failed / reload_failed / exception
    failure_detail: str = ""
    # 已复制的目标文件路径（用于无备份时清空）
    deployed_target_files: List[str] = field(default_factory=list)
    rollback: Optional[RollbackResult] = None


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

    def deploy(self, domain: str, cert_path: str, key_path: str, target_cert_path: str, target_key_path: str) -> DeployResult:
        result = DeployResult(
            success=False,
            deployed_target_files=[target_cert_path, target_key_path],
        )

        logger.info(f"部署 Nginx 证书: {domain}")

        try:
            self._backup_existing_certs(domain, target_cert_path, target_key_path)
            self._copy_certificates(cert_path, key_path, target_cert_path, target_key_path)

            test_ok, test_msg = self._test_config()
            if not test_ok:
                result.failure_type = "config_test_failed"
                result.failure_detail = test_msg
                logger.error(f"Nginx 配置测试未通过，回滚中...")
                result.rollback = self._rollback(domain, target_cert_path, target_key_path)
                return result

            reload_ok, reload_msg = self._reload_nginx()
            if not reload_ok:
                result.failure_type = "reload_failed"
                result.failure_detail = reload_msg
                logger.error(f"Nginx 热重载失败，回滚中...")
                result.rollback = self._rollback(domain, target_cert_path, target_key_path)
                return result

            result.success = True
            logger.info(f"Nginx 证书部署成功: {domain}")
            return result

        except FileNotFoundError as e:
            result.failure_type = "not_found_cmd"
            result.failure_detail = str(e)
            logger.error(f"Nginx 命令未找到: {e}")
        except Exception as e:
            result.failure_type = "exception"
            result.failure_detail = str(e)
            logger.error(f"Nginx 部署异常: {e}")

        try:
            result.rollback = self._rollback(domain, target_cert_path, target_key_path)
        except Exception as rb_e:
            logger.error(f"回滚也失败: {rb_e}")

        return result

    def _backup_existing_certs(self, domain: str, cert_path: str, key_path: str):
        files_to_backup = []
        if Path(cert_path).exists():
            files_to_backup.append(cert_path)
        if Path(key_path).exists():
            files_to_backup.append(key_path)

        if files_to_backup:
            self.backup_manager.create_file_backup(files_to_backup, domain)
        else:
            logger.info("目标位置无现有证书文件，跳过备份（失败时将直接清理新文件）")

    def _copy_certificates(self, src_cert: str, src_key: str, dst_cert: str, dst_key: str):
        import os
        import shutil

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

    def _test_config(self):
        import subprocess

        try:
            result = subprocess.run(
                [self.nginx_bin, "-t"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                logger.info("Nginx 配置测试通过")
                return True, ""
            else:
                detail = result.stderr.strip() or f"nginx -t exit code {result.returncode}"
                logger.error(f"Nginx 配置测试失败: {detail}")
                return False, detail
        except FileNotFoundError:
            msg = f"nginx 命令未找到: {self.nginx_bin}"
            logger.error(f"{msg}，部署失败")
            return False, msg
        except subprocess.TimeoutExpired:
            msg = "nginx -t 配置测试超时 (30s)"
            logger.error(msg)
            return False, msg
        except Exception as e:
            msg = f"nginx -t 异常: {e}"
            logger.error(msg)
            return False, msg

    def _reload_nginx(self):
        import subprocess

        try:
            result = subprocess.run(
                self.reload_command.split(),
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                logger.info("Nginx 热重载成功")
                return True, ""
            else:
                detail = result.stderr.strip() or f"reload exit code {result.returncode}"
                logger.error(f"Nginx 热重载失败: {detail}")
                return False, detail
        except FileNotFoundError:
            msg = f"热重载命令未找到: {self.reload_command}"
            logger.error(msg)
            return False, msg
        except subprocess.TimeoutExpired:
            msg = f"nginx reload 超时 (30s)"
            logger.error(msg)
            return False, msg
        except Exception as e:
            msg = f"nginx reload 异常: {e}"
            logger.error(msg)
            return False, msg

    def _rollback(self, domain: str, cert_path: str, key_path: str) -> RollbackResult:
        rb = RollbackResult(success=False)
        backups = self.backup_manager.list_backups(domain)
        cert_name = Path(cert_path).name
        key_name = Path(key_path).name

        target_path_map: Dict[str, str] = {
            cert_name: cert_path,
            key_name: key_path,
        }

        if not backups:
            logger.warning("没有可用的备份，将尝试删除刚复制进去的新文件")
            deleted = []
            leftover = []
            for target in (cert_path, key_path):
                p = Path(target)
                if p.exists():
                    try:
                        p.unlink()
                        deleted.append(target)
                        logger.info(f"已删除新复制的文件: {target}")
                    except OSError as e:
                        leftover.append(target)
                        logger.warning(f"删除失败: {target}: {e}")
            rb.deleted_new_files = deleted
            rb.leftover_new_files = leftover
            rb.success = (len(leftover) == 0)
            if not rb.success:
                rb.detail = f"无备份，共 {len(deleted)} 个新文件已清理，{len(leftover)} 个残留"
            return rb

        latest_backup = backups[0]
        backup_contents = self.backup_manager.list_backup_contents(str(latest_backup))

        in_backup = {}
        missing = {}
        for arc_name, target in target_path_map.items():
            if arc_name in backup_contents:
                in_backup[arc_name] = target
            else:
                missing[arc_name] = target

        ok = False
        if in_backup:
            ok = self.backup_manager.restore_files_to_paths(str(latest_backup), in_backup)
            rb.restored_files = dict(in_backup) if ok else {}
            rb.missing_files = missing

            if ok:
                logger.info(f"已回滚到备份: {latest_backup}，文件已恢复到原始目标路径")
                # 回滚后重载 nginx（即使失败也不影响结果）
                self._reload_nginx()
                if not missing:
                    rb.success = True
                else:
                    rb.success = False
                    rb.detail = f"部分文件未在备份中 ({', '.join(missing.keys())})"
            else:
                rb.success = False
                rb.detail = f"从备份 {latest_backup} 恢复失败"
        else:
            rb.missing_files = missing
            rb.success = False
            rb.detail = f"备份中未找到任何期望的证书文件 (期望: {cert_name}, {key_name})"

        return rb

    def get_cert_paths(self, domain: str, base_path: Optional[str] = None) -> tuple:
        if base_path:
            base = Path(base_path)
        else:
            base = Path("/etc/nginx/certs")

        cert_path = base / domain / "fullchain.pem"
        key_path = base / domain / "privkey.pem"
        return str(cert_path), str(key_path)
