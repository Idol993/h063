import os
import shutil
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from ssl_manager.utils.logger import logger


class BackupManager:
    def __init__(self, backup_dir: str = "./backups", backup_count: int = 5):
        self.backup_dir = Path(backup_dir)
        self.backup_count = backup_count
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def create_backup(self, source_dir: str, domain: str) -> str:
        source_path = Path(source_dir)
        if not source_path.exists():
            logger.warning(f"源目录不存在，跳过备份: {source_dir}")
            return ""

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"backup_{domain}_{timestamp}.tar.gz"
        backup_path = self.backup_dir / backup_filename

        logger.info(f"创建备份: {backup_path}")

        try:
            with tarfile.open(backup_path, "w:gz") as tar:
                tar.add(source_path, arcname=Path(source_path).name)
            logger.info(f"备份完成: {backup_path}")
            self._cleanup_old_backups(domain)
            return str(backup_path)
        except Exception as e:
            logger.error(f"备份失败: {e}")
            raise

    def create_file_backup(self, file_paths: List[str], domain: str) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"backup_{domain}_{timestamp}.tar.gz"
        backup_path = self.backup_dir / backup_filename

        logger.info(f"创建备份: {backup_path}")

        try:
            with tarfile.open(backup_path, "w:gz") as tar:
                for file_path in file_paths:
                    p = Path(file_path)
                    if p.exists():
                        tar.add(p, arcname=p.name)
            logger.info(f"备份完成: {backup_path}")
            self._cleanup_old_backups(domain)
            return str(backup_path)
        except Exception as e:
            logger.error(f"备份失败: {e}")
            raise

    def _cleanup_old_backups(self, domain: str):
        pattern = f"backup_{domain}_*.tar.gz"
        backups = sorted(self.backup_dir.glob(pattern))

        if len(backups) > self.backup_count:
            old_backups = backups[:-self.backup_count]
            for backup in old_backups:
                try:
                    backup.unlink()
                    logger.info(f"删除旧备份: {backup}")
                except Exception as e:
                    logger.warning(f"删除旧备份失败: {backup}, {e}")

    def list_backups(self, domain: str = None) -> List[Path]:
        if domain:
            pattern = f"backup_{domain}_*.tar.gz"
        else:
            pattern = "backup_*.tar.gz"
        return sorted(self.backup_dir.glob(pattern), reverse=True)

    def restore_backup(self, backup_path: str, target_dir: str) -> bool:
        backup_file = Path(backup_path)
        if not backup_file.exists():
            logger.error(f"备份文件不存在: {backup_path}")
            return False

        target_path = Path(target_dir)
        target_path.parent.mkdir(parents=True, exist_ok=True)

        logger.info(f"恢复备份: {backup_path} -> {target_dir}")

        try:
            with tarfile.open(backup_file, "r:gz") as tar:
                tar.extractall(target_path)
            logger.info(f"备份恢复完成")
            return True
        except Exception as e:
            logger.error(f"恢复备份失败: {e}")
            return False

    def restore_files_to_paths(self, backup_path: str, target_path_map: Dict[str, str]) -> bool:
        """
        从备份中恢复文件到指定目标路径。
        target_path_map: {备份中的文件名: 目标绝对路径}
        例如: {"fullchain.pem": "/etc/nginx/certs/example.com/fullchain.pem", "privkey.pem": "/etc/nginx/certs/example.com/privkey.pem"}
        这样备份了哪些目标文件就恢复回哪些目标文件。
        """
        backup_file = Path(backup_path)
        if not backup_file.exists():
            logger.error(f"备份文件不存在: {backup_path}")
            return False

        logger.info(f"按路径映射恢复备份: {backup_path}")

        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                with tarfile.open(backup_file, "r:gz") as tar:
                    tar.extractall(tmp_dir)

                all_ok = True
                for arc_name, target_abs in target_path_map.items():
                    src = Path(tmp_dir) / arc_name
                    if not src.exists():
                        logger.warning(f"备份中缺少文件 {arc_name}，跳过恢复")
                        all_ok = False
                        continue

                    dst = Path(target_abs)
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(str(src), str(dst))
                    logger.info(f"已恢复: {arc_name} -> {target_abs}")

            if all_ok:
                logger.info(f"备份恢复完成，所有文件已还原到目标路径")
            else:
                logger.warning(f"部分文件恢复失败，请检查上述日志")
            return all_ok
        except Exception as e:
            logger.error(f"按路径映射恢复备份失败: {e}")
            return False

    def list_backup_contents(self, backup_path: str) -> List[str]:
        backup_file = Path(backup_path)
        if not backup_file.exists():
            return []

        try:
            with tarfile.open(backup_file, "r:gz") as tar:
                return tar.getnames()
        except Exception:
            return []
