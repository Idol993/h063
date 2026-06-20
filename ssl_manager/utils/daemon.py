import os
import sys
import time
import signal
from pathlib import Path
from typing import Optional


from ssl_manager.utils.logger import logger


class DaemonManager:
    def __init__(self, pid_file: str = "./data/ssl_manager.pid", log_dir: str = "./logs"):
        self.pid_file = Path(pid_file)
        self.log_dir = Path(log_dir)
        self.pid_file.parent.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def is_running(self) -> bool:
        if not self.pid_file.exists():
            return False
        try:
            with open(self.pid_file, "r") as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            return True
        except (OSError, ValueError):
            return False

    def get_pid(self) -> Optional[int]:
        if not self.pid_file.exists():
            return None
        try:
            with open(self.pid_file, "r") as f:
                return int(f.read().strip())
        except (ValueError, OSError):
            return None

    def _write_pid(self):
        with open(self.pid_file, "w") as f:
            f.write(str(os.getpid()))

    def _remove_pid(self):
        if self.pid_file.exists():
            try:
                self.pid_file.unlink()
            except OSError:
                pass

    def start(self, target_func, *args, **kwargs) -> int:
        """
        启动后台守护进程。
        Windows 下使用 CREATE_NEW_PROCESS_GROUP 分离，
        Unix 下使用标准 double-fork 方式。
        返回子进程 PID。
        """
        if self.is_running():
            existing_pid = self.get_pid()
            raise RuntimeError(f"进程已在运行 (PID={existing_pid})")

        if os.name == "nt":
            return self._start_windows(target_func, *args, **kwargs)
        else:
            return self._start_unix(target_func, *args, **kwargs)

    def _start_windows(self, target_func, *args, **kwargs) -> int:
        import subprocess

        script_path = Path(__file__).parent.parent / "cli.py"

        cmd = [
            sys.executable,
            str(script_path),
            "--config",
            kwargs.get("config_path", "config.yaml"),
            "monitor",
            "--daemon-worker",
        ]

        stdout_path = self.log_dir / "monitor.out.log"
        stderr_path = self.log_dir / "monitor.err.log"

        DETACHED_PROCESS = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200

        stdout_f = open(stdout_path, "a")
        stderr_f = open(stderr_path, "a")

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=stdout_f,
                stderr=stderr_f,
                stdin=subprocess.DEVNULL,
                close_fds=True,
                creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
                cwd=os.getcwd(),
            )
        except Exception:
            stdout_f.close()
            stderr_f.close()
            raise

        child_pid = proc.pid
        with open(self.pid_file, "w") as f:
            f.write(str(child_pid))

        time.sleep(1)
        if not self.is_running():
            raise RuntimeError("子进程启动后立即退出，请检查日志")

        logger.info(f"后台进程启动成功，PID={child_pid}")
        return child_pid

    def _start_unix(self, target_func, *args, **kwargs) -> int:
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as e:
            raise RuntimeError(f"第一次 fork 失败: {e}") from e

        os.setsid()
        os.umask(0)

        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as e:
            raise RuntimeError(f"第二次 fork 失败: {e}") from e

        child_pid = os.getpid()

        sys.stdout.flush()
        sys.stderr.flush()

        stdout_path = self.log_dir / "monitor.out.log"
        stderr_path = self.log_dir / "monitor.err.log"

        with open("/dev/null", "r") as devnull:
            os.dup2(devnull.fileno(), sys.stdin.fileno())
        with open(stdout_path, "a") as f:
            os.dup2(f.fileno(), sys.stdout.fileno())
        with open(stderr_path, "a") as f:
            os.dup2(f.fileno(), sys.stderr.fileno())

        self._write_pid()

        def handle_term(signum, frame):
            self._remove_pid()
            sys.exit(0)

        signal.signal(signal.SIGTERM, handle_term)
        signal.signal(signal.SIGINT, handle_term)

        try:
            target_func(*args, **kwargs)
        finally:
            self._remove_pid()

        return child_pid

    def stop(self, timeout: int = 10) -> bool:
        if not self.is_running():
            self._remove_pid()
            return True

        pid = self.get_pid()
        if not pid:
            return True

        logger.info(f"停止监控进程 PID={pid}...")

        if os.name == "nt":
            try:
                os.kill(pid, signal.CTRL_BREAK_EVENT)
            except OSError:
                try:
                    os.kill(pid, signal.SIGTERM)
                except OSError:
                    pass
        else:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass

        elapsed = 0
        while elapsed < timeout:
            if not self.is_running():
                self._remove_pid()
                logger.info("进程已停止")
                return True
            time.sleep(1)
            elapsed += 1

        if self.is_running():
            logger.warning(f"进程未优雅停止，强制杀死 PID={pid}")
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            time.sleep(1)

        self._remove_pid()
        return True

    def status(self) -> dict:
        running = self.is_running()
        pid = self.get_pid() if running else None
        return {
            "running": running,
            "pid": pid,
            "pid_file": str(self.pid_file),
            "log_dir": str(self.log_dir),
        }
