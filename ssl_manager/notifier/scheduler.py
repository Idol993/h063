import time
from typing import Callable, Optional

import schedule

from ssl_manager.utils.logger import logger


class TaskScheduler:
    def __init__(self):
        self.running = False

    def schedule_daily(self, time_str: str, task: Callable, *args, **kwargs):
        logger.info(f"设置每日定时任务: {time_str}")
        schedule.every().day.at(time_str).do(self._run_task, task, *args, **kwargs)

    def schedule_every_hours(self, hours: int, task: Callable, *args, **kwargs):
        logger.info(f"设置每 {hours} 小时执行一次的任务")
        schedule.every(hours).hours.do(self._run_task, task, *args, **kwargs)

    def schedule_every_minutes(self, minutes: int, task: Callable, *args, **kwargs):
        logger.info(f"设置每 {minutes} 分钟执行一次的任务")
        schedule.every(minutes).minutes.do(self._run_task, task, *args, **kwargs)

    def _run_task(self, task: Callable, *args, **kwargs):
        logger.info("开始执行定时任务")
        try:
            task(*args, **kwargs)
            logger.info("定时任务执行完成")
        except Exception as e:
            logger.error(f"定时任务执行失败: {e}")

    def run_once(self):
        schedule.run_pending()

    def run_forever(self, interval_seconds: int = 60):
        logger.info("定时调度器已启动，进入循环运行...")
        self.running = True
        while self.running:
            schedule.run_pending()
            time.sleep(interval_seconds)

    def stop(self):
        self.running = False
        logger.info("定时调度器已停止")

    def clear(self):
        schedule.clear()
        logger.info("已清除所有定时任务")

    def get_pending_jobs(self) -> list:
        return schedule.get_jobs()


def run_monitor(
    check_time: str,
    check_func: Callable,
    daemon: bool = False,
    check_interval_hours: Optional[int] = None,
):
    scheduler = TaskScheduler()

    if check_interval_hours:
        scheduler.schedule_every_hours(check_interval_hours, check_func)
    else:
        scheduler.schedule_daily(check_time, check_func)

    logger.info("立即执行一次检查...")
    check_func()

    if daemon:
        logger.info(f"以后台模式运行，每日 {check_time} 执行检查")
        try:
            scheduler.run_forever()
        except KeyboardInterrupt:
            scheduler.stop()
            logger.info("用户中断，退出监控模式")
    else:
        logger.info(f"已设置定时任务，每日 {check_time} 执行检查（非守护模式）")
        try:
            scheduler.run_forever()
        except KeyboardInterrupt:
            scheduler.stop()
            logger.info("用户中断，退出监控模式")
