#!/usr/bin/env python3

import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional, Tuple

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from ssl_manager.checker.parser import CertificateParser
from ssl_manager.checker.ssl_client import SSLClient
from ssl_manager.checker.validator import CertificateValidator, CertStatus
from ssl_manager.config.loader import load_config
from ssl_manager.config.schema import AppConfig, DomainConfig
from ssl_manager.deployer.apache_deployer import ApacheDeployer
from ssl_manager.deployer.nginx_deployer import NginxDeployer
from ssl_manager.notifier.alerter import Alerter
from ssl_manager.notifier.scheduler import run_monitor
from ssl_manager.renewer.acme_client import ACMEClient, ACMEClientError
from ssl_manager.renewer.certificate_saver import CertificateSaver
from ssl_manager.renewer.challenger import Challenger
from ssl_manager.utils.daemon import DaemonManager
from ssl_manager.utils.dns_provider import (
    create_dns_provider,
    DNSProviderError,
)
from ssl_manager.utils.logger import logger

console = Console()


def scan_single_domain(domain_config, ssl_client: SSLClient, parser: CertificateParser, validator: CertificateValidator):
    domain = domain_config.domain
    port = domain_config.port

    try:
        cert_der = ssl_client.get_certificate(domain, port)
        if not cert_der:
            return {
                "domain": domain,
                "cert_info": None,
                "status": CertStatus.UNKNOWN,
                "error": "无法获取证书",
            }

        cert_info = parser.parse_der(cert_der)
        status = validator.validate(cert_info)

        return {
            "domain": domain,
            "cert_info": cert_info,
            "status": status,
            "error": None,
        }
    except Exception as e:
        return {
            "domain": domain,
            "cert_info": None,
            "status": CertStatus.UNKNOWN,
            "error": str(e),
        }


def check_all_domains(config: AppConfig, show_progress: bool = True) -> list:
    ssl_client = SSLClient(timeout=config.timeout, proxy=config.proxy)
    parser = CertificateParser()
    validator = CertificateValidator(
        warning_days=config.notifier.threshold.warning_days,
        critical_days=config.notifier.threshold.critical_days,
    )

    results = []
    total = len(config.domains)

    if show_progress:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("扫描证书...", total=total)

            with ThreadPoolExecutor(max_workers=config.max_workers) as executor:
                future_to_domain = {
                    executor.submit(scan_single_domain, dc, ssl_client, parser, validator): dc
                    for dc in config.domains
                }

                for future in as_completed(future_to_domain):
                    domain_config = future_to_domain[future]
                    try:
                        result = future.result()
                        results.append(result)
                        progress.update(task, advance=1, description=f"扫描中: {result['domain']}")
                    except Exception as e:
                        results.append({
                            "domain": domain_config.domain,
                            "cert_info": None,
                            "status": CertStatus.UNKNOWN,
                            "error": str(e),
                        })
                        progress.update(task, advance=1)
    else:
        with ThreadPoolExecutor(max_workers=config.max_workers) as executor:
            future_to_domain = {
                executor.submit(scan_single_domain, dc, ssl_client, parser, validator): dc
                for dc in config.domains
            }
            for future in as_completed(future_to_domain):
                try:
                    results.append(future.result())
                except Exception as e:
                    domain_config = future_to_domain[future]
                    results.append({
                        "domain": domain_config.domain,
                        "cert_info": None,
                        "status": CertStatus.UNKNOWN,
                        "error": str(e),
                    })

    return sorted(results, key=lambda x: x["domain"])


def _get_domain_config(config: AppConfig, domain_name: str) -> Optional[DomainConfig]:
    for dc in config.domains:
        if dc.domain == domain_name:
            return dc
    return None


def _resolve_target_paths(config: AppConfig, domain_name: str, deploy_method: str) -> Tuple[str, str, str]:
    domain_cfg = _get_domain_config(config, domain_name)
    target_cert = domain_cfg.cert_path if domain_cfg else None
    target_key = domain_cfg.key_path if domain_cfg else None
    target_chain = ""

    if deploy_method == "nginx":
        deployer = NginxDeployer(
            nginx_bin=config.deploy.nginx.nginx_bin,
            reload_command=config.deploy.nginx.reload_command,
            backup_dir=config.deploy.backup_dir,
            backup_count=config.deploy.backup_count,
        )
        if not target_cert or not target_key:
            target_cert, target_key = deployer.get_cert_paths(domain_name)
    elif deploy_method == "apache":
        deployer = ApacheDeployer(
            apachectl_bin=config.deploy.apache.apachectl_bin,
            reload_command=config.deploy.apache.reload_command,
            backup_dir=config.deploy.backup_dir,
            backup_count=config.deploy.backup_count,
        )
        if not target_cert or not target_key:
            target_cert, target_key, target_chain = deployer.get_cert_paths(domain_name)

    return target_cert, target_key, target_chain


def _auto_deploy(config: AppConfig, domain_name: str, cert_result: dict) -> bool:
    domain_cfg = _get_domain_config(config, domain_name)
    deploy_method = domain_cfg.deploy_method if domain_cfg else None

    if not deploy_method:
        console.print(f"  [yellow]跳过自动部署: 域名 {domain_name} 未配置 deploy_method[/yellow]")
        return True

    console.print(f"\n  [cyan]自动部署证书到 {deploy_method}: {domain_name}[/cyan]")

    src_cert = cert_result["fullchain_path"]
    src_key = cert_result["key_path"]
    src_chain = cert_result.get("chain_path", "")

    target_cert, target_key, target_chain = _resolve_target_paths(config, domain_name, deploy_method)

    try:
        if deploy_method == "nginx":
            deployer = NginxDeployer(
                nginx_bin=config.deploy.nginx.nginx_bin,
                reload_command=config.deploy.nginx.reload_command,
                backup_dir=config.deploy.backup_dir,
                backup_count=config.deploy.backup_count,
            )
            success = deployer.deploy(domain_name, src_cert, src_key, target_cert, target_key)
        elif deploy_method == "apache":
            deployer = ApacheDeployer(
                apachectl_bin=config.deploy.apache.apachectl_bin,
                reload_command=config.deploy.apache.reload_command,
                backup_dir=config.deploy.backup_dir,
                backup_count=config.deploy.backup_count,
            )
            success = deployer.deploy(
                domain_name, src_cert, src_key, target_cert, target_key,
                src_chain, target_chain
            )
        else:
            console.print(f"  [yellow]未知部署方式: {deploy_method}，跳过[/yellow]")
            return False

        if success:
            console.print(f"  [green]部署成功: {deploy_method} 已热重载新证书[/green]")
        else:
            console.print(f"  [red]部署失败（已尝试回滚）: {deploy_method}[/red]")
            console.print(f"  [red]请检查日志 logs/ssl_manager.log 了解详细原因[/red]")
        return success

    except Exception as e:
        logger.error(f"自动部署 {domain_name} 到 {deploy_method} 失败: {e}")
        console.print(f"  [red]部署异常: {e}[/red]")
        return False


@click.group()
@click.option("--config", "-c", default="config.yaml", help="配置文件路径", type=click.Path())
@click.pass_context
def cli(ctx, config):
    """SSL 证书管理工具 - 扫描、告警、自动续期与部署"""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config
    try:
        ctx.obj["config"] = load_config(config)
    except FileNotFoundError:
        ctx.obj["config"] = None


@cli.command()
@click.option("--domain", "-d", help="检查单个域名（覆盖配置文件）")
@click.option("--port", "-p", default=443, help="端口号", type=int)
@click.option("--no-progress", is_flag=True, help="不显示进度条")
@click.option("--alert", "-a", is_flag=True, help="触发告警通知")
@click.pass_context
def check(ctx, domain, port, no_progress, alert):
    """检查域名 SSL 证书有效期"""
    config: AppConfig = ctx.obj.get("config")

    if domain:
        single_kwargs = dict(
            domains=[DomainConfig(domain=domain, port=port)],
            timeout=config.timeout if config else 10,
            max_workers=config.max_workers if config else 5,
            proxy=config.proxy if config else None,
        )
        if config and config.notifier:
            single_kwargs["notifier"] = config.notifier

        single_config = AppConfig(**single_kwargs)
        config = single_config
    elif config is None:
        click.echo("错误: 配置文件不存在，请使用 -c 指定配置文件或使用 -d 指定域名", err=True)
        sys.exit(1)

    results = check_all_domains(config, show_progress=not no_progress)

    alerter = Alerter(
        webhooks=config.notifier.webhooks if config.notifier else [],
        warning_days=config.notifier.threshold.warning_days if config.notifier else 30,
        critical_days=config.notifier.threshold.critical_days if config.notifier else 7,
    )

    alerter.print_summary_table(results)

    if alert:
        for result in results:
            if result["cert_info"] and result["status"] in (CertStatus.WARNING, CertStatus.CRITICAL, CertStatus.EXPIRED):
                alerter.alert_if_needed(result["domain"], result["cert_info"])

    warning_count = sum(1 for r in results if r["status"] == CertStatus.WARNING)
    critical_count = sum(1 for r in results if r["status"] == CertStatus.CRITICAL)
    expired_count = sum(1 for r in results if r["status"] == CertStatus.EXPIRED)

    console.print(f"\n总计: {len(results)} 个域名, "
                  f"[green]正常: {len(results) - warning_count - critical_count - expired_count}[/green], "
                  f"[yellow]警告: {warning_count}[/yellow], "
                  f"[red]紧急: {critical_count}[/red], "
                  f"[magenta]过期: {expired_count}[/magenta]")

    if critical_count > 0 or expired_count > 0:
        sys.exit(1)


@cli.command()
@click.option("--domain", "-d", help="续期指定域名（覆盖配置文件）")
@click.option("--force", "-f", is_flag=True, help="强制续期，忽略剩余有效期")
@click.option("--staging", is_flag=True, help="使用 Let's Encrypt 测试环境")
@click.option("--no-deploy", is_flag=True, help="续期成功后不自动部署")
@click.pass_context
def renew(ctx, domain, force, staging, no_deploy):
    """使用 ACME 协议自动续期证书（续期成功后按配置自动部署）"""
    config: AppConfig = ctx.obj.get("config")
    if config is None:
        click.echo("错误: 配置文件不存在", err=True)
        sys.exit(1)

    if not config.acme:
        console.print("[red]错误: 未配置 ACME 信息，请在 config.yaml 的 acme 段填写目录 URL、邮箱、DNS 服务商等[/red]")
        sys.exit(1)

    domains_to_renew = []
    if domain:
        domains_to_renew = [domain]
    else:
        if not force:
            console.print("[cyan]扫描证书有效期，筛选需要续期的域名...[/cyan]")
            results = check_all_domains(config, show_progress=False)
            for result in results:
                if result["cert_info"]:
                    days = result["cert_info"].days_remaining
                    if days is not None and days < config.notifier.threshold.warning_days:
                        domains_to_renew.append(result["domain"])
                else:
                    console.print(f"  [yellow]无法获取 {result['domain']} 证书信息，跳过自动续期[/yellow]")
        else:
            domains_to_renew = [dc.domain for dc in config.domains if dc.auto_renew]

    if not domains_to_renew:
        console.print("[green]所有域名证书有效期充足，无需续期[/green]")
        return

    console.print(f"[cyan]需要续期的域名: {', '.join(domains_to_renew)}[/cyan]")

    acme_config = config.acme
    acme_client = ACMEClient(
        directory_url=acme_config.directory_url,
        email=acme_config.email,
        account_key_path=acme_config.account_key_path,
        staging=staging or acme_config.staging,
    )

    try:
        acme_client.initialize()
    except ACMEClientError as e:
        console.print(f"[red]ACME 初始化失败: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        logger.error(f"ACME 初始化异常: {e}")
        console.print(f"[red]ACME 初始化失败: {e}[/red]")
        sys.exit(1)

    if not acme_config.dns_provider:
        console.print("[red]错误: 未配置 DNS 服务商，请在 config.yaml 的 acme.dns_provider 填写 type 和 config[/red]")
        sys.exit(1)

    try:
        dns_provider = create_dns_provider(
            acme_config.dns_provider.type,
            **acme_config.dns_provider.config,
        )
    except (DNSProviderError, ValueError) as e:
        console.print(f"[red]DNS 服务商配置错误: {e}[/red]")
        sys.exit(1)

    dns_provider_type = acme_config.dns_provider.type
    challenger = Challenger(acme_client, dns_provider)
    saver = CertificateSaver()

    renew_success = 0
    deploy_success = 0
    deploy_skip = 0

    for domain_name in domains_to_renew:
        console.print(f"\n{'=' * 50}")
        console.print(f"[cyan]开始续期: {domain_name}[/cyan]")

        cert_result = None

        try:
            cert_domains = [domain_name]
            if domain_name.startswith("*."):
                base_domain = domain_name[2:]
                cert_domains.append(base_domain)

            order = acme_client.new_order(cert_domains)

            if not challenger.perform_dns_challenges(order):
                console.print(f"[red]域名 {domain_name} DNS-01 验证失败[/red]")
                console.print(f"  DNS 服务商: {dns_provider_type}")
                console.print(f"  请检查 DNS 服务商凭据、SDK 安装、以及域名是否在该服务商管理下")
                console.print(f"  详细错误见日志 logs/ssl_manager.log")
                continue

            order = acme_client.poll_for_status(order["order_url"], "ready")
            finalize_url = order["finalize"]

            existing_key = saver.load_existing_key(domain_name)
            csr_pem, key_pem = saver.generate_csr(
                cert_domains,
                key_path=None if not existing_key else str(Path(saver.output_dir) / domain_name / "privkey.pem"),
            )

            acme_client.finalize_order(finalize_url, csr_pem)
            order = acme_client.poll_for_status(order["order_url"], "valid")

            cert_url = order["certificate"]
            fullchain_pem = acme_client.download_certificate(cert_url)

            parsed = saver.parse_certificate_chain(fullchain_pem)
            cert_result = saver.save_certificate(
                domain_name,
                parsed["cert"],
                key_pem,
                parsed["chain"],
            )

            renew_success += 1
            console.print(f"[green]证书续期成功: {domain_name}[/green]")
            console.print(f"  证书路径: {cert_result['cert_path']}")
            console.print(f"  私钥路径: {cert_result['key_path']}")

        except DNSProviderError as e:
            console.print(f"[red]DNS 操作失败（{domain_name}）[/red]")
            console.print(f"  DNS 服务商: {dns_provider_type}")
            console.print(f"  失败原因: {e}")
            continue
        except ACMEClientError as e:
            console.print(f"[red]ACME 错误（{domain_name}）: {e}[/red]")
            continue
        except Exception as e:
            logger.error(f"续期域名 {domain_name} 失败: {e}", exc_info=True)
            console.print(f"[red]续期失败 {domain_name}: {e}[/red]")
            continue

        if no_deploy:
            deploy_skip += 1
            console.print(f"  [yellow]--no-deploy 已指定，跳过自动部署[/yellow]")
            continue

        if cert_result:
            if _auto_deploy(config, domain_name, cert_result):
                deploy_success += 1

    console.print(f"\n{'=' * 50}")
    console.print(f"[bold]续期完成:[/bold] 续期成功 {renew_success}/{len(domains_to_renew)}")
    if not no_deploy:
        console.print(f"[bold]部署完成:[/bold] 部署成功 {deploy_success}/{renew_success}, 跳过 {deploy_skip}")

    if renew_success == 0:
        sys.exit(1)


@cli.command()
@click.option("--domain", "-d", required=True, help="部署指定域名的证书")
@click.option("--cert", required=True, help="证书文件路径", type=click.Path(exists=True))
@click.option("--key", required=True, help="私钥文件路径", type=click.Path(exists=True))
@click.option("--chain", default="", help="证书链文件路径（可选）")
@click.option("--method", "-m", type=click.Choice(["nginx", "apache"]), help="部署方式")
@click.pass_context
def deploy(ctx, domain, cert, key, chain, method):
    """部署证书到 Nginx 或 Apache（备份+替换+测试+热重载+回滚）"""
    config: AppConfig = ctx.obj.get("config")
    if config is None:
        click.echo("错误: 配置文件不存在", err=True)
        sys.exit(1)

    deploy_method = method
    if not deploy_method:
        for dc in config.domains:
            if dc.domain == domain and dc.deploy_method:
                deploy_method = dc.deploy_method
                break

    if not deploy_method:
        console.print("[red]错误: 请指定部署方式 (--method nginx/apache) 或在 config.yaml 中配置 deploy_method[/red]")
        sys.exit(1)

    target_cert, target_key, target_chain = _resolve_target_paths(config, domain, deploy_method)

    console.print(f"[cyan]部署到 {deploy_method}: {domain}[/cyan]")
    console.print(f"  源证书: {cert}")
    console.print(f"  源私钥: {key}")
    console.print(f"  目标证书: {target_cert}")
    console.print(f"  目标私钥: {target_key}")

    if deploy_method == "nginx":
        deployer = NginxDeployer(
            nginx_bin=config.deploy.nginx.nginx_bin,
            reload_command=config.deploy.nginx.reload_command,
            backup_dir=config.deploy.backup_dir,
            backup_count=config.deploy.backup_count,
        )

        success = deployer.deploy(domain, cert, key, target_cert, target_key)
        if success:
            console.print(f"[green]Nginx 证书部署成功（已备份旧证书 + 热重载）: {domain}[/green]")
        else:
            console.print(f"[red]Nginx 证书部署失败（已尝试回滚）: {domain}[/red]")
            console.print(f"[red]请检查日志 logs/ssl_manager.log 或运行 `nginx -t` 诊断问题[/red]")
            sys.exit(1)

    elif deploy_method == "apache":
        deployer = ApacheDeployer(
            apachectl_bin=config.deploy.apache.apachectl_bin,
            reload_command=config.deploy.apache.reload_command,
            backup_dir=config.deploy.backup_dir,
            backup_count=config.deploy.backup_count,
        )

        success = deployer.deploy(domain, cert, key, target_cert, target_key, chain, target_chain or "")
        if success:
            console.print(f"[green]Apache 证书部署成功（已备份旧证书 + 热重载）: {domain}[/green]")
        else:
            console.print(f"[red]Apache 证书部署失败（已尝试回滚）: {domain}[/red]")
            console.print(f"[red]请检查日志 logs/ssl_manager.log 或运行 `apachectl configtest` 诊断问题[/red]")
            sys.exit(1)


@cli.command()
@click.option("--daemon", "action", flag_value="start", help="启动后台监控进程")
@click.option("--stop", "action", flag_value="stop", help="停止后台监控进程")
@click.option("--status", "action", flag_value="status", help="查看后台监控进程状态")
@click.option("--restart", "action", flag_value="restart", help="重启后台监控进程")
@click.option("--once", "action", flag_value="once", help="只检查一次，不进入循环")
@click.option("--foreground", "action", flag_value="foreground", default=True, help="前台运行（默认）")
@click.option("--daemon-worker", "action", flag_value="worker", hidden=True, help="内部使用：守护子进程入口")
@click.pass_context
def monitor(ctx, action):
    """定时监控证书有效期（支持后台守护进程模式）"""
    config: AppConfig = ctx.obj.get("config")
    config_path = ctx.obj["config_path"]

    daemon = DaemonManager(pid_file="./data/ssl_manager.pid", log_dir="./logs")

    if action == "status":
        st = daemon.status()
        if st["running"]:
            console.print(f"[green]监控进程运行中[/green]")
            console.print(f"  PID: {st['pid']}")
            console.print(f"  PID 文件: {st['pid_file']}")
            console.print(f"  日志目录: {st['log_dir']}")
        else:
            console.print(f"[yellow]监控进程未运行[/yellow]")
            console.print(f"  PID 文件: {st['pid_file']}")
            console.print(f"  日志目录: {st['log_dir']}")
        return

    if action == "stop":
        console.print("[cyan]正在停止监控进程...[/cyan]")
        if daemon.stop():
            console.print("[green]监控进程已停止[/green]")
        else:
            console.print("[red]停止失败，请手动检查[/red]")
            sys.exit(1)
        return

    if config is None:
        click.echo("错误: 配置文件不存在", err=True)
        sys.exit(1)

    if action == "restart":
        console.print("[cyan]重启监控进程...[/cyan]")
        if daemon.is_running():
            daemon.stop()
        action = "start"

    alerter = Alerter(
        webhooks=config.notifier.webhooks,
        warning_days=config.notifier.threshold.warning_days,
        critical_days=config.notifier.threshold.critical_days,
    )

    def check_and_alert():
        log_file = Path("./logs/monitor_console.log")
        log_file.parent.mkdir(parents=True, exist_ok=True)
        non_console = Console(file=open(str(log_file), "a", encoding="utf-8"))
        non_console.print(f"\n=== 开始定时检查 ({time.strftime('%Y-%m-%d %H:%M:%S')}) ===")
        results = check_all_domains(config, show_progress=False)
        alerter.print_summary_table(results)

        for result in results:
            if result["cert_info"]:
                alerter.alert_if_needed(result["domain"], result["cert_info"])

        warning_count = sum(1 for r in results if r["status"] == CertStatus.WARNING)
        critical_count = sum(1 for r in results if r["status"] == CertStatus.CRITICAL)
        expired_count = sum(1 for r in results if r["status"] == CertStatus.EXPIRED)
        non_console.print(
            f"本次检查: 警告 {warning_count}, "
            f"紧急 {critical_count}, 过期 {expired_count}"
        )

    def run_foreground():
        console.print(f"[cyan]启动监控模式（前台运行）[/cyan]")
        console.print(f"  每日检查时间: {config.monitor.check_time}")
        if config.monitor.check_interval_hours:
            console.print(f"  检查间隔: 每 {config.monitor.check_interval_hours} 小时")
        console.print(f"  按 Ctrl+C 停止\n")
        run_monitor(
            check_time=config.monitor.check_time,
            check_func=check_and_alert,
            daemon=False,
            check_interval_hours=config.monitor.check_interval_hours,
        )

    if action == "once":
        check_and_alert()
        return

    if action == "worker":
        daemon._write_pid()

        def handle_term(signum, frame):
            daemon._remove_pid()
            sys.exit(0)

        import signal as sig_module
        sig_module.signal(sig_module.SIGTERM, handle_term)
        sig_module.signal(sig_module.SIGINT, handle_term)

        try:
            check_and_alert()
            run_monitor(
                check_time=config.monitor.check_time,
                check_func=check_and_alert,
                daemon=True,
                check_interval_hours=config.monitor.check_interval_hours,
            )
        finally:
            daemon._remove_pid()
        return

    if action == "start":
        if daemon.is_running():
            existing_pid = daemon.get_pid()
            console.print(f"[yellow]监控进程已在运行 (PID={existing_pid})，使用 --restart 重启[/yellow]")
            sys.exit(0)

        console.print("[cyan]启动后台监控进程...[/cyan]")
        try:
            pid = daemon.start(config_path=config_path)
            console.print(f"[green]后台监控进程启动成功，PID={pid}[/green]")
            console.print(f"  查看状态: python -m ssl_manager.cli monitor --status")
            console.print(f"  停止进程: python -m ssl_manager.cli monitor --stop")
            console.print(f"  标准输出日志: logs/monitor.out.log")
            console.print(f"  标准错误日志: logs/monitor.err.log")
            console.print(f"  应用日志: logs/ssl_manager.log")
        except RuntimeError as e:
            console.print(f"[red]启动失败: {e}[/red]")
            sys.exit(1)
        return

    run_foreground()


@cli.command()
@click.option("--domain", "-d", help="查看指定域名的证书详情")
@click.pass_context
def info(ctx, domain):
    """显示证书详细信息"""
    config: AppConfig = ctx.obj.get("config")

    if domain:
        config = AppConfig(
            domains=[DomainConfig(domain=domain, port=443)],
            timeout=10,
            max_workers=1,
        )
    elif config is None:
        click.echo("错误: 配置文件不存在，请使用 -c 指定配置文件或使用 -d 指定域名", err=True)
        sys.exit(1)

    ssl_client = SSLClient(timeout=config.timeout, proxy=config.proxy)
    parser = CertificateParser()
    validator = CertificateValidator()

    for dc in config.domains:
        console.print(f"\n[cyan]=== {dc.domain}:{dc.port} ===[/cyan]")

        cert_der = ssl_client.get_certificate(dc.domain, dc.port)
        if not cert_der:
            console.print("[red]无法获取证书（可能是网络问题或域名未启用 SSL）[/red]")
            continue

        cert_info = parser.parse_der(cert_der)
        status = validator.validate(cert_info)
        status_color = validator.get_status_color(status)
        status_label = validator.get_status_label(status)

        console.print(f"  状态: [{status_color}]{status_label}[/{status_color}]")
        console.print(f"  通用名 (CN): {cert_info.cn}")
        console.print(f"  主题备用名 (SAN): {', '.join(cert_info.san) if cert_info.san else '无'}")
        console.print(f"  颁发者: {cert_info.issuer}")
        console.print(f"  序列号: {cert_info.serial_number}")
        console.print(f"  版本: {cert_info.version + 1}")
        console.print(f"  签名算法: {cert_info.signature_algorithm}")
        console.print(f"  公钥类型: {cert_info.public_key_type} {cert_info.public_key_bits} bits")
        console.print(f"  生效时间: {cert_info.not_before.strftime('%Y-%m-%d %H:%M:%S') if cert_info.not_before else '未知'}")
        console.print(f"  到期时间: {cert_info.not_after.strftime('%Y-%m-%d %H:%M:%S') if cert_info.not_after else '未知'}")
        console.print(f"  剩余天数: {cert_info.days_remaining if cert_info.days_remaining is not None else '未知'} 天")


def main():
    cli()


if __name__ == "__main__":
    main()
