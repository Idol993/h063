#!/usr/bin/env python3
"""SSL 证书管理命令行工具"""

import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from ssl_manager.checker.parser import CertificateParser
from ssl_manager.checker.ssl_client import SSLClient
from ssl_manager.checker.validator import CertificateValidator, CertStatus
from ssl_manager.config.loader import load_config
from ssl_manager.config.schema import AppConfig
from ssl_manager.deployer.apache_deployer import ApacheDeployer
from ssl_manager.deployer.nginx_deployer import NginxDeployer
from ssl_manager.notifier.alerter import Alerter
from ssl_manager.notifier.scheduler import run_monitor
from ssl_manager.renewer.acme_client import ACMEClient
from ssl_manager.renewer.certificate_saver import CertificateSaver
from ssl_manager.renewer.challenger import Challenger
from ssl_manager.utils.dns_provider import create_dns_provider
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
        from ssl_manager.config.schema import DomainConfig, NotifierConfig

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
@click.pass_context
def renew(ctx, domain, force, staging):
    """使用 ACME 协议自动续期证书"""
    config: AppConfig = ctx.obj.get("config")
    if config is None:
        click.echo("错误: 配置文件不存在", err=True)
        sys.exit(1)

    if not config.acme:
        click.echo("错误: 未配置 ACME 信息", err=True)
        sys.exit(1)

    domains_to_renew = []
    if domain:
        domains_to_renew = [domain]
    else:
        if not force:
            results = check_all_domains(config, show_progress=False)
            for result in results:
                if result["cert_info"]:
                    days = result["cert_info"].days_remaining
                    if days is not None and days < config.notifier.threshold.warning_days:
                        domains_to_renew.append(result["domain"])
        else:
            domains_to_renew = [dc.domain for dc in config.domains if dc.auto_renew]

    if not domains_to_renew:
        console.print("[green]所有域名证书有效期充足，无需续期[/green]")
        return

    console.print(f"需要续期的域名: {', '.join(domains_to_renew)}")

    acme_config = config.acme
    acme_client = ACMEClient(
        directory_url=acme_config.directory_url,
        email=acme_config.email,
        account_key_path=acme_config.account_key_path,
        staging=staging or acme_config.staging,
    )

    try:
        acme_client.initialize()
    except Exception as e:
        logger.error(f"ACME 初始化失败: {e}")
        console.print(f"[red]ACME 初始化失败: {e}[/red]")
        sys.exit(1)

    if not acme_config.dns_provider:
        console.print("[red]错误: 未配置 DNS 服务商，无法进行 DNS-01 验证[/red]")
        sys.exit(1)

    dns_provider = create_dns_provider(
        acme_config.dns_provider.type,
        **acme_config.dns_provider.config,
    )
    challenger = Challenger(acme_client, dns_provider)
    saver = CertificateSaver()

    success_count = 0

    for domain_name in domains_to_renew:
        try:
            console.print(f"\n[cyan]开始续期: {domain_name}[/cyan]")

            cert_domains = [domain_name]
            if domain_name.startswith("*."):
                base_domain = domain_name[2:]
                cert_domains.append(base_domain)

            order = acme_client.new_order(cert_domains)

            if not challenger.perform_dns_challenges(order):
                console.print(f"[red]域名 {domain_name} 验证失败[/red]")
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
            result = saver.save_certificate(
                domain_name,
                parsed["cert"],
                key_pem,
                parsed["chain"],
            )

            success_count += 1
            console.print(f"[green]证书续期成功: {domain_name}[/green]")
            console.print(f"  证书路径: {result['cert_path']}")
            console.print(f"  私钥路径: {result['key_path']}")

        except Exception as e:
            logger.error(f"续期域名 {domain_name} 失败: {e}")
            console.print(f"[red]续期失败 {domain_name}: {e}[/red]")

    console.print(f"\n续期完成: {success_count}/{len(domains_to_renew)} 成功")


@cli.command()
@click.option("--domain", "-d", required=True, help="部署指定域名的证书")
@click.option("--cert", required=True, help="证书文件路径", type=click.Path(exists=True))
@click.option("--key", required=True, help="私钥文件路径", type=click.Path(exists=True))
@click.option("--chain", default="", help="证书链文件路径", type=click.Path(exists=True))
@click.option("--method", "-m", type=click.Choice(["nginx", "apache"]), help="部署方式")
@click.pass_context
def deploy(ctx, domain, cert, key, chain, method):
    """部署证书到 Nginx 或 Apache"""
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
        console.print("[red]错误: 请指定部署方式 (--method nginx/apache)[/red]")
        sys.exit(1)

    target_cert = None
    target_key = None
    target_chain = None

    for dc in config.domains:
        if dc.domain == domain:
            target_cert = dc.cert_path
            target_key = dc.key_path
            break

    if deploy_method == "nginx":
        deployer = NginxDeployer(
            nginx_bin=config.deploy.nginx.nginx_bin,
            reload_command=config.deploy.nginx.reload_command,
            backup_dir=config.deploy.backup_dir,
            backup_count=config.deploy.backup_count,
        )

        if not target_cert or not target_key:
            target_cert, target_key = deployer.get_cert_paths(domain)

        success = deployer.deploy(domain, cert, key, target_cert, target_key)
        if success:
            console.print(f"[green]Nginx 证书部署成功: {domain}[/green]")
        else:
            console.print(f"[red]Nginx 证书部署失败: {domain}[/red]")
            sys.exit(1)

    elif deploy_method == "apache":
        deployer = ApacheDeployer(
            apachectl_bin=config.deploy.apache.apachectl_bin,
            reload_command=config.deploy.apache.reload_command,
            backup_dir=config.deploy.backup_dir,
            backup_count=config.deploy.backup_count,
        )

        if not target_cert or not target_key:
            target_cert, target_key, target_chain = deployer.get_cert_paths(domain)

        success = deployer.deploy(domain, cert, key, target_cert, target_key, chain, target_chain or "")
        if success:
            console.print(f"[green]Apache 证书部署成功: {domain}[/green]")
        else:
            console.print(f"[red]Apache 证书部署失败: {domain}[/red]")
            sys.exit(1)


@cli.command()
@click.option("--daemon", is_flag=True, help="以后台模式运行")
@click.option("--once", is_flag=True, help="只检查一次，不进入循环")
@click.pass_context
def monitor(ctx, daemon, once):
    """定时监控证书有效期"""
    config: AppConfig = ctx.obj.get("config")
    if config is None:
        click.echo("错误: 配置文件不存在", err=True)
        sys.exit(1)

    alerter = Alerter(
        webhooks=config.notifier.webhooks,
        warning_days=config.notifier.threshold.warning_days,
        critical_days=config.notifier.threshold.critical_days,
    )

    def check_and_alert():
        console.print(f"\n[cyan]=== 开始定时检查 ({time.strftime('%Y-%m-%d %H:%M:%S')}) ===[/cyan]")
        results = check_all_domains(config, show_progress=False)
        alerter.print_summary_table(results)

        for result in results:
            if result["cert_info"]:
                alerter.alert_if_needed(result["domain"], result["cert_info"])

        warning_count = sum(1 for r in results if r["status"] == CertStatus.WARNING)
        critical_count = sum(1 for r in results if r["status"] == CertStatus.CRITICAL)
        expired_count = sum(1 for r in results if r["status"] == CertStatus.EXPIRED)
        console.print(f"本次检查: [yellow]警告 {warning_count}[/yellow], "
                      f"[red]紧急 {critical_count}[/red], [magenta]过期 {expired_count}[/magenta]")

    if once:
        check_and_alert()
        return

    console.print(f"[cyan]启动监控模式，每日 {config.monitor.check_time} 检查[/cyan]")
    if daemon:
        console.print("[green]以后台模式运行[/green]")

    run_monitor(
        check_time=config.monitor.check_time,
        check_func=check_and_alert,
        daemon=daemon or True,
        check_interval_hours=config.monitor.check_interval_hours,
    )


@cli.command()
@click.option("--domain", "-d", help="查看指定域名的证书详情")
@click.pass_context
def info(ctx, domain):
    """显示证书详细信息"""
    config: AppConfig = ctx.obj.get("config")

    if domain:
        from ssl_manager.config.schema import DomainConfig

        config = AppConfig(
            domains=[DomainConfig(domain=domain, port=443)],
            timeout=10,
            max_workers=1,
        )
    elif config is None:
        click.echo("错误: 配置文件不存在", err=True)
        sys.exit(1)

    ssl_client = SSLClient(timeout=config.timeout, proxy=config.proxy)
    parser = CertificateParser()
    validator = CertificateValidator()

    for dc in config.domains:
        console.print(f"\n[cyan]=== {dc.domain}:{dc.port} ===[/cyan]")

        cert_der = ssl_client.get_certificate(dc.domain, dc.port)
        if not cert_der:
            console.print("[red]无法获取证书[/red]")
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
