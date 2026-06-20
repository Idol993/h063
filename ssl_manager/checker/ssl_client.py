import socket
import ssl
from datetime import datetime
from typing import Optional, Tuple


class SSLClient:
    def __init__(self, timeout: int = 10, proxy: Optional[str] = None):
        self.timeout = timeout
        self.proxy = proxy

    def get_certificate(self, hostname: str, port: int = 443) -> Optional[bytes]:
        try:
            if self.proxy:
                return self._get_cert_via_proxy(hostname, port)
            return self._get_cert_direct(hostname, port)
        except Exception as e:
            from ssl_manager.utils.logger import logger
            logger.error(f"获取 {hostname}:{port} 证书失败: {e}")
            return None

    def _get_cert_direct(self, hostname: str, port: int) -> Optional[bytes]:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                return cert_der

    def _get_cert_via_proxy(self, hostname: str, port: int) -> Optional[bytes]:
        from urllib.parse import urlparse

        proxy_url = urlparse(self.proxy)
        proxy_host = proxy_url.hostname
        proxy_port = proxy_url.port or 8080

        sock = socket.create_connection((proxy_host, proxy_port), timeout=self.timeout)
        sock.settimeout(self.timeout)

        connect_request = f"CONNECT {hostname}:{port} HTTP/1.1\r\nHost: {hostname}:{port}\r\n\r\n"
        sock.sendall(connect_request.encode())

        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        if b"200" not in response.split(b"\r\n")[0]:
            sock.close()
            raise ConnectionError(f"代理连接失败: {response.split(b'\r\n')[0].decode(errors='ignore')}")

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
            return cert_der

    def get_certificate_chain(self, hostname: str, port: int = 443) -> Optional[Tuple[bytes, ...]]:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_chain = ssock.getpeercert(binary_form=True)
                    return (cert_chain,) if cert_chain else None
        except Exception as e:
            from ssl_manager.utils.logger import logger
            logger.error(f"获取 {hostname}:{port} 证书链失败: {e}")
            return None
