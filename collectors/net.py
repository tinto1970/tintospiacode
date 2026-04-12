"""
Network reachability collector.

For each configured host performs one or more checks:
  - ping   : ICMP echo via system ping (exit code 0 = OK)
  - http   : TCP connect to port 80
  - https  : TCP connect to port 443
  - ssh    : TCP connect to port 22
  - <any>  : can also specify a custom port via {"type": "tcp", "port": 1234}

Status values: "ok" | "ko"
"""

import logging
import re
import socket
import subprocess
import time

logger = logging.getLogger(__name__)

DEFAULT_PORTS = {
    "http":  80,
    "https": 443,
    "ssh":   22,
    "ftp":   21,
    "smtp":  25,
    "dns":   53,
    "rdp":   3389,
}


class NetCollector:
    def __init__(self, config: dict):
        self.hosts = config.get("hosts", [])
        self.timeout = int(config.get("timeout", 3))

    def collect(self) -> dict:
        logger.info("Net: starting collection for %d hosts", len(self.hosts))
        results = []
        for host_cfg in self.hosts:
            host = host_cfg["host"]
            name = host_cfg.get("name", host)
            checks_cfg = host_cfg.get("checks", ["ping"])

            checks = []
            for c in checks_cfg:
                if isinstance(c, str):
                    check_type = c
                    port = DEFAULT_PORTS.get(check_type)
                else:
                    check_type = c.get("type", "tcp")
                    port = c.get("port", DEFAULT_PORTS.get(check_type))

                check_result = self._run_check(host, check_type, port)
                checks.append(check_result)
                logger.debug(
                    "Net: %s %s → %s (%s)",
                    host, check_type, check_result["status"], check_result.get("detail", ""),
                )

            results.append({"name": name, "host": host, "checks": checks})

        return {"hosts": results}

    def _run_check(self, host: str, check_type: str, port: int | None) -> dict:
        if check_type == "ping":
            return self._check_ping(host)
        port = port or DEFAULT_PORTS.get(check_type)
        if port:
            return self._check_tcp(host, check_type, port)
        return {"type": check_type, "status": "ko", "detail": "unknown check type"}

    def _check_ping(self, host: str) -> dict:
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(self.timeout), host],
                capture_output=True,
                timeout=self.timeout + 3,
            )
            if result.returncode == 0:
                m = re.search(rb"time=(\d+\.?\d*)", result.stdout)
                detail = f"{float(m.group(1)):.1f} ms" if m else ""
                return {"type": "ping", "status": "ok", "detail": detail}
            return {"type": "ping", "status": "ko", "detail": "no response"}
        except subprocess.TimeoutExpired:
            return {"type": "ping", "status": "ko", "detail": "timeout"}
        except Exception as exc:
            return {"type": "ping", "status": "ko", "detail": str(exc)[:60]}

    def _check_tcp(self, host: str, check_type: str, port: int) -> dict:
        try:
            t0 = time.monotonic()
            with socket.create_connection((host, port), timeout=self.timeout):
                rtt = int((time.monotonic() - t0) * 1000)
            return {"type": check_type, "port": port, "status": "ok", "detail": f"{rtt} ms"}
        except ConnectionRefusedError:
            return {"type": check_type, "port": port, "status": "ko", "detail": "refused"}
        except socket.timeout:
            return {"type": check_type, "port": port, "status": "ko", "detail": "timeout"}
        except OSError as exc:
            return {"type": check_type, "port": port, "status": "ko", "detail": str(exc)[:60]}
