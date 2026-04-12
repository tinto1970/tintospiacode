"""
OS monitoring collector.

Monitors disk usage and service/process status on remote hosts.

  type: windows  — WinRM (pywinrm, NTLM) + PowerShell script
  type: truenas  — TrueNAS SCALE/CORE REST API (HTTPS Basic auth)
  type: linux    — SSH (paramiko) + shell commands
"""

import json
import logging
import re

import requests
import urllib3

logger = logging.getLogger(__name__)


def _check_type(c) -> str:
    return c if isinstance(c, str) else c.get("type", "")


def _ps_str(s: str) -> str:
    """Escape a string for a single-quoted PowerShell literal."""
    return s.replace("'", "''")


class OSCollector:
    def __init__(self, config: dict):
        self.hosts   = config.get("hosts", [])
        self.timeout = int(config.get("timeout", 15))

    def collect(self) -> dict:
        logger.info("OS: collecting %d hosts", len(self.hosts))
        return {"hosts": [self._collect_host(h) for h in self.hosts]}

    # ------------------------------------------------------------------

    def _collect_host(self, cfg: dict) -> dict:
        name      = cfg.get("name", cfg["host"])
        host      = cfg["host"]
        host_type = cfg.get("type", "linux").lower()
        checks    = cfg.get("checks", [{"type": "disk"}])

        entry = {
            "name": name, "host": host, "type": host_type,
            "disk": [], "services": [], "processes": [], "error": None,
        }
        try:
            if host_type == "windows":
                self._collect_windows(cfg, checks, entry)
            elif host_type == "truenas":
                self._collect_truenas(cfg, checks, entry)
            else:
                self._collect_linux(cfg, checks, entry)
        except Exception as exc:
            logger.error("OS: %s (%s) — %s", name, host, exc)
            entry["error"] = str(exc)[:300]
        return entry

    # ------------------------------------------------------------------
    # Windows via WinRM
    # ------------------------------------------------------------------

    def _collect_windows(self, cfg: dict, checks: list, entry: dict):
        host     = cfg["host"]
        username = cfg["username"]
        password = cfg["password"]

        want_disk    = any(_check_type(c) == "disk"    for c in checks)
        svc_queries  = [c["name"] for c in checks if isinstance(c, dict) and _check_type(c) == "service"]
        proc_queries = [c["name"] for c in checks if isinstance(c, dict) and _check_type(c) == "process"]

        script = self._build_windows_script(want_disk, svc_queries, proc_queries)

        # Strategy 1: SSH to Windows (OpenSSH, port 22) — preferred when available
        ssh_port = int(cfg.get("ssh_port", 22))
        raw = self._windows_via_ssh(host, username, password, ssh_port, script)

        # Strategy 2: WinRM (NTLM, port 5985)
        if raw is None:
            raw = self._windows_via_winrm(host, username, password, script)

        if raw is None:
            raise RuntimeError(
                "Cannot connect to Windows host — SSH (port 22) and WinRM (port 5985) both failed. "
                "On the Windows machine run as Administrator: "
                "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0; "
                "Start-Service sshd; Set-Service sshd -StartupType Automatic"
            )

        for d in raw.get("disk") or []:
            entry["disk"].append({
                "mount":    d.get("mount", ""),
                "label":    d.get("label", ""),
                "total_gb": d.get("total_gb", 0),
                "used_gb":  d.get("used_gb",  0),
                "free_gb":  d.get("free_gb",  0),
                "pct_used": d.get("pct_used", 0),
            })

        for s in raw.get("services") or []:
            ok = s.get("found", False) and str(s.get("status", "")).lower() == "running"
            entry["services"].append({
                "name":    s.get("query", ""),
                "display": s.get("name",  ""),
                "status":  s.get("status", "NotFound"),
                "ok":      ok,
            })

        for p in raw.get("processes") or []:
            entry["processes"].append({
                "name":    p.get("query", ""),
                "running": bool(p.get("running", False)),
                "count":   int(p.get("count", 0)),
            })

    def _windows_via_ssh(self, host: str, username: str, password: str, port: int, script: str) -> dict | None:
        """Run PowerShell script via OpenSSH on Windows. Returns parsed dict or None."""
        import socket
        # Quick port check before attempting connect
        try:
            s = socket.create_connection((host, port), timeout=3)
            s.close()
        except OSError:
            return None

        import paramiko
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, port=port, username=username, password=password,
                           timeout=self.timeout, look_for_keys=False, allow_agent=False)
            try:
                # Encode script as base64 for reliable transmission
                import base64
                enc = base64.b64encode(script.encode("utf-16-le")).decode()
                cmd = f"powershell -NonInteractive -EncodedCommand {enc}"
                _, stdout, stderr = client.exec_command(cmd, timeout=self.timeout + 10)
                out = stdout.read().decode("utf-8", errors="replace")
                stdout.channel.recv_exit_status()
                return json.loads(out)
            finally:
                client.close()
        except Exception as exc:
            logger.debug("OS: %s SSH failed — %s", host, exc)
            return None

    def _windows_via_winrm(self, host: str, username: str, password: str, script: str) -> dict | None:
        """Run PowerShell script via WinRM (NTLM). Returns parsed dict or None."""
        try:
            import winrm
            session = winrm.Session(
                host,
                auth=(username, password),
                transport="ntlm",
                read_timeout_sec=self.timeout + 15,
                operation_timeout_sec=self.timeout + 10,
            )
            result = session.run_ps(script)
            if result.status_code != 0:
                err = result.std_err.decode("utf-8", errors="replace").strip()
                logger.debug("OS: %s WinRM PS exit %d — %s", host, result.status_code, err[:200])
                return None
            return json.loads(result.std_out.decode("utf-8", errors="replace"))
        except Exception as exc:
            logger.debug("OS: %s WinRM failed — %s", host, exc)
            return None

    def _build_windows_script(self, want_disk: bool, svc_queries: list, proc_queries: list) -> str:
        def ps_arr(lst):
            if not lst:
                return "@()"
            return "@(" + ", ".join(f"'{_ps_str(n)}'" for n in lst) + ")"

        disk_block = ""
        if want_disk:
            disk_block = """
$result.disk = @(Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | ForEach-Object {
    $total = [long]$_.Size; $free = [long]$_.FreeSpace
    [PSCustomObject]@{
        mount    = $_.DeviceID
        label    = $_.VolumeName
        total_gb = [math]::Round($total / 1GB, 1)
        used_gb  = [math]::Round(($total - $free) / 1GB, 1)
        free_gb  = [math]::Round($free / 1GB, 1)
        pct_used = if ($total -gt 0) { [math]::Round(($total - $free) / $total * 100) } else { 0 }
    }
})
"""

        return f"""$ErrorActionPreference = 'Continue'
$result = [PSCustomObject]@{{ disk = @(); services = @(); processes = @() }}
{disk_block}
$svcQueries = {ps_arr(svc_queries)}
foreach ($q in $svcQueries) {{
    $svc = Get-Service | Where-Object {{ $_.DisplayName -like "*$q*" -or $_.Name -like "*$q*" }} | Select-Object -First 1
    $result.services += [PSCustomObject]@{{
        query  = $q
        name   = if ($svc) {{ $svc.DisplayName }} else {{ $q }}
        status = if ($svc) {{ $svc.Status.ToString() }} else {{ 'NotFound' }}
        found  = [bool]$svc
    }}
}}

$procQueries = {ps_arr(proc_queries)}
foreach ($q in $procQueries) {{
    $safeName = $q -replace '\\.exe$', ''
    $procs = @(Get-Process | Where-Object {{ $_.Name -like "*$safeName*" }})
    $result.processes += [PSCustomObject]@{{
        query   = $q
        running = ($procs.Count -gt 0)
        count   = $procs.Count
    }}
}}

$result | ConvertTo-Json -Depth 4
"""

    # ------------------------------------------------------------------
    # TrueNAS REST API
    # ------------------------------------------------------------------

    def _collect_truenas(self, cfg: dict, checks: list, entry: dict):
        base     = f"https://{cfg['host']}"
        auth     = (cfg["username"], cfg["password"])
        ssl      = cfg.get("verify_ssl", False)

        if not ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        def get(path):
            r = requests.get(f"{base}/api/v2.0/{path}", auth=auth, verify=ssl, timeout=self.timeout)
            r.raise_for_status()
            return r.json()

        want_disk    = any(_check_type(c) == "disk"    for c in checks)
        want_service = any(_check_type(c) == "service" for c in checks)
        svc_names    = [c["name"] for c in checks if isinstance(c, dict) and _check_type(c) == "service" and "name" in c]

        if want_disk:
            pools = get("pool")
            for pool in pools:
                if not isinstance(pool, dict):
                    continue
                total = int(pool.get("size", 0))
                alloc = int(pool.get("allocated", 0))
                free  = int(pool.get("free", 0))
                entry["disk"].append({
                    "mount":    f"/{pool['name']}",
                    "label":    f"ZFS pool ({pool.get('status', '')})",
                    "total_gb": round(total / 1024**3, 1),
                    "used_gb":  round(alloc / 1024**3, 1),
                    "free_gb":  round(free  / 1024**3, 1),
                    "pct_used": round(alloc / total * 100) if total else 0,
                })

        if want_service:
            all_svcs = get("service")
            if svc_names:
                # filter to requested names
                all_svcs = [s for s in all_svcs if s.get("service", "") in svc_names]
            for s in all_svcs:
                ok = s.get("state", "") == "RUNNING"
                entry["services"].append({
                    "name":    s.get("service", ""),
                    "display": s.get("service", ""),
                    "status":  s.get("state", ""),
                    "ok":      ok,
                })
            logger.debug("OS TrueNAS: %d services", len(entry["services"]))

    # ------------------------------------------------------------------
    # Linux via SSH
    # ------------------------------------------------------------------

    def _collect_linux(self, cfg: dict, checks: list, entry: dict):
        import paramiko

        host     = cfg["host"]
        username = cfg["username"]
        password = cfg.get("password", "")
        port     = int(cfg.get("ssh_port", 22))
        ssh_key  = cfg.get("ssh_key", "")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kw = {"username": username, "timeout": self.timeout, "look_for_keys": bool(ssh_key), "allow_agent": False}
        if ssh_key:
            kw["key_filename"] = ssh_key
        if password:
            kw["password"] = password
        client.connect(host, port=port, **kw)

        try:
            want_disk    = any(_check_type(c) == "disk"    for c in checks)
            svc_queries  = [c["name"] for c in checks if isinstance(c, dict) and _check_type(c) == "service"]
            proc_queries = [c["name"] for c in checks if isinstance(c, dict) and _check_type(c) == "process"]

            if want_disk:
                entry["disk"] = self._linux_disk(client)
            for name in svc_queries:
                entry["services"].append(self._linux_service(client, name))
            for name in proc_queries:
                entry["processes"].append(self._linux_process(client, name))
        finally:
            client.close()

    def _ssh_cmd(self, client, cmd: str) -> str:
        _, stdout, _ = client.exec_command(cmd, timeout=self.timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        stdout.channel.recv_exit_status()
        return out

    def _linux_disk(self, client) -> list:
        out = self._ssh_cmd(client, "df -k 2>/dev/null")
        skip = {"tmpfs", "devtmpfs", "devfs", "procfs", "udev", "cgroup", "overlay", "shm", "none"}
        disks = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 6:
                continue
            fs = parts[0]
            if any(fs.startswith(s) for s in skip):
                continue
            try:
                total_kb = int(parts[1])
                used_kb  = int(parts[2])
                avail_kb = int(parts[3])
                pct      = int(parts[4].rstrip("%"))
                mount    = parts[5]
            except (ValueError, IndexError):
                continue
            if total_kb < 100 * 1024:  # skip < 100 MB
                continue
            disks.append({
                "mount":    mount,
                "label":    "",
                "total_gb": round(total_kb / 1024**2, 1),
                "used_gb":  round(used_kb  / 1024**2, 1),
                "free_gb":  round(avail_kb / 1024**2, 1),
                "pct_used": pct,
            })
        return disks

    def _linux_service(self, client, name: str) -> dict:
        out = self._ssh_cmd(client, f"systemctl is-active -- {name!r} 2>/dev/null || echo unknown")
        status = out.strip().splitlines()[0] if out.strip() else "unknown"
        return {"name": name, "display": name, "status": status, "ok": status == "active"}

    def _linux_process(self, client, name: str) -> dict:
        safe  = re.sub(r"[^a-zA-Z0-9._\- ]", "", name)
        out   = self._ssh_cmd(client, f"pgrep -c -f {safe!r} 2>/dev/null; true")
        try:
            count = int(out.strip().splitlines()[-1])
        except (ValueError, IndexError):
            count = 0
        return {"name": name, "running": count > 0, "count": count}
