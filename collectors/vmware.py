"""
VMware vCenter collector.
Uses the vCenter REST API (vSphere 7+).
Falls back to PowerCLI via pwsh if use_powercli is enabled.
"""

import json
import logging
import subprocess
import requests
import urllib3

logger = logging.getLogger(__name__)


class VMwareCollector:
    def __init__(self, config: dict):
        self.host = config["host"].rstrip("/")
        self.username = config["username"]
        self.password = config["password"]
        self.verify_ssl = config.get("verify_ssl", False)
        self.use_powercli = config.get("use_powercli", False)
        self._session_id = None

        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ------------------------------------------------------------------
    # Authentication (REST API)
    # ------------------------------------------------------------------

    def _login(self):
        url = f"{self.host}/api/session"
        resp = requests.post(
            url,
            auth=(self.username, self.password),
            verify=self.verify_ssl,
            timeout=30,
        )
        resp.raise_for_status()
        self._session_id = resp.json()
        logger.debug("VMware: authenticated successfully")

    def _headers(self) -> dict:
        return {"vmware-api-session-id": self._session_id}

    def _get(self, path: str, params: dict = None) -> dict | list:
        if not self._session_id:
            self._login()
        url = f"{self.host}/api/{path.lstrip('/')}"
        resp = requests.get(url, headers=self._headers(), params=params, verify=self.verify_ssl, timeout=30)
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # PowerCLI fallback
    # ------------------------------------------------------------------

    def _run_powercli(self, script: str) -> list:
        ps_script = f"""
        Import-Module VMware.PowerCLI -ErrorAction SilentlyContinue
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
        Connect-VIServer -Server '{self.host}' -User '{self.username}' -Password '{self.password}' | Out-Null
        {script}
        Disconnect-VIServer -Confirm:$false | Out-Null
        """
        result = subprocess.run(
            ["pwsh", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(f"PowerCLI error: {result.stderr}")
        return json.loads(result.stdout)

    # ------------------------------------------------------------------
    # Data collection
    # ------------------------------------------------------------------

    def collect(self) -> dict:
        logger.info("VMware: starting collection (powercli=%s)", self.use_powercli)
        try:
            if self.use_powercli:
                return self._collect_via_powercli()
            self._login()
            return {
                "hosts": self._collect_hosts(),
                "vms": self._collect_vms(),
                "datastores": self._collect_datastores(),
                "clusters": self._collect_clusters(),
            }
        except Exception as exc:
            logger.error("VMware: collection failed — %s", exc)
            return {"error": str(exc)}

    def _collect_hosts(self) -> list:
        raw = self._get("vcenter/host")
        hosts = []
        for h in raw:
            hosts.append({
                "host": h.get("host"),
                "name": h.get("name"),
                "connection_state": h.get("connection_state"),
                "power_state": h.get("power_state"),
            })
        logger.debug("VMware: collected %d hosts", len(hosts))
        return hosts

    def _collect_vms(self) -> list:
        raw = self._get("vcenter/vm")
        vms = []
        for v in raw:
            vms.append({
                "vm": v.get("vm"),
                "name": v.get("name"),
                "power_state": v.get("power_state"),
                "cpu_count": v.get("cpu_count"),
                "memory_size_mb": v.get("memory_size_MiB"),
            })
        logger.debug("VMware: collected %d VMs", len(vms))
        return vms

    def _collect_datastores(self) -> list:
        raw = self._get("vcenter/datastore")
        datastores = []
        for d in raw:
            datastores.append({
                "datastore": d.get("datastore"),
                "name": d.get("name"),
                "type": d.get("type"),
                "capacity_gb": round(d.get("capacity", 0) / 1024**3, 2),
                "free_space_gb": round(d.get("free_space", 0) / 1024**3, 2),
            })
        logger.debug("VMware: collected %d datastores", len(datastores))
        return datastores

    def _collect_clusters(self) -> list:
        raw = self._get("vcenter/cluster")
        clusters = []
        for c in raw:
            clusters.append({
                "cluster": c.get("cluster"),
                "name": c.get("name"),
                "drs_enabled": c.get("drs_enabled"),
                "ha_enabled": c.get("ha_enabled"),
                "resource_pool": c.get("resource_pool"),
            })
        logger.debug("VMware: collected %d clusters", len(clusters))
        return clusters

    def _collect_via_powercli(self) -> dict:
        script = r"""
        $vms = Get-VM | Select-Object Name, PowerState, NumCpu, MemoryMB, @{N='Host';E={$_.VMHost.Name}} | ConvertTo-Json -Depth 3
        $hosts = Get-VMHost | Select-Object Name, State, ConnectionState, CpuUsageMhz, CpuTotalMhz, MemoryUsageGB, MemoryTotalGB | ConvertTo-Json -Depth 3
        @{ vms = ($vms | ConvertFrom-Json); hosts = ($hosts | ConvertFrom-Json) } | ConvertTo-Json -Depth 5
        """
        return self._run_powercli(script)
