"""
Proxmox VE collector.
Uses the Proxmox REST API and SSH for sensors data.
"""

import json
import logging
import re
import requests
import urllib3

logger = logging.getLogger(__name__)


class ProxmoxCollector:
    def __init__(self, config: dict):
        self.host = config["host"].rstrip("/")
        self.username = config["username"]
        self.password = config["password"]
        self.verify_ssl = config.get("verify_ssl", False)
        self.ssh_host = config.get("ssh_host")       # hostname/IP for SSH (optional, falls back to API host)
        self.ssh_user = config.get("ssh_user", "root")
        self.ssh_password = config.get("ssh_password", self.password)
        self.ssh_port = config.get("ssh_port", 22)
        self._ticket = None
        self._csrf = None

        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def _login(self):
        url = f"{self.host}/api2/json/access/ticket"
        resp = requests.post(
            url,
            data={"username": self.username, "password": self.password},
            verify=self.verify_ssl,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()["data"]
        self._ticket = data["ticket"]
        self._csrf = data["CSRFPreventionToken"]
        logger.debug("Proxmox: authenticated successfully")

    def _get(self, path: str) -> dict | list:
        if not self._ticket:
            self._login()
        url = f"{self.host}/api2/json/{path.lstrip('/')}"
        resp = requests.get(
            url,
            cookies={"PVEAuthCookie": self._ticket},
            headers={"CSRFPreventionToken": self._csrf},
            verify=self.verify_ssl,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json().get("data", [])

    # ------------------------------------------------------------------
    # Data collection
    # ------------------------------------------------------------------

    def collect(self) -> dict:
        logger.info("Proxmox: starting collection")
        try:
            self._login()
            nodes = self._collect_nodes()
            vms = []
            containers = []
            storage = []
            sensors = []
            for node in nodes:
                node_name = node["node"]
                vms.extend(self._collect_vms(node_name))
                containers.extend(self._collect_containers(node_name))
                storage.extend(self._collect_storage(node_name))
                sensors.extend(self._collect_sensors(node_name))
            return {
                "nodes": nodes,
                "vms": vms,
                "containers": containers,
                "storage": storage,
                "sensors": sensors,
            }
        except Exception as exc:
            logger.error("Proxmox: collection failed — %s", exc)
            return {"error": str(exc)}

    # ------------------------------------------------------------------
    # SSH helpers
    # ------------------------------------------------------------------

    def _ssh_run(self, node_name: str, command: str) -> str:
        import paramiko
        # derive SSH host: use ssh_host if set, otherwise strip port from API host
        if self.ssh_host:
            host = self.ssh_host
        else:
            host = re.sub(r"^https?://", "", self.host).split(":")[0]

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                host, port=self.ssh_port,
                username=self.ssh_user, password=self.ssh_password,
                timeout=15, look_for_keys=False, allow_agent=False,
            )
            _, stdout, stderr = client.exec_command(command, timeout=15)
            out = stdout.read().decode()
            err = stderr.read().decode()
            if err:
                logger.debug("Proxmox SSH stderr on %s: %s", node_name, err.strip())
            return out
        finally:
            client.close()

    def _collect_sensors(self, node: str) -> list:
        try:
            out = self._ssh_run(node, "sensors -j 2>/dev/null")
            raw = json.loads(out)
        except Exception as exc:
            logger.warning("Proxmox sensors on %s failed — %s", node, exc)
            return []

        readings = []
        for chip, features in raw.items():
            if not isinstance(features, dict):
                continue
            for feature_name, feature_data in features.items():
                if not isinstance(feature_data, dict):
                    continue
                # look for temperature inputs (keys ending with _input)
                for key, value in feature_data.items():
                    if key.endswith("_input") and "temp" in key.lower() and value > 0:
                        readings.append({
                            "node": node,
                            "chip": chip,
                            "feature": feature_name,
                            "temp_c": round(value, 1),
                        })
        logger.debug("Proxmox: collected %d sensor readings on node %s", len(readings), node)
        return readings

    def _collect_nodes(self) -> list:
        raw = self._get("nodes")
        nodes = []
        for n in raw:
            nodes.append({
                "node": n.get("node"),
                "status": n.get("status"),
                "uptime": n.get("uptime"),
                "cpu_usage": round(n.get("cpu", 0) * 100, 1),
                "mem_used_gb": round(n.get("mem", 0) / 1024**3, 2),
                "mem_total_gb": round(n.get("maxmem", 0) / 1024**3, 2),
                "disk_used_gb": round(n.get("disk", 0) / 1024**3, 2),
                "disk_total_gb": round(n.get("maxdisk", 0) / 1024**3, 2),
            })
        logger.debug("Proxmox: collected %d nodes", len(nodes))
        return nodes

    def _collect_vms(self, node: str) -> list:
        raw = self._get(f"nodes/{node}/qemu")
        vms = []
        for v in raw:
            vms.append({
                "vmid": v.get("vmid"),
                "name": v.get("name"),
                "node": node,
                "status": v.get("status"),
                "cpu_usage": round(v.get("cpu", 0) * 100, 1),
                "mem_used_gb": round(v.get("mem", 0) / 1024**3, 2),
                "mem_total_gb": round(v.get("maxmem", 0) / 1024**3, 2),
                "disk_gb": round(v.get("disk", 0) / 1024**3, 2),
                "uptime": v.get("uptime"),
                "tags": v.get("tags", ""),
            })
        logger.debug("Proxmox: collected %d VMs on node %s", len(vms), node)
        return vms

    def _collect_containers(self, node: str) -> list:
        raw = self._get(f"nodes/{node}/lxc")
        containers = []
        for c in raw:
            containers.append({
                "vmid": c.get("vmid"),
                "name": c.get("name"),
                "node": node,
                "status": c.get("status"),
                "cpu_usage": round(c.get("cpu", 0) * 100, 1),
                "mem_used_gb": round(c.get("mem", 0) / 1024**3, 2),
                "mem_total_gb": round(c.get("maxmem", 0) / 1024**3, 2),
                "disk_gb": round(c.get("disk", 0) / 1024**3, 2),
                "uptime": c.get("uptime"),
                "tags": c.get("tags", ""),
            })
        logger.debug("Proxmox: collected %d containers on node %s", len(containers), node)
        return containers

    def _collect_storage(self, node: str) -> list:
        raw = self._get(f"nodes/{node}/storage")
        storage = []
        for s in raw:
            if s.get("active"):
                storage.append({
                    "storage": s.get("storage"),
                    "node": node,
                    "type": s.get("type"),
                    "total_gb": round(s.get("total", 0) / 1024**3, 2),
                    "used_gb": round(s.get("used", 0) / 1024**3, 2),
                    "avail_gb": round(s.get("avail", 0) / 1024**3, 2),
                    "enabled": s.get("enabled", 1) == 1,
                    "shared": s.get("shared", 0) == 1,
                    "content": s.get("content", ""),
                })
        logger.debug("Proxmox: collected %d storage entries on node %s", len(storage), node)
        return storage
