"""
Hugo data file generator.
Writes collected data as JSON files into the Hugo site's data/ directory.
"""

import json
import logging
import os
import subprocess
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class HugoGenerator:
    def __init__(self, site_path: str):
        self.site_path = site_path
        self.data_path = os.path.join(site_path, "data")

    def _write(self, relative_path: str, data):
        full_path = os.path.join(self.data_path, relative_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        logger.debug("Hugo: wrote %s", full_path)

    def _code_build_info(self) -> dict:
        """Return commit count and short SHA of the tintospiacode repository."""
        code_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        try:
            count = subprocess.run(
                ["git", "rev-list", "--count", "HEAD"],
                cwd=code_path, capture_output=True, text=True, check=True,
            ).stdout.strip()
            sha = subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=code_path, capture_output=True, text=True, check=True,
            ).stdout.strip()
            return {"number": int(count), "sha": sha}
        except Exception as exc:
            logger.warning("Hugo: could not read code repo build info — %s", exc)
            return {"number": 0, "sha": ""}

    def generate(self, results: dict):
        logger.info("Hugo: generating data files")

        if "veeam" in results:
            self._write("veeam/server_info.json", {"host": results["veeam"].get("host", "")})
            self._write("veeam/jobs.json", results["veeam"].get("jobs", []))
            self._write("veeam/sessions.json", results["veeam"].get("sessions", []))
            self._write("veeam/repositories.json", results["veeam"].get("repositories", []))
            self._write("veeam/managed_servers.json", results["veeam"].get("managed_servers", []))

        if "proxmox" in results:
            self._write("proxmox/nodes.json", results["proxmox"].get("nodes", []))
            self._write("proxmox/vms.json", results["proxmox"].get("vms", []))
            self._write("proxmox/containers.json", results["proxmox"].get("containers", []))
            self._write("proxmox/storage.json", results["proxmox"].get("storage", []))
            self._write("proxmox/sensors.json", results["proxmox"].get("sensors", []))

        if "esxi" in results:
            self._write("vmware/esxi_hosts.json", results["esxi"].get("hosts", []))

        if "paloalto" in results:
            self._write("paloalto/server_info.json", {"host": results["paloalto"].get("host", "")})
            self._write("paloalto/environmentals.json", results["paloalto"].get("environmentals", {}))
            self._write("paloalto/system_info.json", results["paloalto"].get("system_info", {}))
            self._write("paloalto/interfaces.json", results["paloalto"].get("interfaces", []))
            self._write("paloalto/sessions.json", results["paloalto"].get("sessions", {}))
            self._write("paloalto/routing.json", results["paloalto"].get("routing", {}))
            self._write("paloalto/ha_state.json", results["paloalto"].get("ha_state", {}))
            self._write("paloalto/licenses.json", results["paloalto"].get("licenses", []))
            self._write("paloalto/tasks.json", results["paloalto"].get("tasks", []))
            self._write("paloalto/security_policy.json", results["paloalto"].get("security_policy", []))

        if "net" in results:
            self._write("net/hosts.json", results["net"].get("hosts", []))

        if "os" in results:
            self._write("os/hosts.json", results["os"].get("hosts", []))

        self._write("meta/last_update.json", {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "sources": list(results.keys()),
        })
        self._write("meta/build.json", self._code_build_info())

        logger.info("Hugo: data files written successfully")

    def generate_demo(self, results: dict, demo_site_path: str):
        """Write the subset of data needed by the demo site (Veeam, Proxmox, VMware only)."""
        demo_generator = HugoGenerator(demo_site_path)

        if "veeam" in results:
            demo_generator._write("veeam/server_info.json", {"host": results["veeam"].get("host", "")})
            demo_generator._write("veeam/jobs.json", results["veeam"].get("jobs", []))
            demo_generator._write("veeam/sessions.json", results["veeam"].get("sessions", []))
            demo_generator._write("veeam/repositories.json", results["veeam"].get("repositories", []))
            demo_generator._write("veeam/managed_servers.json", results["veeam"].get("managed_servers", []))

        if "proxmox" in results:
            demo_generator._write("proxmox/nodes.json", results["proxmox"].get("nodes", []))
            demo_generator._write("proxmox/vms.json", results["proxmox"].get("vms", []))
            demo_generator._write("proxmox/containers.json", results["proxmox"].get("containers", []))
            demo_generator._write("proxmox/storage.json", results["proxmox"].get("storage", []))
            demo_generator._write("proxmox/sensors.json", results["proxmox"].get("sensors", []))

        if "esxi" in results:
            demo_generator._write("vmware/esxi_hosts.json", results["esxi"].get("hosts", []))

        # Sources list limited to what's actually in the demo
        demo_sources = [s for s in results.keys() if s in ("veeam", "proxmox", "esxi")]
        demo_generator._write("meta/last_update.json", {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "sources": demo_sources,
        })
        demo_generator._write("meta/build.json", self._code_build_info())
        logger.info("Hugo demo: data files written successfully")
