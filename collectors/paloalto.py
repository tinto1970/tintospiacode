"""
Palo Alto Networks firewall collector.
Uses the PAN-OS XML API and SSH for environmental data.
"""

import logging
import re
import select
import time
import xml.etree.ElementTree as ET

import requests
import urllib3

logger = logging.getLogger(__name__)


class PaloAltoCollector:
    def __init__(self, config: dict):
        self.host = config["host"].rstrip("/")
        self.api_key = config.get("api_key", "")
        self.verify_ssl = config.get("verify_ssl", False)
        self.ssh_host = config.get("ssh_host")        # hostname for SSH (default: derived from host)
        self.ssh_user = config.get("ssh_user", "admin")
        self.ssh_password = config.get("ssh_password", "")
        self.ssh_port = config.get("ssh_port", 22)

        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ------------------------------------------------------------------
    # API helpers
    # ------------------------------------------------------------------

    def _api(self, params: dict) -> ET.Element:
        params["key"] = self.api_key
        resp = requests.get(
            f"{self.host}/api/",
            params=params,
            verify=self.verify_ssl,
            timeout=30,
        )
        resp.raise_for_status()
        root = ET.fromstring(resp.text)
        if root.attrib.get("status") != "success":
            raise RuntimeError(f"PAN-OS API error: {resp.text[:200]}")
        return root

    def _op(self, cmd: str) -> ET.Element:
        return self._api({"type": "op", "cmd": cmd})

    def _get_text(self, root: ET.Element, path: str, default: str = "") -> str:
        el = root.find(path)
        return el.text.strip() if el is not None and el.text else default

    # ------------------------------------------------------------------
    # Data collection
    # ------------------------------------------------------------------

    def collect(self) -> dict:
        logger.info("PaloAlto: starting collection")
        try:
            data = {
                "environmentals": self._collect_environmentals(),
            }
            if self.api_key:
                data.update({
                    "system_info": self._collect_system_info(),
                    "interfaces": self._collect_interfaces(),
                    "sessions": self._collect_session_summary(),
                    "routing": self._collect_routing_summary(),
                    "ha_state": self._collect_ha_state(),
                    "licenses": self._collect_licenses(),
                })
            return data
        except Exception as exc:
            logger.error("PaloAlto: collection failed — %s", exc)
            return {"error": str(exc)}

    # ------------------------------------------------------------------
    # SSH helpers (PAN-OS clish)
    # ------------------------------------------------------------------

    def _ssh_host(self) -> str:
        if self.ssh_host:
            return self.ssh_host
        return re.sub(r"^https?://", "", self.host).split(":")[0]

    def _ssh_run(self, command: str, timeout: int = 25) -> str:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                self._ssh_host(), port=self.ssh_port,
                username=self.ssh_user, password=self.ssh_password,
                timeout=15, look_for_keys=False, allow_agent=False,
            )
            shell = client.invoke_shell(term='vt100', width=220, height=200)

            def drain(secs):
                buf = ''
                deadline = time.time() + secs
                while time.time() < deadline:
                    r, _, _ = select.select([shell], [], [], 0.2)
                    if r:
                        buf += shell.recv(65535).decode(errors='replace')
                return buf

            drain(8)                          # wait for full MOTD/banner
            shell.send('set cli pager off\n')
            drain(3)
            shell.send(f'{command}\n')
            out = drain(timeout)
            return out
        finally:
            client.close()

    def _parse_environmentals(self, raw: str) -> dict:
        """Parse `show system environmentals` output into structured data."""
        result = {"thermal": [], "power": [], "power_supplies": []}
        section = None

        for line in raw.splitlines():
            line_s = line.strip()
            if not line_s or line_s.startswith('---') or line_s.startswith('Slot'):
                if 'Thermal' in line:
                    section = 'thermal'
                elif 'Power Supplies' in line:
                    section = 'power_supplies'
                elif 'Power' in line:
                    section = 'power'
                continue

            # remove ANSI escape sequences and backspace artifacts
            line_s = re.sub(r'\x1b\[[0-9;]*[mGKH]|\[K', '', line_s).strip()
            # skip prompt lines
            if '@' in line_s and ('>' in line_s or '#' in line_s):
                continue
            if not line_s:
                continue

            parts = line_s.split()
            if not parts or parts[0] != 'S1':
                continue

            if section == 'thermal' and len(parts) >= 6:
                # S1  Description...  Alarm  Degrees_C  Min_C  Max_C
                desc = ' '.join(parts[1:-4])
                alarm = parts[-4].lower() == 'true'
                try:
                    temp = float(parts[-3])
                except ValueError:
                    continue
                result['thermal'].append({
                    'description': desc,
                    'alarm': alarm,
                    'temp_c': temp,
                })

            elif section == 'power' and len(parts) >= 6:
                # S1  Description...  Alarm  Volts  Min_V  Max_V
                desc = ' '.join(parts[1:-4])
                alarm = parts[-4].lower() == 'true'
                try:
                    volts = float(parts[-3])
                except ValueError:
                    continue
                result['power'].append({
                    'description': desc,
                    'alarm': alarm,
                    'volts': volts,
                })

            elif section == 'power_supplies' and len(parts) >= 4:
                desc = ' '.join(parts[1:-2])
                alarm = parts[-2].lower() == 'true'
                inserted = parts[-1].lower() == 'true'
                result['power_supplies'].append({
                    'description': desc,
                    'alarm': alarm,
                    'inserted': inserted,
                })

        logger.debug(
            "PaloAlto: environmentals — %d thermal, %d power rails, %d PSUs",
            len(result['thermal']), len(result['power']), len(result['power_supplies']),
        )
        return result

    def _collect_environmentals(self) -> dict:
        try:
            raw = self._ssh_run('show system environmentals')
            return self._parse_environmentals(raw)
        except Exception as exc:
            logger.error("PaloAlto: environmentals collection failed — %s", exc)
            return {}

    def _collect_system_info(self) -> dict:
        root = self._op("<show><system><info></info></system></show>")
        info = root.find("result/system")
        if info is None:
            return {}
        return {
            "hostname": self._get_text(info, "hostname"),
            "model": self._get_text(info, "model"),
            "serial": self._get_text(info, "serial"),
            "sw_version": self._get_text(info, "sw-version"),
            "uptime": self._get_text(info, "uptime"),
            "ip_address": self._get_text(info, "ip-address"),
            "threat_version": self._get_text(info, "threat-version"),
            "av_version": self._get_text(info, "av-version"),
            "wildfire_version": self._get_text(info, "wildfire-version"),
        }

    def _collect_interfaces(self) -> list:
        root = self._op("<show><interface>all</interface></show>")
        interfaces = []
        for iface in root.findall("result/hw/entry"):
            interfaces.append({
                "name": self._get_text(iface, "name"),
                "type": self._get_text(iface, "type"),
                "state": self._get_text(iface, "state"),
                "mac": self._get_text(iface, "mac"),
                "speed": self._get_text(iface, "speed"),
                "duplex": self._get_text(iface, "duplex"),
            })
        logger.debug("PaloAlto: collected %d interfaces", len(interfaces))
        return interfaces

    def _collect_session_summary(self) -> dict:
        root = self._op("<show><session><info></info></session></show>")
        info = root.find("result")
        if info is None:
            return {}
        return {
            "num_active": self._get_text(info, "num-active"),
            "num_max": self._get_text(info, "num-max"),
            "num_tcp": self._get_text(info, "num-tcp"),
            "num_udp": self._get_text(info, "num-udp"),
            "tps": self._get_text(info, "tps"),
        }

    def _collect_routing_summary(self) -> dict:
        root = self._op("<show><routing><summary></summary></routing></show>")
        info = root.find("result")
        if info is None:
            return {}
        return {
            "total": self._get_text(info, "total"),
            "active": self._get_text(info, "active"),
            "ecmp": self._get_text(info, "ecmp"),
        }

    def _collect_ha_state(self) -> dict:
        try:
            root = self._op("<show><high-availability><state></state></high-availability></show>")
            info = root.find("result/group")
            if info is None:
                return {"enabled": False}
            return {
                "enabled": True,
                "mode": self._get_text(info, "mode"),
                "local_state": self._get_text(info, "local-info/state"),
                "peer_state": self._get_text(info, "peer-info/state"),
                "peer_ip": self._get_text(info, "peer-info/mgmt-ip"),
            }
        except Exception:
            return {"enabled": False}

    def _collect_licenses(self) -> list:
        root = self._op("<request><license><info></info></license></request>")
        licenses = []
        for lic in root.findall("result/licenses/entry"):
            licenses.append({
                "feature": self._get_text(lic, "feature"),
                "description": self._get_text(lic, "description"),
                "expiry": self._get_text(lic, "expired"),
                "expires": self._get_text(lic, "expires"),
                "expired": self._get_text(lic, "expired") == "yes",
            })
        logger.debug("PaloAlto: collected %d licenses", len(licenses))
        return licenses
