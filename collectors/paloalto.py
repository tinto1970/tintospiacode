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
                "host": self._ssh_host(),
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
                    "tasks": self._collect_tasks(),
                    "security_policy": self._collect_security_policy(),
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

    def _collect_tasks(self, max_tasks: int = 5) -> list:
        """Last N commit jobs from show jobs all."""
        try:
            root = self._op("<show><jobs><all></all></jobs></show>")
            tasks = []
            for job in root.findall("result/job"):
                tasks.append({
                    "id":           job.findtext("id", ""),
                    "type":         job.findtext("type", ""),
                    "user":         job.findtext("user", ""),
                    "status":       job.findtext("status", ""),
                    "result":       job.findtext("result", ""),
                    "start_time":   job.findtext("tenq", ""),
                    "end_time":     job.findtext("tfin", ""),
                    "details":      job.findtext("details/line", ""),
                    "has_warnings": job.find("warnings/line") is not None,
                })
            tasks.sort(key=lambda j: int(j["id"]) if j["id"].isdigit() else 0, reverse=True)
            result = tasks[:max_tasks]
            logger.debug("PaloAlto: collected %d tasks", len(result))
            return result
        except Exception as exc:
            logger.error("PaloAlto: tasks collection failed — %s", exc)
            return []

    def _traffic_log_query(self, nlogs: int = 500) -> list:
        """Submit an async traffic log query and return the XML entries when done."""
        resp = requests.get(
            f"{self.host}/api/",
            params={"key": self.api_key, "type": "log", "log-type": "traffic", "nlogs": str(nlogs)},
            verify=self.verify_ssl, timeout=30,
        )
        root = ET.fromstring(resp.text)
        job_id = root.findtext("result/job")
        if not job_id:
            logger.warning("PaloAlto: log query did not return a job id")
            return []

        for _ in range(25):
            time.sleep(3)
            resp2 = requests.get(
                f"{self.host}/api/",
                params={"key": self.api_key, "type": "log", "action": "get", "job-id": job_id},
                verify=self.verify_ssl, timeout=30,
            )
            root2 = ET.fromstring(resp2.text)
            if root2.findtext("result/job/status") == "FIN":
                entries = root2.findall("result/log/logs/entry")
                logger.debug("PaloAlto: traffic log query returned %d entries", len(entries))
                return entries
        logger.warning("PaloAlto: traffic log query timed out (job %s)", job_id)
        return []

    def _collect_security_policy(self) -> list:
        """Security rules from config + per-rule hit count and apps seen from traffic logs."""
        try:
            # --- rules from config API ---
            resp = requests.get(
                f"{self.host}/api/",
                params={
                    "key": self.api_key, "type": "config", "action": "get",
                    "xpath": "/config/devices/entry[@name='localhost.localdomain']"
                             "/vsys/entry[@name='vsys1']/rulebase/security/rules",
                },
                verify=self.verify_ssl, timeout=30,
            )
            root = ET.fromstring(resp.text)

            rules = {}   # name → rule dict (preserves insertion order = policy order)
            for entry in root.findall("result/rules/entry"):
                name = entry.get("name", "")
                rules[name] = {
                    "name":        name,
                    "from":        ", ".join(m.text for m in entry.findall("from/member") if m.text),
                    "to":          ", ".join(m.text for m in entry.findall("to/member") if m.text),
                    "source":      ", ".join(m.text for m in entry.findall("source/member") if m.text),
                    "destination": ", ".join(m.text for m in entry.findall("destination/member") if m.text),
                    "application": ", ".join(m.text for m in entry.findall("application/member") if m.text),
                    "action":      entry.findtext("action", ""),
                    "hit_count":   0,
                    "apps_seen":   0,
                    "apps_list":   [],
                }

            # --- aggregate traffic logs ---
            entries = self._traffic_log_query(nlogs=500)
            rule_stats: dict[str, dict] = {}
            for e in entries:
                rule = e.findtext("rule", "")
                app  = e.findtext("app", "")
                if not rule:
                    continue
                if rule not in rule_stats:
                    rule_stats[rule] = {"count": 0, "apps": set()}
                rule_stats[rule]["count"] += 1
                if app and app not in ("incomplete", "not-applicable", "unknown"):
                    rule_stats[rule]["apps"].add(app)

            for rule_name, stats in rule_stats.items():
                if rule_name in rules:
                    rules[rule_name]["hit_count"] = stats["count"]
                    rules[rule_name]["apps_seen"] = len(stats["apps"])
                    rules[rule_name]["apps_list"] = sorted(stats["apps"])

            result = list(rules.values())
            logger.debug("PaloAlto: collected %d security rules", len(result))
            return result
        except Exception as exc:
            logger.error("PaloAlto: security policy collection failed — %s", exc)
            return []

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
