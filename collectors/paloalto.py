"""
Palo Alto Networks firewall collector.
Uses the PAN-OS XML API.
"""

import logging
import xml.etree.ElementTree as ET

import requests
import urllib3

logger = logging.getLogger(__name__)


class PaloAltoCollector:
    def __init__(self, config: dict):
        self.host = config["host"].rstrip("/")
        self.api_key = config["api_key"]
        self.verify_ssl = config.get("verify_ssl", False)

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
            return {
                "system_info": self._collect_system_info(),
                "interfaces": self._collect_interfaces(),
                "sessions": self._collect_session_summary(),
                "routing": self._collect_routing_summary(),
                "ha_state": self._collect_ha_state(),
                "licenses": self._collect_licenses(),
            }
        except Exception as exc:
            logger.error("PaloAlto: collection failed — %s", exc)
            return {"error": str(exc)}

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
