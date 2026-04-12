"""
VMware ESXi standalone collector.
Uses SSH + esxcli / vim-cmd — no vCenter required.
"""

import csv
import io
import logging
import re
import time

logger = logging.getLogger(__name__)


class ESXiCollector:
    def __init__(self, config: dict):
        # Support both single-host (legacy) and multi-host (hosts: [...]) format
        if "hosts" in config:
            self._hosts = config["hosts"]
        else:
            self._hosts = [{
                "host":         config["host"],
                "ssh_user":     config.get("ssh_user", "root"),
                "ssh_password": config.get("ssh_password", ""),
                "ssh_port":     config.get("ssh_port", 22),
            }]

    # ------------------------------------------------------------------
    # SSH helpers
    # ------------------------------------------------------------------

    def _connect(self, host_cfg: dict):
        import paramiko
        host     = host_cfg["host"]
        port     = host_cfg.get("ssh_port", 22)
        username = host_cfg.get("ssh_user", "root")
        password = host_cfg.get("ssh_password", "")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Try password auth first
        try:
            client.connect(
                host, port=port, username=username, password=password,
                timeout=15, look_for_keys=False, allow_agent=False,
            )
            return client
        except paramiko.AuthenticationException:
            pass

        # Fall back to keyboard-interactive (common on ESXi)
        sock = client.get_transport()
        if sock:
            sock.close()

        transport = paramiko.Transport((host, port))
        transport.connect(hostkey=None)
        transport.auth_interactive(
            username,
            lambda title, instructions, prompt_list: [
                paramiko.common.byte_chr(0) if p[1] else password
                for p in prompt_list
            ] if prompt_list else [password],
        )
        client2 = paramiko.SSHClient()
        client2._transport = transport
        return client2

    def _run(self, client, cmd: str, timeout: int = 20) -> str:
        _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode(errors="replace").strip()
        return out

    def _parse_csv(self, text: str) -> list[dict]:
        """Parse esxcli --formatter=csv output into a list of dicts."""
        lines = [l for l in text.splitlines() if l.strip()]
        if len(lines) < 2:
            return []
        reader = csv.DictReader(io.StringIO("\n".join(lines)))
        return [row for row in reader]

    def _parse_keyvalue(self, text: str) -> dict:
        """Parse esxcli --formatter=keyvalue output.

        Handles two formats:
          - ESXi style:  Struct.Field.type=value
          - Generic:     Key: Value
        """
        result = {}
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if "=" in line and ":" not in line.split("=")[0]:
                # ESXi dotted format: VersionGet.Version.string=8.0.2
                k, _, v = line.partition("=")
                parts = k.split(".")
                # Use the middle part (field name) as key, strip type suffix
                field = parts[1] if len(parts) >= 2 else parts[0]
                result[field] = v.strip()
            elif ":" in line:
                k, _, v = line.partition(":")
                result[k.strip()] = v.strip()
        return result

    # ------------------------------------------------------------------
    # Data collection
    # ------------------------------------------------------------------

    def collect(self) -> dict:
        """Returns {"hosts": [ {host, system_info, sensors, vms, datastores, nics}, ... ]}"""
        results = []
        for host_cfg in self._hosts:
            host_addr = host_cfg.get("host", "unknown")
            logger.info("ESXi: starting collection on %s", host_addr)
            client = None
            try:
                client = self._connect(host_cfg)
                results.append({
                    "host":        host_addr,
                    "system_info": self._collect_system_info(client, host_addr),
                    "sensors":     self._collect_sensors(client),
                    "vms":         self._collect_vms(client),
                    "datastores":  self._collect_datastores(client),
                    "nics":        self._collect_nics(client),
                })
            except Exception as exc:
                logger.error("ESXi: collection failed for %s — %s", host_addr, exc)
                results.append({"host": host_addr, "error": str(exc)})
            finally:
                if client:
                    client.close()
        return {"hosts": results}

    def _collect_system_info(self, client, host_addr: str = "") -> dict:
        ver = self._parse_keyvalue(
            self._run(client, "esxcli --formatter=keyvalue system version get")
        )
        mem_raw = self._parse_keyvalue(
            self._run(client, "esxcli --formatter=keyvalue hardware memory get")
        )

        # Parse platform info (plain text, no --formatter support)
        platform_raw = self._run(client, "esxcli hardware platform get")
        platform = {}
        for line in platform_raw.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                platform[k.strip()] = v.strip()

        uptime_us = self._run(client, "esxcli system stats uptime get").strip()
        try:
            uptime_s = int(uptime_us) // 1_000_000
            days, rem = divmod(uptime_s, 86400)
            hours, rem = divmod(rem, 3600)
            mins = rem // 60
            uptime_str = f"{days}d {hours}h {mins}m"
        except (ValueError, TypeError):
            uptime_str = uptime_us

        try:
            mem_gb = round(int(mem_raw.get("PhysicalMemory", "0")) / 1024**3, 1)
        except (ValueError, TypeError):
            mem_gb = 0

        info = {
            "hostname":    host_addr,
            "version":     ver.get("Version", ""),
            "build":       ver.get("Build", ""),
            "product":     ver.get("Product", "VMware ESXi"),
            "model":       platform.get("Product Name", ""),
            "vendor":      platform.get("Vendor Name", ""),
            "serial":      platform.get("Serial Number", ""),
            "uptime":      uptime_str,
            "mem_total_gb": mem_gb,
        }
        logger.debug("ESXi: system info collected")
        return info

    def _collect_sensors(self, client) -> dict:
        """Collect hardware sensors. ESXi 8 removed 'hardware sensor list';
        try it anyway and return empty gracefully if unavailable."""
        raw = self._run(client, "esxcli --formatter=csv hardware sensor list")
        if raw.startswith("Error:") or not raw:
            logger.debug("ESXi: hardware sensor list not available (ESXi 8+), skipping")
            return {"thermal": [], "fans": [], "voltages": []}

        rows = self._parse_csv(raw)
        thermal, fans, voltages = [], [], []
        for r in rows:
            sensor_type = r.get("SensorType", r.get("Sensor Type", "")).lower()
            description = r.get("Description", "")
            health = r.get("Health State", r.get("HealthState", ""))
            try:
                reading = int(r.get("CurrentReading", r.get("Current Reading", "0")))
                modifier = int(r.get("UnitModifier", r.get("Unit Modifier", "0")))
                value = reading * (10 ** modifier)
            except (ValueError, TypeError):
                value = 0.0

            entry = {"description": description, "health": health}
            if "temperature" in sensor_type:
                entry["temp_c"] = round(value, 1)
                thermal.append(entry)
            elif "fan" in sensor_type:
                entry["rpm"] = int(value)
                fans.append(entry)
            elif "voltage" in sensor_type:
                entry["volts"] = round(value, 3)
                voltages.append(entry)

        logger.debug(
            "ESXi: sensors — %d thermal, %d fans, %d voltages",
            len(thermal), len(fans), len(voltages),
        )
        return {"thermal": thermal, "fans": fans, "voltages": voltages}

    def _collect_vms(self, client) -> list:
        # Running VMs via esxcli (has DisplayName + ConfigFile)
        raw_running = self._run(client, "esxcli --formatter=csv vm process list")
        running_rows = self._parse_csv(raw_running)
        running_names = {r.get("DisplayName", r.get("Display Name", "")) for r in running_rows}

        # All registered VMs via vim-cmd
        raw_all = self._run(client, "vim-cmd vmsvc/getallvms 2>/dev/null")
        vms = []
        for line in raw_all.splitlines():
            line = line.strip()
            # Header line starts with "Vmid"
            if not line or line.startswith("Vmid"):
                continue
            # Format: Vmid   Name   File   GuestOS   Version   Annotation
            parts = re.split(r"\s{2,}", line)
            if len(parts) < 4:
                continue
            try:
                vmid = int(parts[0])
            except ValueError:
                continue
            name = parts[1]
            vmx_file = parts[2] if len(parts) > 2 else ""
            guest_os = parts[3] if len(parts) > 3 else ""
            vms.append({
                "vmid": vmid,
                "name": name,
                "status": "running" if name in running_names else "stopped",
                "guest_os": guest_os,
                "vmx_file": vmx_file,
            })

        logger.debug("ESXi: collected %d VMs (%d running)", len(vms), len(running_names))
        return vms

    def _collect_datastores(self, client) -> list:
        raw = self._run(client, "esxcli --formatter=csv storage filesystem list")
        rows = self._parse_csv(raw)
        datastores = []
        for r in rows:
            try:
                size = int(r.get("Size", r.get("Capacity", "0")))
                free = int(r.get("Free", r.get("FreeSpace", "0")))
            except (ValueError, TypeError):
                size = free = 0
            ds_type = r.get("Type", "")
            if not ds_type or ds_type.lower() in ("vfat", ""):
                continue   # skip boot/scratch partitions
            datastores.append({
                "name":      r.get("Volume Name", r.get("VolumeName", "")),
                "mount":     r.get("Mount Point", r.get("MountPoint", "")),
                "type":      ds_type,
                "size_gb":   round(size / 1024**3, 2),
                "free_gb":   round(free / 1024**3, 2),
                "used_gb":   round((size - free) / 1024**3, 2),
            })
        logger.debug("ESXi: collected %d datastores", len(datastores))
        return datastores

    def _collect_nics(self, client) -> list:
        raw = self._run(client, "esxcli --formatter=csv network nic list")
        rows = self._parse_csv(raw)
        nics = []
        for r in rows:
            nics.append({
                "name":   r.get("Name", ""),
                "driver": r.get("Driver", ""),
                "link":   r.get("Link Status", r.get("LinkStatus", "")),
                "speed":  r.get("Speed", ""),
                "duplex": r.get("Duplex", ""),
                "mac":    r.get("MAC Address", r.get("MACAddress", "")),
            })
        logger.debug("ESXi: collected %d NICs", len(nics))
        return nics
