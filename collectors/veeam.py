"""
Veeam Backup & Replication collector.

Job collection strategy:
  1. WinRM (preferred): run Get-VBRJob PowerShell directly on the Veeam server via
     WinRM (port 5985). Covers all job types including ProxmoxVE (VmbApiPolicyTempJob).
     Requires winrm_enabled: true in the veeam config section.
  2. SSH relay (rocky_linux_relay in config): run Get-VeeamJobsRelay.ps1 on a
     Linux relay host via SSH. Requires port 9401 open from relay to Veeam server
     (Identity service). Currently not usable if that port is blocked.
  3. Local file (jobs_export_path in veeam config): read a JSON file exported by
     Export-VeeamJobs.ps1 running on the Veeam server via Task Scheduler.
  4. Fallback: REST API /jobs endpoint (Backup/HyperV/Agent only — ProxmoxVE jobs
     are NOT exposed by the Veeam REST API).

Sessions, repositories and managed servers always come from the REST API.
"""

import json
import logging
import os
import re
from datetime import datetime, timezone
import requests
import urllib3

logger = logging.getLogger(__name__)


def _normalise_ps_jobs(raw: list) -> list:
    """Normalise a list of job dicts from any PS script source into the tintospia schema."""
    jobs = []
    for j in raw:
        jobs.append({
            "name":             j.get("name", ""),
            "type":             j.get("type", ""),
            "is_disabled":      j.get("is_disabled", False),
            "schedule_enabled": j.get("schedule_enabled", False),
            "last_result":      j.get("last_result", ""),
            "last_end_time":    j.get("last_end_time", ""),
            "last_start_time":  j.get("last_start_time", ""),
            "last_state":       j.get("last_state", ""),
        })
    return jobs


class VeeamCollector:
    def __init__(self, config: dict, relay_config: dict = None):
        self.host = config["host"].rstrip("/")
        self.username = config["username"]
        self.password = config["password"]
        self.verify_ssl = config.get("verify_ssl", False)
        # WinRM: run PS directly on the Veeam server (port 5985, no SSL)
        self.winrm_enabled = config.get("winrm_enabled", True)
        # Path to the JSON file produced by Export-VeeamJobs.ps1.
        # Can be a local path (SMB mount) or any accessible filesystem path.
        self.jobs_export_path = config.get("jobs_export_path", "")
        # Optional SSH relay config (rocky_linux_relay section from top-level config)
        self._relay = relay_config or {}
        self._token = None

        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ------------------------------------------------------------------
    # REST API helpers
    # ------------------------------------------------------------------

    def _login(self):
        url = f"{self.host}/api/oauth2/token"
        resp = requests.post(
            url,
            data={"grant_type": "password", "username": self.username, "password": self.password},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            verify=self.verify_ssl,
            timeout=30,
        )
        resp.raise_for_status()
        self._token = resp.json()["access_token"]
        logger.debug("Veeam: REST authenticated")

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}

    def _get(self, path: str, params: dict = None) -> dict:
        if not self._token:
            self._login()
        url = f"{self.host}/api/v1/{path.lstrip('/')}"
        resp = requests.get(url, headers=self._headers(), params=params, verify=self.verify_ssl, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _get_all(self, path: str, page_size: int = 100) -> list:
        items = []
        skip = 0
        while True:
            data = self._get(path, params={"limit": page_size, "skip": skip})
            page = data.get("data", [])
            items.extend(page)
            total = data.get("pagination", {}).get("total", 0)
            skip += len(page)
            if skip >= total or not page:
                break
        return items

    # ------------------------------------------------------------------
    # Data collection
    # ------------------------------------------------------------------

    def collect(self) -> dict:
        logger.info("Veeam: starting collection")
        try:
            self._login()
            host = re.sub(r"^https?://", "", self.host).split(":")[0]
            return {
                "host": host,
                "server_info": self._collect_server_info(),
                "jobs": self._collect_jobs(),
                "backup_sessions": self._collect_backup_sessions(),
                "sessions": self._collect_sessions(),
                "repositories": self._collect_repositories(),
                "scale_out_repositories": self._collect_scale_out_repositories(),
                "proxies": self._collect_proxies(),
                "managed_servers": self._collect_managed_servers(),
                "malware_events": self._collect_malware_events(),
            }
        except Exception as exc:
            logger.error("Veeam: collection failed — %s", exc)
            return {"error": str(exc)}

    def _collect_jobs(self) -> list:
        # --- strategy 1: WinRM ---
        if self.winrm_enabled:
            try:
                jobs = self._collect_jobs_via_winrm()
                if jobs is not None:
                    return jobs
            except Exception as exc:
                logger.warning("Veeam: WinRM failed — %s — trying next strategy", exc)

        # --- strategy 2: SSH relay ---
        if self._relay:
            try:
                jobs = self._collect_jobs_via_relay()
                if jobs is not None:
                    return jobs
            except Exception as exc:
                logger.warning("Veeam: SSH relay failed — %s — trying next strategy", exc)

        # --- strategy 3: local PS export file ---
        if self.jobs_export_path and os.path.isfile(self.jobs_export_path):
            try:
                with open(self.jobs_export_path, encoding="utf-8-sig") as f:
                    raw = json.load(f)
                if isinstance(raw, dict):
                    raw = [raw]
                jobs = _normalise_ps_jobs(raw)
                logger.info("Veeam: loaded %d jobs from export file", len(jobs))
                return jobs
            except Exception as exc:
                logger.warning("Veeam: could not read jobs export file — %s — falling back to REST", exc)

        # --- strategy 4: REST API (no ProxmoxVE jobs) ---
        logger.warning("Veeam: no WinRM/relay/export available — using REST API (ProxmoxVE jobs will be missing)")
        jobs = []
        for j in self._get_all("jobs"):
            jobs.append({
                "name":             j.get("name", ""),
                "type":             j.get("type", ""),
                "is_disabled":      j.get("isDisabled", False),
                "schedule_enabled": j.get("scheduleEnabled", False),
                "last_result":      "",
                "last_end_time":    "",
                "last_start_time":  "",
                "last_state":       "",
            })
        logger.debug("Veeam: collected %d jobs via REST", len(jobs))
        return jobs

    def _collect_jobs_via_winrm(self) -> list | None:
        """Run Get-VBRJob PowerShell directly on the Veeam server via WinRM, return parsed jobs."""
        import winrm

        server = re.sub(r"^https?://", "", self.host).split(":")[0]
        logger.debug("Veeam WinRM: connecting to %s", server)

        session = winrm.Session(
            f"http://{server}:5985/wsman",
            auth=(self.username, self.password),
            transport="ntlm",
            read_timeout_sec=120,
            operation_timeout_sec=110,
        )

        # PowerShell script: load Veeam module, collect all jobs, output JSON
        ps_script = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

try {
    Import-Module 'Veeam.Backup.PowerShell' -ErrorAction SilentlyContinue
    if (-not (Get-Command Get-VBRJob -ErrorAction SilentlyContinue)) {
        Add-PSSnapin VeeamPSSnapIn
    }
} catch {
    Write-Error "Failed to load Veeam module: $_"
    exit 1
}

$jobs = @(Get-VBRJob)
$output = foreach ($job in $jobs) {
    $session = $job.FindLastSession()
    [PSCustomObject]@{
        name             = $job.Name
        type             = $job.JobType.ToString()
        is_disabled      = [bool]$job.IsDisabled
        schedule_enabled = [bool]$job.IsScheduleEnabled
        last_result      = if ($session) { $session.Result.ToString()          } else { 'Never' }
        last_end_time    = if ($session) { $session.EndTime.ToString('o')       } else { ''      }
        last_state       = if ($session) { $session.State.ToString()           } else { ''      }
        last_start_time  = if ($session) { $session.CreationTime.ToString('o') } else { ''      }
    }
}

$output | ConvertTo-Json -Depth 3 -AsArray
"""

        result = session.run_ps(ps_script)

        if result.status_code != 0:
            stderr = result.std_err.decode("utf-8", errors="replace").strip()
            logger.error("Veeam WinRM: PowerShell exited %d — %s", result.status_code, stderr[:500])
            return None

        out = result.std_out.decode("utf-8", errors="replace")
        if result.std_err:
            warn = result.std_err.decode("utf-8", errors="replace").strip()
            if warn:
                logger.debug("Veeam WinRM: PS stderr (non-fatal): %s", warn[:300])

        json_start = out.find("[")
        json_end   = out.rfind("]")
        if json_start == -1 or json_end == -1:
            logger.error("Veeam WinRM: no JSON array in output — first 300 chars: %s", out[:300])
            return None

        raw = json.loads(out[json_start : json_end + 1])
        if isinstance(raw, dict):
            raw = [raw]
        jobs = _normalise_ps_jobs(raw)
        logger.info("Veeam WinRM: collected %d jobs", len(jobs))
        return jobs

    def _collect_jobs_via_relay(self) -> list | None:
        """Run Get-VeeamJobsRelay.ps1 on the configured relay host via SSH, return parsed jobs."""
        import paramiko

        relay_host = self._relay["host"]
        relay_user = self._relay.get("ssh_user", "tinto")
        relay_key  = self._relay.get("ssh_key", "")
        module_path = self._relay.get(
            "veeam_module",
            "/opt/veeam/powershell/Veeam.Backup.PowerShell/Veeam.Backup.PowerShell.psd1",
        )

        # Path to the relay script (same directory as this file's package root)
        script_src = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "scripts", "Get-VeeamJobsRelay.ps1",
        )
        if not os.path.isfile(script_src):
            logger.error("Veeam relay: script not found at %s", script_src)
            return None

        veeam_server = re.sub(r"^https?://", "", self.host).split(":")[0]

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            connect_kwargs = {"username": relay_user, "timeout": 30}
            if relay_key:
                connect_kwargs["key_filename"] = relay_key
                connect_kwargs["look_for_keys"] = False
            client.connect(relay_host, **connect_kwargs)
            logger.debug("Veeam relay: connected to %s", relay_host)

            # Upload relay script to a temp path on the relay host
            remote_script = "/tmp/Get-VeeamJobsRelay.ps1"
            sftp = client.open_sftp()
            try:
                sftp.put(script_src, remote_script)
            finally:
                sftp.close()

            # Build pwsh command — password passed via -Password arg
            # The password is not logged
            escaped_password = self.password.replace("'", "''")
            cmd = (
                f"pwsh -NonInteractive -File {remote_script}"
                f" -ModulePath '{module_path}'"
                f" -Server '{veeam_server}'"
                f" -Username '{self.username}'"
                f" -Password '{escaped_password}'"
            )

            stdin, stdout, stderr = client.exec_command(cmd, timeout=120)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace").strip()
            exit_code = stdout.channel.recv_exit_status()

            # Exit code -1 can occur due to a background Veeam thread crash (ClientTimeSyncProc)
            # after the main script has already written its JSON — treat it as non-fatal if
            # the stdout contains a valid JSON array.
            if exit_code not in (0, -1):
                logger.error("Veeam relay: pwsh exited %d — stderr: %s", exit_code, err[:500])
                return None

            if exit_code == -1:
                logger.debug("Veeam relay: pwsh exited -1 (known Veeam background thread crash on Linux — non-fatal if JSON present)")
            if err:
                logger.debug("Veeam relay: pwsh stderr (non-fatal): %s", err[:500])

            # Extract JSON from stdout (ignore any stray lines before/after the array)
            json_start = out.find("[")
            json_end   = out.rfind("]")
            if json_start == -1 or json_end == -1:
                logger.error("Veeam relay: no JSON array found in output — first 500 chars: %s", out[:500])
                return None

            raw = json.loads(out[json_start : json_end + 1])
            if isinstance(raw, dict):
                raw = [raw]
            jobs = _normalise_ps_jobs(raw)
            logger.info("Veeam relay: collected %d jobs via SSH relay", len(jobs))
            return jobs

        finally:
            client.close()

    @staticmethod
    def _session_duration(start_str: str, end_str: str) -> str:
        if not start_str or not end_str:
            return ""
        try:
            fmt = "%Y-%m-%dT%H:%M:%S.%f%z"
            start = datetime.fromisoformat(start_str)
            end   = datetime.fromisoformat(end_str)
            secs  = max(0, int((end - start).total_seconds()))
            h, rem = divmod(secs, 3600)
            m, s   = divmod(rem, 60)
            return f"{h:02d}:{m:02d}:{s:02d}"
        except Exception:
            return ""

    def _normalise_session(self, s: dict) -> dict:
        result_obj = s.get("result") or {}
        start = s.get("creationTime")
        end   = s.get("endTime")
        return {
            "id":               s.get("id"),
            "name":             s.get("name"),
            "job_id":           s.get("jobId"),
            "type":             s.get("sessionType"),
            "state":            s.get("state"),
            "result":           result_obj.get("result", "") if isinstance(result_obj, dict) else str(result_obj),
            "creation_time":    start,
            "end_time":         end,
            "duration":         self._session_duration(start, end),
            "progress_percent": s.get("progressPercent"),
        }

    def _collect_sessions(self) -> list:
        data = self._get("sessions", params={"limit": 10, "orderColumn": "CreationTime", "orderAsc": "false"})
        sessions = [self._normalise_session(s) for s in data.get("data", [])]
        logger.debug("Veeam: collected %d sessions", len(sessions))
        return sessions

    _BACKUP_SESSION_TYPES = {"BackupJob", "BackupCopyJob", "BackupToTapeJob", "FilesToTapeJob", "EpAgentBackup"}

    def _collect_backup_sessions(self, want: int = 10) -> list:
        """Return the `want` most recent sessions of backup job types, paginating as needed."""
        sessions = []
        skip = 0
        page_size = 100
        while len(sessions) < want:
            data = self._get("sessions", params={
                "limit": page_size, "skip": skip,
                "orderColumn": "CreationTime", "orderAsc": "false",
            })
            page = data.get("data", [])
            if not page:
                break
            for s in page:
                if s.get("sessionType") in self._BACKUP_SESSION_TYPES:
                    sessions.append(self._normalise_session(s))
                    if len(sessions) >= want:
                        break
            total = data.get("pagination", {}).get("total", 0)
            skip += len(page)
            if skip >= total:
                break
        logger.debug("Veeam: collected %d backup sessions", len(sessions))
        return sessions

    def _collect_repositories(self) -> list:
        # /repositories/states includes capacity data; /repositories does not
        repos = []
        for r in self._get_all("backupInfrastructure/repositories/states"):
            repos.append({
                "id":            r.get("id"),
                "name":          r.get("name"),
                "type":          r.get("type"),
                "capacity_gb":   round(r.get("capacityGB", 0), 1),
                "free_space_gb": round(r.get("freeGB", 0), 1),
                "used_space_gb": round(r.get("usedSpaceGB", 0), 1),
                "is_online":     r.get("isOnline", True),
            })
        logger.debug("Veeam: collected %d repositories", len(repos))
        return repos

    def _collect_scale_out_repositories(self) -> list:
        # Build id → state map from repository states (already fetched for repositories)
        state_map = {r["id"]: r for r in self._get_all("backupInfrastructure/repositories/states")}

        # Map SOBR id → job names from REST jobs
        sobr_jobs: dict = {}
        for job in self._get_all("jobs"):
            repo_id = (
                job.get("storage", {}).get("backupRepositoryId")
                or job.get("backupRepository", {}).get("backupRepositoryId")
            )
            if repo_id:
                sobr_jobs.setdefault(repo_id, []).append(job.get("name", ""))

        sobrs = []
        for s in self._get_all("backupInfrastructure/scaleOutRepositories"):
            extents = []
            total_cap = total_free = total_used = 0.0

            for pe in s.get("performanceTier", {}).get("performanceExtents", []):
                ext_id = pe.get("id")
                state = state_map.get(ext_id, {})
                cap  = round(state.get("capacityGB", 0), 1)
                free = round(state.get("freeGB", 0), 1)
                used = round(state.get("usedSpaceGB", 0), 1)
                total_cap  += cap
                total_free += free
                total_used += used
                status_list = pe.get("status", [])
                extents.append({
                    "name":         pe.get("name", ""),
                    "type":         state.get("type", ""),
                    "extent_type":  "Performance",
                    "capacity_gb":  cap,
                    "free_space_gb": free,
                    "used_space_gb": used,
                    "status":       status_list[0] if status_list else "",
                    "is_online":    state.get("isOnline", True),
                })

            sobr_id = s.get("id")
            sobrs.append({
                "id":            sobr_id,
                "name":          s.get("name"),
                "capacity_gb":   round(total_cap, 1),
                "free_space_gb": round(total_free, 1),
                "used_space_gb": round(total_used, 1),
                "extents":       extents,
                "jobs":          sobr_jobs.get(sobr_id, []),
            })

        logger.debug("Veeam: collected %d scale-out repositories", len(sobrs))
        return sobrs

    def _collect_proxies(self) -> list:
        proxies = []
        for p in self._get_all("backupInfrastructure/proxies"):
            srv = p.get("server", {})
            proxies.append({
                "id":             p.get("id"),
                "name":           p.get("name"),
                "type":           p.get("type"),
                "host":           srv.get("hostName", ""),
                "max_tasks":      srv.get("maxTaskCount", 0),
                "transport_mode": srv.get("transportMode", ""),
            })
        logger.debug("Veeam: collected %d proxies", len(proxies))
        return proxies

    def _collect_malware_events(self, want: int = 10) -> list:
        events = []
        skip = 0
        page_size = 100
        while len(events) < want:
            data = self._get("malwareDetection/events", params={
                "limit": page_size, "skip": skip,
                "orderColumn": "CreationTimeUtc", "orderAsc": "false",
            })
            page = data.get("data", [])
            if not page:
                break
            for e in page:
                # Strip the log-path preamble; keep only the detection summary
                raw_details = e.get("details", "")
                parts = raw_details.split("\n\n", 1)
                summary = parts[1].strip() if len(parts) > 1 else raw_details.strip()
                events.append({
                    "id":             e.get("id"),
                    "type":           e.get("type"),
                    "severity":       e.get("severity"),
                    "state":          e.get("state"),
                    "machine":        (e.get("machine") or {}).get("displayName", ""),
                    "detection_time": e.get("detectionTimeUtc"),
                    "creation_time":  e.get("creationTimeUtc"),
                    "details":        summary,
                })
                if len(events) >= want:
                    break
            total = data.get("pagination", {}).get("total", 0)
            skip += len(page)
            if skip >= total:
                break
        logger.debug("Veeam: collected %d malware events", len(events))
        return events

    def _collect_managed_servers(self) -> list:
        servers = []
        for s in self._get_all("backupInfrastructure/managedServers"):
            servers.append({
                "id":            s.get("id"),
                "name":          s.get("name"),
                "type":          s.get("type"),
                "vi_host_type":  s.get("viHostType", ""),
                "status":        s.get("status", ""),
                "description":   s.get("description", ""),
                "is_backup_server": s.get("isBackupServer", False),
            })
        logger.debug("Veeam: collected %d managed servers", len(servers))
        return servers

    def _collect_server_info(self) -> dict:
        info = self._get("serverInfo")
        # Last configuration backup: scan sessions for the most recent ConfigurationBackup
        cfg_bkp = {}
        skip = 0
        page_size = 100
        while True:
            data = self._get("sessions", params={
                "limit": page_size, "skip": skip,
                "orderColumn": "CreationTime", "orderAsc": "false",
            })
            page = data.get("data", [])
            if not page:
                break
            for s in page:
                if s.get("sessionType") == "ConfigurationBackup":
                    result_obj = s.get("result") or {}
                    result_str = result_obj.get("result", "") if isinstance(result_obj, dict) else str(result_obj)
                    start = s.get("creationTime", "")
                    end   = s.get("endTime", "")
                    cfg_bkp = {
                        "last_run":  start,
                        "end_time":  end,
                        "duration":  self._session_duration(start, end),
                        "result":    result_str,
                        "message":   result_obj.get("message", "") if isinstance(result_obj, dict) else "",
                    }
                    break
            if cfg_bkp:
                break
            total = data.get("pagination", {}).get("total", 0)
            skip += len(page)
            if skip >= total:
                break

        logger.debug("Veeam: collected server info")
        return {
            "name":            info.get("name", ""),
            "build_version":   info.get("buildVersion", ""),
            "platform":        info.get("platform", ""),
            "database_vendor": info.get("databaseVendor", ""),
            "database_version": info.get("sqlServerVersion", ""),
            "config_backup":   cfg_bkp,
        }
