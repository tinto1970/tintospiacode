"""
Veeam Backup & Replication collector.

Job collection strategy:
  - Primary: read a JSON file exported by Export-VeeamJobs.ps1 running on the
    Veeam Windows server via Task Scheduler. This is the only way to include
    ProxmoxVE jobs (VmbApiPolicyTempJob), which are not exposed by the REST API.
  - Fallback: REST API /jobs endpoint (returns only Backup/HyperV/Agent jobs).

Sessions, repositories and managed servers always come from the REST API.
"""

import json
import logging
import os
import requests
import urllib3

logger = logging.getLogger(__name__)


class VeeamCollector:
    def __init__(self, config: dict):
        self.host = config["host"].rstrip("/")
        self.username = config["username"]
        self.password = config["password"]
        self.verify_ssl = config.get("verify_ssl", False)
        # Path to the JSON file produced by Export-VeeamJobs.ps1.
        # Can be a local path (SMB mount) or any accessible filesystem path.
        self.jobs_export_path = config.get("jobs_export_path", "")
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
            import re
            host = re.sub(r"^https?://", "", self.host).split(":")[0]
            return {
                "host": host,
                "jobs": self._collect_jobs(),
                "sessions": self._collect_sessions(),
                "repositories": self._collect_repositories(),
                "managed_servers": self._collect_managed_servers(),
            }
        except Exception as exc:
            logger.error("Veeam: collection failed — %s", exc)
            return {"error": str(exc)}

    def _collect_jobs(self) -> list:
        # --- primary: read from PS export file ---
        if self.jobs_export_path and os.path.isfile(self.jobs_export_path):
            try:
                with open(self.jobs_export_path, encoding="utf-8-sig") as f:
                    raw = json.load(f)
                if isinstance(raw, dict):
                    raw = [raw]
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
                logger.info("Veeam: loaded %d jobs from export file", len(jobs))
                return jobs
            except Exception as exc:
                logger.warning("Veeam: could not read jobs export file — %s — falling back to REST", exc)

        # --- fallback: REST API (no ProxmoxVE jobs) ---
        logger.warning("Veeam: jobs_export_path not set or file missing — using REST API (ProxmoxVE jobs will be missing)")
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

    def _collect_sessions(self) -> list:
        data = self._get("sessions", params={"limit": 10, "orderColumn": "CreationTime", "orderAsc": "false"})
        sessions = []
        for s in data.get("data", []):
            sessions.append({
                "id":               s.get("id"),
                "name":             s.get("name"),
                "job_id":           s.get("jobId"),
                "type":             s.get("sessionType"),
                "state":            s.get("state"),
                "result":           s.get("result"),
                "creation_time":    s.get("creationTime"),
                "end_time":         s.get("endTime"),
                "progress_percent": s.get("progressPercent"),
            })
        logger.debug("Veeam: collected %d sessions", len(sessions))
        return sessions

    def _collect_repositories(self) -> list:
        repos = []
        for r in self._get_all("backupInfrastructure/repositories"):
            repos.append({
                "id":            r.get("id"),
                "name":          r.get("name"),
                "type":          r.get("type"),
                "capacity_gb":   round(r.get("capacityGB", 0), 1),
                "free_space_gb": round(r.get("freeSpaceGB", 0), 1),
                "used_space_gb": round(r.get("usedSpaceGB", 0), 1),
            })
        logger.debug("Veeam: collected %d repositories", len(repos))
        return repos

    def _collect_managed_servers(self) -> list:
        servers = []
        for s in self._get_all("backupInfrastructure/managedServers"):
            servers.append({
                "id":          s.get("id"),
                "name":        s.get("name"),
                "type":        s.get("type"),
                "description": s.get("description"),
            })
        logger.debug("Veeam: collected %d managed servers", len(servers))
        return servers
