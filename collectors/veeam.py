"""
Veeam Backup & Replication collector.
Uses the Veeam REST API v1 (VBR 12+).
"""

import logging
import requests
import urllib3

logger = logging.getLogger(__name__)


class VeeamCollector:
    def __init__(self, config: dict):
        self.host = config["host"].rstrip("/")
        self.username = config["username"]
        self.password = config["password"]
        self.verify_ssl = config.get("verify_ssl", False)
        self._token = None

        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def _login(self):
        url = f"{self.host}/api/oauth2/token"
        resp = requests.post(
            url,
            data={
                "grant_type": "password",
                "username": self.username,
                "password": self.password,
            },
            headers={"x-api-version": "1.1-rev2", "Content-Type": "application/x-www-form-urlencoded"},
            verify=self.verify_ssl,
            timeout=30,
        )
        resp.raise_for_status()
        self._token = resp.json()["access_token"]
        logger.debug("Veeam: authenticated successfully")

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
        }

    def _get(self, path: str, params: dict = None) -> dict | list:
        if not self._token:
            self._login()
        url = f"{self.host}/api/v1/{path.lstrip('/')}"
        resp = requests.get(url, headers=self._headers(), params=params, verify=self.verify_ssl, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _get_all(self, path: str, page_size: int = 100) -> list:
        """Fetch all pages for paginated endpoints."""
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
            return {
                "jobs": self._collect_jobs(),
                "sessions": self._collect_sessions(),
                "repositories": self._collect_repositories(),
                "managed_servers": self._collect_managed_servers(),
            }
        except Exception as exc:
            logger.error("Veeam: collection failed — %s", exc)
            return {"error": str(exc)}

    def _collect_jobs(self) -> list:
        jobs = []
        for j in self._get_all("jobs"):
            jobs.append({
                "id": j.get("id"),
                "name": j.get("name"),
                "type": j.get("type"),
                "description": j.get("description"),
                "is_disabled": j.get("isDisabled", False),
                "schedule_enabled": j.get("scheduleEnabled", False),
            })
        logger.debug("Veeam: collected %d jobs", len(jobs))
        return jobs

    def _collect_sessions(self) -> list:
        sessions = []
        for s in self._get_all("sessions"):
            sessions.append({
                "id": s.get("id"),
                "name": s.get("name"),
                "job_id": s.get("jobId"),
                "type": s.get("sessionType"),
                "state": s.get("state"),
                "result": s.get("result"),
                "creation_time": s.get("creationTime"),
                "end_time": s.get("endTime"),
                "progress_percent": s.get("progressPercent"),
                "log_truncated": s.get("isLogTruncated", False),
            })
        logger.debug("Veeam: collected %d sessions", len(sessions))
        return sessions

    def _collect_repositories(self) -> list:
        repos = []
        for r in self._get_all("backupInfrastructure/repositories"):
            repos.append({
                "id": r.get("id"),
                "name": r.get("name"),
                "type": r.get("type"),
                "capacity_gb": round(r.get("capacityGB", 0), 1),
                "free_space_gb": round(r.get("freeSpaceGB", 0), 1),
                "used_space_gb": round(r.get("usedSpaceGB", 0), 1),
            })
        logger.debug("Veeam: collected %d repositories", len(repos))
        return repos

    def _collect_managed_servers(self) -> list:
        servers = []
        for s in self._get_all("backupInfrastructure/managedServers"):
            servers.append({
                "id": s.get("id"),
                "name": s.get("name"),
                "type": s.get("type"),
                "description": s.get("description"),
            })
        logger.debug("Veeam: collected %d managed servers", len(servers))
        return servers
