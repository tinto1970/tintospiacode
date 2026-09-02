"""
Git-Vault collector.

Reads the most recent backup log and runs gh-verify.sh to report
the health of the local git mirror + snapshot backup.
"""

import logging
import os
import re
import subprocess
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Regex for a timestamped log line: "YYYY-MM-DD HH:MM:SS TOKEN rest"
_LINE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(OK|!!|\S+)\s+(.*)$"
)

# Keys that appear in both Italian and English log summaries
_SUMMARY_KEYS = {
    "ok":               ("ok",),
    "skipped":          ("saltati", "skipped"),
    "failed":           ("falliti", "failed"),
    "elapsed":          ("durata", "elapsed"),
    "total_on_disk":    ("totale su disco", "total on disk"),
}


def _parse_log(log_path: str) -> dict:
    """Parse the most recent complete backup run from a log file."""
    try:
        with open(log_path, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError as exc:
        return {"error": str(exc)}

    # Split into runs; each run starts with ">> Backup" / ">> Backing up"
    runs: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        stripped = line.strip()
        if re.search(r">> (Backup di|Backing up) ", stripped):
            if current:
                runs.append(current)
            current = [stripped]
        elif current:
            current.append(stripped)
    if current:
        runs.append(current)

    if not runs:
        return {"error": "no backup runs found in log"}

    # Find the last completed run (has a summary block)
    last = None
    for run in reversed(runs):
        if any(re.search(r">> (Riepilogo|Summary) ", l) for l in run):
            last = run
            break

    if not last:
        return {"error": "no complete backup run found in log"}

    # Extract summary values
    summary: dict = {}
    in_summary = False
    repos: list[dict] = []
    _TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\s*")

    for line in last:
        # Capture leading timestamp
        ts_m = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
        ts = ts_m.group(1) if ts_m else ""
        # Body = line with timestamp stripped
        body = _TS_RE.sub("", line).strip()

        if re.search(r">> (Riepilogo|Summary) ", body):
            in_summary = True
            summary["timestamp"] = ts
            continue

        if in_summary:
            for field, keys in _SUMMARY_KEYS.items():
                for k in keys:
                    m2 = re.match(rf"^\s*{re.escape(k)}:\s+(.+)$", body, re.IGNORECASE)
                    if m2:
                        summary[field] = m2.group(1).strip()
                        break
            continue

        # Per-repo OK line: "OK name (SIZE, N ref)"
        m3 = re.match(r"OK (\S+) \(([^,]+),\s*(\d+) refs?\)", body)
        if m3:
            repos.append({
                "name":   m3.group(1),
                "size":   m3.group(2).strip(),
                "refs":   int(m3.group(3)),
                "status": "ok",
                "note":   "",
            })
            continue

        # Empty-repo note (log line emitted before the OK line)
        m4 = re.match(r"(\S+):\s+(?:repository vuoto|empty repository)", body)
        if m4:
            name = m4.group(1)
            for r in repos:
                if r["name"] == name:
                    r["note"] = "empty"
            continue

        # Error lines
        if re.match(r"ERR|FAIL", body, re.IGNORECASE):
            repos_match = re.match(r"(\S+):\s+(.+)", body)
            if repos_match:
                repos.append({
                    "name":   repos_match.group(1),
                    "size":   "",
                    "refs":   0,
                    "status": "error",
                    "note":   repos_match.group(2),
                })

    return {
        "timestamp":    summary.get("timestamp", ""),
        "ok":           int(summary.get("ok", 0)),
        "skipped":      int(summary.get("skipped", 0)),
        "failed":       int(summary.get("failed", 0)),
        "elapsed":      summary.get("elapsed", ""),
        "total_on_disk": summary.get("total_on_disk", ""),
        "repos":        repos,
    }


def _parse_verify(output: str) -> dict:
    """Parse gh-verify.sh output into mirrors and bundles lists."""
    mirrors: list[dict] = []
    bundles: list[dict] = []
    problems = 0
    items_checked = 0
    in_mirrors = False
    in_bundles = False
    overall_ok = None

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Strip leading timestamp if present
        m = re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\s+(.*)", line)
        body = m.group(1) if m else line

        if re.search(r"Checking mirrors in", body):
            in_mirrors, in_bundles = True, False
            continue
        if re.search(r"Checking bundles of", body):
            in_mirrors, in_bundles = False, True
            continue
        if re.search(r"Backup total:", body):
            in_mirrors, in_bundles = False, False
            continue

        # items checked
        m2 = re.match(r"items? checked:\s*(\d+)", body)
        if m2:
            items_checked = int(m2.group(1))
            continue

        # Final verdict
        if re.match(r"OK no problems found", body):
            overall_ok = True
            continue
        m3 = re.match(r"(\d+) problems? found", body)
        if m3:
            problems = int(m3.group(1))
            overall_ok = False
            continue

        if in_mirrors:
            m_ok = re.match(r"OK (\S+) \((\d+) refs?, ([^)]+)\)", body)
            if m_ok:
                mirrors.append({
                    "name":   m_ok.group(1),
                    "refs":   int(m_ok.group(2)),
                    "size":   m_ok.group(3).strip(),
                    "status": "ok",
                    "note":   "",
                })
                continue
            m_warn = re.match(r"!!\s+(\S+):\s+(.+)", body)
            if m_warn:
                note = m_warn.group(2)
                status = "warn" if "empty" in note else "error"
                mirrors.append({
                    "name":   m_warn.group(1),
                    "refs":   0,
                    "size":   "",
                    "status": status,
                    "note":   note,
                })
                if status == "error":
                    problems += 1
            continue

        if in_bundles:
            m_ok = re.match(r"OK (\S+\.bundle) \(([^,]+),\s*(\d+) refs?\)", body)
            if m_ok:
                bundles.append({
                    "name":   m_ok.group(1),
                    "size":   m_ok.group(2).strip(),
                    "refs":   int(m_ok.group(3)),
                    "status": "ok",
                    "note":   "",
                })
                continue
            m_err = re.match(r"!!\s+(\S+):\s+(.+)", body)
            if m_err:
                bundles.append({
                    "name":   m_err.group(1),
                    "size":   "",
                    "refs":   0,
                    "status": "error",
                    "note":   m_err.group(2),
                })
                problems += 1

    return {
        "mirrors":       mirrors,
        "bundles":       bundles,
        "items_checked": items_checked,
        "problems":      problems,
        "ok":            overall_ok if overall_ok is not None else (problems == 0),
    }


class GitVaultCollector:
    def __init__(self, config: dict):
        self.backup_root = config.get("backup_root", "/home/tinto/gitbackup-data")
        self.verify_script = config.get("verify_script", "")
        self.timeout = int(config.get("timeout", 120))

    def _latest_log(self) -> str | None:
        log_dir = os.path.join(self.backup_root, "logs")
        try:
            logs = sorted(
                (f for f in os.listdir(log_dir) if f.startswith("backup-") and f.endswith(".log")),
                reverse=True,
            )
            return os.path.join(log_dir, logs[0]) if logs else None
        except OSError:
            return None

    def collect(self) -> dict:
        logger.info("GitVault: starting collection")
        result: dict = {}

        # --- Last backup run from log ---
        log_path = self._latest_log()
        if log_path:
            result["last_backup"] = _parse_log(log_path)
            result["log_file"] = os.path.basename(log_path)
        else:
            result["last_backup"] = {"error": "no log files found"}
            result["log_file"] = ""

        # --- Snapshot dates ---
        snap_root = os.path.join(self.backup_root, "snapshots")
        try:
            snap_dates = sorted(
                d for d in os.listdir(snap_root)
                if os.path.isdir(os.path.join(snap_root, d))
            )
        except OSError:
            snap_dates = []
        result["snapshots"] = snap_dates

        # --- Live verify ---
        if self.verify_script and os.path.isfile(self.verify_script):
            try:
                proc = subprocess.run(
                    [self.verify_script],
                    capture_output=True, text=True,
                    timeout=self.timeout,
                )
                combined = proc.stdout + proc.stderr
                result["verify"] = _parse_verify(combined)
                result["verify"]["ran"] = True
            except subprocess.TimeoutExpired:
                result["verify"] = {"ran": False, "error": "verify timed out"}
            except Exception as exc:
                result["verify"] = {"ran": False, "error": str(exc)}
        else:
            result["verify"] = {"ran": False, "error": "verify script not configured"}

        logger.info("GitVault: collection complete")
        return result
