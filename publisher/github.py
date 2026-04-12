"""
GitHub publisher.
Commits and pushes the Hugo site repository after each data update.
"""

import json
import logging
import os
import subprocess
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class GitHubPublisher:
    def __init__(self, config: dict):
        self.repo_path = config["repo_path"]
        self.branch = config.get("branch", "main")
        self.remote = config.get("remote", "origin")
        self.commit_message_tpl = config.get("commit_message", "data: update {timestamp}")

    def _run(self, *args):
        result = subprocess.run(
            list(args),
            cwd=self.repo_path,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git {args[1]} failed: {result.stderr.strip()}")
        return result.stdout.strip()

    def publish(self):
        logger.info("Publisher: starting git publish")

        status = self._run("git", "status", "--porcelain")
        if not status:
            logger.info("Publisher: no changes to commit, skipping")
            return

        self._run("git", "add", "-A")

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        message = self.commit_message_tpl.format(timestamp=timestamp)
        self._run("git", "commit", "-m", message)

        # Inject build info (SHA + build number) into the commit we just made
        sha   = self._run("git", "rev-parse", "--short", "HEAD")
        count = self._run("git", "rev-list", "--count", "HEAD")
        build_path = os.path.join(self.repo_path, "data", "meta", "build.json")
        with open(build_path, "w") as f:
            json.dump({"number": int(count), "sha": sha}, f)
        self._run("git", "add", build_path)
        self._run("git", "commit", "--amend", "--no-edit")

        self._run("git", "push", self.remote, self.branch)
        logger.info("Publisher: pushed to %s/%s", self.remote, self.branch)
