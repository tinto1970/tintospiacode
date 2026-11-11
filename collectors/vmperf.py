"""
VMware VM performance accumulator.
Reads current quick-stats from ESXi collector results, appends a sample to a
rolling JSON file on disk (max 288 entries ≈ 48 h at 10-min intervals).
"""

import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class VMPerfAccumulator:
    MAX_SAMPLES = 288  # 48 h at ~10 min intervals

    def __init__(self, config: dict):
        self.path = config.get(
            "metrics_path",
            "/home/tinto/tintospia-metrics/vmware_perf.json",
        )

    def accumulate(self, esxi_hosts: list) -> dict:
        """Build a sample from ESXi host results, append to rolling file, return all data."""
        snapshot = {}
        for host_result in esxi_hosts:
            if "error" in host_result:
                continue
            host = host_result.get("host", "")
            for vm in host_result.get("vm_perf", []):
                name = vm.get("name", "")
                if not name:
                    continue
                snapshot[name] = {
                    "host":         host,
                    "cpu_pct":      vm.get("cpu_pct"),
                    "ram_gb":       vm.get("ram_gb"),
                    "ram_total_gb": vm.get("ram_total_gb"),
                    "disk_gb":      vm.get("disk_gb"),
                    "power":        vm.get("power", ""),
                }

        samples = []
        if os.path.exists(self.path):
            try:
                with open(self.path, encoding="utf-8") as f:
                    data = json.load(f)
                    samples = data.get("samples", [])
            except Exception as exc:
                logger.warning("VMPerf: could not read rolling file — %s", exc)

        samples.append({
            "ts":  datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "vms": snapshot,
        })
        samples = samples[-self.MAX_SAMPLES:]

        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump({"samples": samples}, f)
        except Exception as exc:
            logger.error("VMPerf: could not write rolling file — %s", exc)

        all_names: set = set()
        for s in samples:
            all_names.update(s.get("vms", {}).keys())

        return {
            "samples":  samples,
            "vm_names": sorted(all_names),
        }
