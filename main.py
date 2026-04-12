#!/usr/bin/env python3
"""
tintospia — infrastructure monitoring dashboard generator.

Usage:
    python main.py [--config config.yaml]
"""

import argparse
import logging
import os
import subprocess
import sys

import yaml

from collectors.veeam import VeeamCollector
from collectors.proxmox import ProxmoxCollector
from collectors.vmware import VMwareCollector
from collectors.paloalto import PaloAltoCollector
from collectors.esxi import ESXiCollector
from generators.hugo import HugoGenerator
from publisher.github import GitHubPublisher

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("tintospia")


def load_config(path: str) -> dict:
    if not os.path.exists(path):
        logger.error("Config file not found: %s", path)
        logger.error("Copy config.example.yaml to config.yaml and fill in your values.")
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def run_collectors(config: dict) -> dict:
    collectors_cfg = config.get("collectors", {})
    results = {}

    collector_map = {
        "veeam": VeeamCollector,
        "proxmox": ProxmoxCollector,
        "vmware": VMwareCollector,
        "paloalto": PaloAltoCollector,
        "esxi": ESXiCollector,
    }

    for name, cls in collector_map.items():
        cfg = collectors_cfg.get(name, {})
        if not cfg.get("enabled", False):
            logger.info("Collector '%s' disabled, skipping", name)
            continue
        try:
            collector = cls(cfg)
            results[name] = collector.collect()
        except Exception as exc:
            logger.error("Collector '%s' raised an exception: %s", name, exc)
            results[name] = {"error": str(exc)}

    return results


def hugo_build(site_path: str):
    logger.info("Hugo: building site")
    result = subprocess.run(
        ["hugo", "--minify"],
        cwd=site_path,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        logger.error("Hugo build failed:\n%s", result.stderr)
        raise RuntimeError("Hugo build failed")
    logger.info("Hugo: build complete\n%s", result.stdout.strip())


def main():
    parser = argparse.ArgumentParser(description="tintospia — infrastructure monitoring dashboard generator")
    parser.add_argument("--config", default="config.yaml", help="Path to config file (default: config.yaml)")
    args = parser.parse_args()

    config = load_config(args.config)

    # 1. Collect data from all enabled sources
    results = run_collectors(config)

    if not results:
        logger.warning("No collectors produced results, nothing to do")
        sys.exit(0)

    # 2. Write Hugo data files
    hugo_cfg = config.get("hugo", {})
    site_path = hugo_cfg.get("site_path", "")
    if not site_path:
        logger.error("hugo.site_path is not configured")
        sys.exit(1)

    generator = HugoGenerator(site_path)
    generator.generate(results)

    # 3. Build Hugo site
    if hugo_cfg.get("build_after_collect", True):
        hugo_build(site_path)

    # 4. Publish to GitHub (optional)
    publish_cfg = config.get("publish", {})
    if publish_cfg.get("enabled", False):
        publisher = GitHubPublisher(publish_cfg)
        publisher.publish()

    logger.info("tintospia: run complete")


if __name__ == "__main__":
    main()
