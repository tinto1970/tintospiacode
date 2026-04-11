# tintospia

Infrastructure monitoring dashboard generator. Collects data from Veeam Backup & Replication, Proxmox VE, VMware vCenter, and Palo Alto firewalls, then generates a static Hugo website that can be published to Cloudflare Pages.

## Features

- **Veeam**: backup jobs, sessions, repositories, managed servers
- **Proxmox**: nodes, VMs, containers, storage
- **VMware**: hosts, VMs, datastores, clusters (REST API or PowerCLI)
- **Palo Alto**: system info, interfaces, session summary, HA state, licenses
- Configurable: enable/disable each collector independently
- Optional automatic push to GitHub for Cloudflare Pages publishing
- Designed to run as a cron job (e.g., every 10 minutes)

## Requirements

- Python 3.12+
- `python3.12-venv` (Ubuntu: `sudo apt install python3.12-venv`)
- Hugo extended (latest)
- `pwsh` (PowerShell Core) — only if using VMware PowerCLI mode

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp config.example.yaml config.yaml
# edit config.yaml with your credentials and paths
```

## Usage

```bash
.venv/bin/python main.py
# or with a custom config path:
.venv/bin/python main.py --config /etc/tintospia/config.yaml
```

## Cron example

Run every 10 minutes and log output:

```
*/10 * * * * cd /path/to/tintospiacode && .venv/bin/python main.py >> /var/log/tintospia.log 2>&1
```

## Configuration

Copy `config.example.yaml` to `config.yaml`. The file is gitignored and never committed.

Key settings:

| Key | Description |
|-----|-------------|
| `collectors.<name>.enabled` | Enable/disable each data source |
| `hugo.site_path` | Absolute path to the tintospiasite directory |
| `hugo.build_after_collect` | Run `hugo build` after data collection |
| `publish.enabled` | Push tintospiasite to GitHub after build |
| `publish.branch` | Target branch (default: `main`) |

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).
