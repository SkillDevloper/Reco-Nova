"""
Continuous Recon Monitoring System.
Detects newly exposed or changed assets between scans.
"""

import asyncio
import json
import time
from pathlib import Path
from datetime import datetime
from core.display import Display
from core.logger import get_logger
from core.scan_engine import ScanEngine

logger = get_logger("monitor")
display = Display()

DB_DIR = Path("database")
DB_DIR.mkdir(parents=True, exist_ok=True)


class Monitor:
    def __init__(self, domain: str, interval: int = 3600):
        self.domain = domain
        self.interval = interval
        self.db_file = DB_DIR / f"{domain}_baseline.json"

    async def run(self):
        display.section(f"Monitoring Mode — {self.domain}")
        display.info(f"Scan interval: [bold]{self.interval}[/bold] seconds")

        iteration = 0
        while True:
            iteration += 1
            display.info(f"Scan #{iteration} — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

            # Run scan
            engine = ScanEngine(
                targets=[self.domain],
                threads=10,
                timeout=10,
                output_dir="output",
                full_scan=False,
                generate_graph=False,
                screenshots=False,
                passive_only=True,
                verbose=False,
            )
            await engine.run()

            # Load current scan data
            current_data = self._load_current_scan()

            if self.db_file.exists():
                previous_data = json.loads(self.db_file.read_text())
                diff = self._diff(previous_data, current_data)
                self._report_diff(diff)
            else:
                display.info("First scan — establishing baseline.")

            # Save as new baseline
            self.db_file.write_text(json.dumps(current_data, indent=2))

            if iteration == 1 and not self.db_file.exists():
                display.success("Baseline established.")

            display.info(f"Next scan in [bold]{self.interval}[/bold] seconds...")
            await asyncio.sleep(self.interval)

    def _load_current_scan(self) -> dict:
        domain_dir = Path("output") / self.domain
        data = {
            "timestamp": datetime.now().isoformat(),
            "subdomains": [],
            "live_hosts": [],
            "apis": [],
            "sensitive_files": [],
            "parameters": [],
        }

        if (domain_dir / "subdomains.txt").exists():
            data["subdomains"] = (domain_dir / "subdomains.txt").read_text().splitlines()
        if (domain_dir / "live_hosts.txt").exists():
            data["live_hosts"] = (domain_dir / "live_hosts.txt").read_text().splitlines()
        if (domain_dir / "apis.txt").exists():
            data["apis"] = (domain_dir / "apis.txt").read_text().splitlines()
        if (domain_dir / "sensitive_files.txt").exists():
            data["sensitive_files"] = (domain_dir / "sensitive_files.txt").read_text().splitlines()
        if (domain_dir / "parameters.txt").exists():
            data["parameters"] = [
                line.replace("[PARAM] ", "").strip()
                for line in (domain_dir / "parameters.txt").read_text().splitlines()
                if line.startswith("[PARAM]")
            ]

        return data

    def _diff(self, previous: dict, current: dict) -> dict:
        diff = {}
        for key in ["subdomains", "live_hosts", "apis", "sensitive_files", "parameters"]:
            prev_set = set(previous.get(key, []))
            curr_set = set(current.get(key, []))
            added = curr_set - prev_set
            removed = prev_set - curr_set
            if added or removed:
                diff[key] = {"added": sorted(added), "removed": sorted(removed)}
        return diff

    def _report_diff(self, diff: dict):
        if not diff:
            display.success("No changes detected.")
            return

        display.section("CHANGE DETECTION REPORT")

        for key, changes in diff.items():
            label = key.replace("_", " ").title()
            if changes["added"]:
                display.warning(f"NEW {label}:")
                for item in changes["added"]:
                    display.found(f"  + {item}")
            if changes["removed"]:
                display.info(f"REMOVED {label}:")
                for item in changes["removed"]:
                    display.console.print(f"    [dim]- {item}[/dim]")

        # Save diff report
        report_dir = Path("reports")
        report_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        report_file = report_dir / f"{self.domain}_diff_{timestamp}.json"
        report_file.write_text(json.dumps(diff, indent=2))
        display.info(f"Diff report saved: {report_file}")