"""
Flexible Target Input Module.
Handles single domain, file list, stdin, and interactive input.
"""

import sys
import re
import os
import uuid
from pathlib import Path
from core.display import Display
from core.logger import get_logger

logger = get_logger("input_handler")
display = Display()

# Configure unique tldextract cache directory to prevent lock contention
TLD_CACHE_DIR = Path.home() / ".cache" / f"tldextract_reco_nova_{uuid.uuid4().hex[:8]}"
os.environ["TLD_EXTRACT_CACHE_DIR"] = str(TLD_CACHE_DIR)

# Import tldextract after setting cache directory
import tldextract

DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)


def is_valid_domain(domain: str) -> bool:
    domain = domain.strip().lower()
    if not domain:
        return False
    # Strip protocol if user included it
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]
    ext = tldextract.extract(domain)
    return bool(ext.domain and ext.suffix)


def normalize(domain: str) -> str:
    domain = domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]
    domain = domain.split("?")[0]
    return domain


def check_dns_resolves(domain: str) -> bool:
    """Check if domain resolves to avoid DNS failures."""
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        resolver.resolve(domain, 'A')
        return True
    except Exception:
        try:
            # Try AAAA as fallback
            resolver.resolve(domain, 'AAAA')
            return True
        except Exception:
            return False


class InputHandler:
    def from_domain(self, domain: str) -> list[str]:
        norm = normalize(domain)
        if not is_valid_domain(norm):
            display.error(f"Invalid domain: {domain}")
            return []
        
        # Check DNS resolution to prevent unreachable domains
        if not check_dns_resolves(norm):
            display.error(f"Domain does not resolve: {norm}")
            logger.warning(f"DNS resolution failed for: {norm}")
            return []
        
        display.success(f"Target: [bold]{norm}[/bold]")
        logger.info(f"Single domain target: {norm}")
        return [norm]

    def from_file(self, filepath: str) -> list[str]:
        path = Path(filepath)
        if not path.exists():
            display.error(f"File not found: {filepath}")
            return []

        raw = path.read_text().splitlines()
        targets = []
        skipped = 0

        for line in raw:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            norm = normalize(line)
            if is_valid_domain(norm):
                targets.append(norm)
            else:
                skipped += 1
                logger.warning(f"Skipped invalid domain: {line}")

        # Deduplicate
        targets = list(dict.fromkeys(targets))

        display.success(f"Loaded [bold]{len(targets)}[/bold] targets from {filepath}")
        if skipped:
            display.warning(f"Skipped {skipped} invalid entries")

        logger.info(f"Loaded {len(targets)} targets from file: {filepath}")
        return targets

    def from_stdin(self) -> list[str]:
        display.info("Reading targets from stdin...")
        lines = sys.stdin.read().splitlines()
        targets = []

        for line in lines:
            norm = normalize(line)
            if is_valid_domain(norm):
                targets.append(norm)

        targets = list(dict.fromkeys(targets))
        display.success(f"Read [bold]{len(targets)}[/bold] targets from stdin")
        logger.info(f"Loaded {len(targets)} targets from stdin")
        return targets

    def interactive(self) -> list[str]:
        display.console.print()
        display.console.print("  [bold cyan]Interactive Mode[/bold cyan] — Enter domains (one per line, empty line to finish):\n")

        targets = []
        while True:
            try:
                line = input("  > ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if not line:
                if targets:
                    break
                continue

            norm = normalize(line)
            if is_valid_domain(norm):
                targets.append(norm)
                display.success(f"Added: {norm}")
            else:
                display.warning(f"Invalid domain skipped: {line}")

        targets = list(dict.fromkeys(targets))
        logger.info(f"Interactive mode: {len(targets)} targets collected")
        return targets