"""
Sensitive Asset Detection Module.
Checks for exposed .env, .git, backups, configs, and other sensitive files.
Includes smart false-positive filtering using a per-host baseline response.
"""

import asyncio
import aiohttp
import hashlib
import random
import string
import re
from pathlib import Path
from urllib.parse import urlparse
from config.settings import config
from core.display import Display
from core.logger import get_logger

logger = get_logger("sensitive_assets")
display = Display()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}

CLOUD_PATTERNS = [
    # AWS S3
    (r"https?://([a-z0-9\-]+)\.s3\.amazonaws\.com", "AWS S3"),
    (r"https?://s3\.amazonaws\.com/([a-z0-9\-]+)", "AWS S3"),
    (r"https?://([a-z0-9\-]+)\.s3\.[a-z0-9\-]+\.amazonaws\.com", "AWS S3"),
    # Azure
    (r"https?://([a-z0-9\-]+)\.blob\.core\.windows\.net", "Azure Blob"),
    # GCP
    (r"https?://([a-z0-9\-]+)\.storage\.googleapis\.com", "GCP Storage"),
    (r"https?://storage\.cloud\.google\.com/([a-z0-9\-]+)", "GCP Storage"),
    # Cloudflare R2
    (r"https?://([a-z0-9\-]+)\.r2\.cloudflarestorage\.com", "Cloudflare R2"),
    # DigitalOcean Spaces
    (r"https?://([a-z0-9\-]+)\.digitaloceanspaces\.com", "DO Spaces"),
]


class SensitiveAssetDetection:
    def __init__(self, live_hosts: list[str], output_dir: Path,
                 timeout: int = 10, threads: int = 20, **kwargs):
        self.live_hosts = live_hosts
        self.output_dir = output_dir
        self.timeout = timeout
        self.threads = threads
        # Accept delay_range from kwargs to prevent 'unexpected keyword argument' crashes
        self.delay_range = kwargs.get('delay_range', None)
        self.found: list[dict] = []
        self.cloud_assets: list[str] = []
        # origin ("scheme://host") → baseline dict(hash, length, title, status)
        self._baselines: dict[str, dict] = []

    async def run(self) -> tuple[list[dict], list[str]]:
        display.info(f"Scanning for sensitive files across [bold]{len(self.live_hosts)}[/bold] hosts...")

        semaphore = asyncio.Semaphore(self.threads)
        connector = aiohttp.TCPConnector(ssl=False, limit=self.threads)

        async with aiohttp.ClientSession(
            connector=connector,
            headers=HEADERS,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
        ) as session:
            # Build per-host baseline using a guaranteed non-existent path
            await self._build_baselines(session)

            tasks = []
            for host in self.live_hosts:
                for path in config.sensitive_files:
                    url = host.rstrip("/") + "/" + path.lstrip("/")
                    tasks.append(self._check(session, semaphore, url))
            await asyncio.gather(*tasks, return_exceptions=True)

        # Detect cloud assets from found URLs
        self._detect_cloud_assets()

        # Save results
        self._save_results()

        display.success(f"Sensitive files found: [bold red]{len(self.found)}[/bold red]")
        display.success(f"Cloud assets detected: [bold yellow]{len(self.cloud_assets)}[/bold yellow]")

        logger.info(f"Sensitive: {len(self.found)}, Cloud: {len(self.cloud_assets)}")
        return self.found, self.cloud_assets

    async def _build_baselines(self, session):
        """Request a clearly non-existent path on each host to fingerprint fake 200/404 pages."""
        if not self.live_hosts:
            return

        semaphore = asyncio.Semaphore(min(self.threads, 10))
        tasks = [
            self._baseline_for_host(session, semaphore, host)
            for host in self.live_hosts
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _baseline_for_host(self, session, semaphore, host_url: str):
        """Capture baseline hash/length/title for non-existent resource on a host."""
        async with semaphore:
            try:
                nonce = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
                fake_path = f"/reconova-nonexistent-{nonce}.html"
                url = host_url.rstrip("/") + fake_path
                async with session.get(url, allow_redirects=False) as resp:
                    body = await resp.text(errors="ignore")
                    origin = self._origin_from_url(str(resp.url))
                    baseline = {
                        "hash": hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest(),
                        "length": len(body),
                        "title": self._extract_title(body),
                        "status": resp.status,
                    }
                    self._baselines[origin] = baseline
            except Exception:
                # Baseline is best-effort; if it fails we fall back to simple status checks
                return

    async def _check(self, session, semaphore, url: str):
        async with semaphore:
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    if resp.status in [200, 206]:
                        ct = resp.headers.get("Content-Type", "")
                        body = await resp.text(errors="ignore")
                        body_len = len(body)
                        body_hash = hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()
                        title = self._extract_title(body)

                        origin = self._origin_from_url(str(resp.url))
                        baseline = self._baselines.get(origin)

                        # Smart false-positive filtering:
                        # discard responses that look identical to the baseline
                        if baseline:
                            same_hash = body_hash == baseline.get("hash")
                            same_shape = (
                                body_len == baseline.get("length")
                                and title == baseline.get("title")
                                and resp.status == baseline.get("status")
                            )
                            if same_hash or same_shape:
                                return

                        size = resp.headers.get("Content-Length", "?")
                        body_preview = body[:200]

                        severity = self._classify_severity(url, body_preview)
                        finding = {
                            "url": url,
                            "status": resp.status,
                            "size": size,
                            "content_type": ct,
                            "severity": severity,
                            "preview": body_preview[:100],
                        }
                        self.found.append(finding)
                        display.found(
                            f"[{severity}] [bold]{url}[/bold] "
                            f"[dim]({resp.status}, {size}b)[/dim]"
                        )
                        logger.info(f"Sensitive found: {url} [{resp.status}]")

            except Exception:
                pass

    def _origin_from_url(self, url: str) -> str:
        """Normalize a URL to its scheme://host origin for baseline lookups."""
        try:
            parsed = urlparse(url)
            if parsed.scheme and parsed.netloc:
                return f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            pass
        # Fallback best-effort origin
        if "://" in url:
            parts = url.split("/", 3)
            return "/".join(parts[:3])
        return url

    def _extract_title(self, html: str) -> str:
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if match:
            return re.sub(r"\s+", " ", match.group(1)).strip()[:80]
        return ""

    def _classify_severity(self, url: str, preview: str) -> str:
        critical_patterns = [
            ".env", ".git/config", "id_rsa", "credentials",
            "database.sql", ".pem", "secret"
        ]
        high_patterns = [
            "backup", "config.php", "wp-config", ".htaccess",
            "composer.json", "package.json"
        ]

        url_lower = url.lower()
        if any(p in url_lower for p in critical_patterns):
            # Check if it actually contains sensitive data
            if any(kw in preview.lower() for kw in ["password", "secret", "key", "token", "db_"]):
                return "CRITICAL"
            return "HIGH"
        if any(p in url_lower for p in high_patterns):
            return "HIGH"
        return "MEDIUM"

    def _detect_cloud_assets(self):
        import re
        checked_urls = [f["url"] for f in self.found]
        for host in self.live_hosts:
            checked_urls.append(host)

        for url in checked_urls:
            for pattern, cloud_type in CLOUD_PATTERNS:
                match = re.search(pattern, url, re.IGNORECASE)
                if match:
                    asset = f"{cloud_type}: {url}"
                    if asset not in self.cloud_assets:
                        self.cloud_assets.append(asset)

    def _save_results(self):
        # Save results (only if not empty)
        if self.found:
            lines = []
            for f in sorted(self.found, key=lambda x: x["severity"]):
                lines.append(
                    f"[{f['severity']:8}] {f['url']}  "
                    f"(status={f['status']}, size={f['size']}b)"
                )
            out_file = self.output_dir / "sensitive_files.txt"
            out_file.write_text("\n".join(lines))

        if self.cloud_assets:
            cloud_file = self.output_dir / "cloud_assets.txt"
            cloud_file.write_text("\n".join(self.cloud_assets))