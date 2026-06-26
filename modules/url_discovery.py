"""
URL & Parameter Discovery Engine.
Collects URLs from Wayback Machine, CommonCrawl, and live crawling.
Extracts all parameters for vulnerability analysis.
"""

import asyncio
import aiohttp
import re
import shutil
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
from core.display import Display
from core.logger import get_logger
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.live import Live

logger = get_logger("url_discovery")
display = Display()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}

EXCLUDED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf",
    ".zip", ".tar", ".gz",
}


class URLDiscovery:
    def __init__(self, domain: str, live_hosts: list[str],
                 output_dir: Path, timeout: int = 10, threads: int = 20, **kwargs):
        self.domain = domain
        self.live_hosts = live_hosts
        self.output_dir = output_dir
        self.timeout = timeout
        self.threads = threads
        # Accept delay_range from kwargs to prevent 'unexpected keyword argument' crashes
        self.delay_range = kwargs.get('delay_range', None)
        self.urls: set = set()
        self.parameters: dict = {}  # param_name -> set of URLs

    async def run(self) -> tuple[list[str], dict]:
        display.info(f"Starting URL discovery for [bold]{self.domain}[/bold]")
        
        # Create progress bar for URL discovery
        progress = display.progress_bar()
        
        with Live(progress, refresh_per_second=10):
            task_wayback = progress.add_task("Wayback Machine", total=100)
            task_commoncrawl = progress.add_task("CommonCrawl", total=100)
            task_crawl = progress.add_task("Live Crawling", total=100)
            
            # Track success of primary methods
            wayback_success = False
            commoncrawl_success = False
            
            # Run primary methods
            wayback_result = await self._wayback_machine(progress, task_wayback)
            commoncrawl_result = await self._commoncrawl(progress, task_commoncrawl)
            
            # Check if we need fallbacks (less than 50 URLs found)
            if len(self.urls) < 50:
                display.warning("Primary sources insufficient, activating fallbacks...")
                
                # Add fallback tasks
                task_gauplus = progress.add_task("gauplus fallback", total=100)
                task_katana = progress.add_task("katana fallback", total=100)
                
                await asyncio.gather(
                    self._gauplus_fallback(progress, task_gauplus),
                    self._katana_fallback(progress, task_katana),
                    return_exceptions=True
                )
            
            # Always run live crawling
            await self._crawl_live_hosts(progress, task_crawl)

        # Filter URLs
        self.urls = {u for u in self.urls if self._is_relevant(u)}

        # Extract parameters from all URLs
        self._extract_parameters()

        # Save results (only if not empty)
        if self.urls:
            url_file = self.output_dir / "urls.txt"
            url_file.write_text("\n".join(sorted(self.urls)))
        
        if self.parameters:
            param_lines = []
            for param, urls in sorted(self.parameters.items()):
                param_lines.append(f"{param} ({len(urls)} URLs):")
                for u in list(urls)[:3]:
                    param_lines.append(f"  {u}")
            param_file = self.output_dir / "parameters.txt"
            param_file.write_text("\n".join(param_lines))

        display.success(f"URLs discovered: [bold green]{len(self.urls)}[/bold green]")
        display.success(f"Parameters found: [bold green]{len(self.parameters)}[/bold green]")

        logger.info(f"URLs: {len(self.urls)}, Parameters: {len(self.parameters)}")
        return sorted(self.urls), self.parameters

    # ── Wayback Machine ───────────────────────────────────────────

    async def _wayback_machine(self, progress: Progress, task_id: int):
        url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{self.domain}/*&output=text&fl=original"
            f"&collapse=urlkey&limit=10000&filter=statuscode:200"
        )
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            ) as session:
                async with session.get(url, headers=HEADERS) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.splitlines():
                            line = line.strip()
                            if line and self.domain in line:
                                self.urls.add(line)
            logger.debug(f"Wayback Machine: fetched for {self.domain}")
        except Exception as e:
            logger.warning(f"Wayback failed: {e}")

    # ── CommonCrawl ───────────────────────────────────────────────

    async def _commoncrawl(self, progress: Progress, task_id: int):
        url = (
            f"https://index.commoncrawl.org/CC-MAIN-2024-10-index"
            f"?url=*.{self.domain}&output=json&limit=5000"
        )
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=20)
            ) as session:
                async with session.get(url, headers=HEADERS) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        import json
                        for line in text.splitlines():
                            try:
                                data = json.loads(line)
                                u = data.get("url", "")
                                if u and self.domain in u:
                                    self.urls.add(u)
                            except Exception:
                                pass
            logger.debug(f"CommonCrawl done for {self.domain}")
        except Exception as e:
            logger.warning(f"CommonCrawl failed: {e}")

    # ── Live Crawler ──────────────────────────────────────────────

    async def _crawl_live_hosts(self, progress: Progress, task_id: int):
        semaphore = asyncio.Semaphore(self.threads)
        targets = self.live_hosts[:20]  # Top 20 live hosts

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers=HEADERS,
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:
            tasks = [self._crawl_page(session, semaphore, host) for host in targets]
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _crawl_page(self, session, semaphore, base_url: str, depth: int = 2):
        """Crawl a page and follow links up to given depth."""
        visited = set()
        queue = [(base_url, 0)]

        while queue:
            url, current_depth = queue.pop(0)
            if url in visited or current_depth > depth:
                continue
            visited.add(url)

            async with semaphore:
                try:
                    async with session.get(url, allow_redirects=True, max_redirects=3) as resp:
                        if resp.status == 200:
                            ct = resp.headers.get("Content-Type", "")
                            if "html" in ct:
                                body = await resp.text(errors="ignore")
                                self.urls.add(str(resp.url))
                                new_links = self._extract_links(body, str(resp.url))
                                for link in new_links:
                                    if link not in visited and self.domain in link:
                                        queue.append((link, current_depth + 1))
                                        self.urls.add(link)
                except Exception:
                    pass

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        links = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all(["a", "link", "script", "form"], href=True):
                href = tag.get("href") or tag.get("src") or tag.get("action", "")
                if href:
                    full = urljoin(base_url, href)
                    if self.domain in full:
                        links.append(full)
        except Exception:
            pass
        return links

    def _is_relevant(self, url: str) -> bool:
        if not url.startswith("http"):
            return False
        parsed = urlparse(url)
        ext = "." + parsed.path.split(".")[-1].lower() if "." in parsed.path else ""
        return ext not in EXCLUDED_EXTENSIONS

    def _extract_parameters(self):
        """Extract all URL parameters and group by name."""
        for url in self.urls:
            try:
                parsed = urlparse(url)
                if parsed.query:
                    params = parse_qs(parsed.query, keep_blank_values=True)
                    for param_name in params:
                        clean = param_name.strip().lower()
                        if clean not in self.parameters:
                            self.parameters[clean] = set()
                        self.parameters[clean].add(url)
            except Exception:
                pass

    # ── Fallback Methods ─────────────────────────────────────────────

    async def _gauplus_fallback(self, progress: Progress, task_id: int):
        """Fallback: Use gauplus for active URL discovery."""
        if not shutil.which("gauplus"):
            logger.info("gauplus not found, skipping fallback")
            return
        
        display.info("Wayback/CommonCrawl failed, trying gauplus fallback...")
        progress.update(task_id, description="gauplus fallback")
        
        try:
            # Run gauplus on domain
            proc = await asyncio.create_subprocess_exec(
                "gauplus", "-subs", "-t", "100", self.domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            
            if proc.returncode == 0:
                urls = stdout.decode().splitlines()
                for url in urls:
                    url = url.strip()
                    if url and self.domain in url:
                        self.urls.add(url)
                logger.info(f"gauplus found {len(urls)} URLs")
                display.success(f"gauplus fallback: {len(urls)} URLs discovered")
            else:
                logger.warning(f"gauplus failed: {stderr.decode()}")
        except Exception as e:
            logger.warning(f"gauplus fallback error: {e}")

    async def _katana_fallback(self, progress: Progress, task_id: int):
        """Fallback: Use katana for active crawling."""
        if not shutil.which("katana"):
            logger.info("katana not found, skipping fallback")
            return
        
        display.info("Trying katana active crawling fallback...")
        progress.update(task_id, description="katana fallback")
        
        try:
            # Run katana on live hosts
            targets = self.live_hosts[:10]  # Top 10 hosts
            for target in targets:
                proc = await asyncio.create_subprocess_exec(
                    "katana", "-u", target, "-depth", "2", "-js-crawl",
                    "-no-sandbox", "-system-chrome",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
                
                if proc.returncode == 0:
                    urls = stdout.decode().splitlines()
                    for url in urls:
                        url = url.strip()
                        if url and self.domain in url:
                            self.urls.add(url)
                    logger.info(f"katana found {len(urls)} URLs from {target}")
        except Exception as e:
            logger.warning(f"katana fallback error: {e}")