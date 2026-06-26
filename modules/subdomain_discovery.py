"""
Attack Surface Discovery Engine — Subdomain Discovery.
Uses subfinder, assetfinder, amass, crt.sh, and DNS brute-force.
"""

import asyncio
import subprocess
import shutil
import random
import aiohttp
import json
import dns.resolver
from pathlib import Path
from core.display import Display
from core.logger import get_logger

logger = get_logger("subdomain_discovery")
display = Display()

# Common subdomains for brute-force fallback
COMMON_SUBS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "api", "dev", "staging",
    "stage", "test", "testing", "qa", "uat", "prod", "production", "beta",
    "admin", "administrator", "portal", "app", "apps", "web", "webmail",
    "dashboard", "panel", "control", "cp", "cpanel", "whm", "plesk",
    "internal", "intranet", "private", "secure", "ssl", "vpn", "remote",
    "git", "gitlab", "github", "bitbucket", "jira", "confluence", "wiki",
    "jenkins", "ci", "cd", "build", "deploy", "monitor", "monitoring",
    "grafana", "kibana", "elastic", "logstash", "prometheus",
    "db", "database", "mysql", "postgres", "mongodb", "redis", "cache",
    "cdn", "static", "assets", "media", "img", "images", "files",
    "shop", "store", "cart", "checkout", "payment", "billing",
    "support", "help", "docs", "documentation", "kb", "forum",
    "blog", "news", "press", "status", "health", "ping",
    "mobile", "m", "wap", "legacy", "old", "new", "v2", "v3",
    "auth", "login", "sso", "oauth", "id", "account", "accounts",
    "data", "analytics", "report", "reports", "stats", "metrics",
    "backup", "archive", "download", "downloads", "upload", "uploads",
    "api2", "api-v2", "rest", "graphql", "ws", "websocket",
    "ns1", "ns2", "mx", "mx1", "mx2", "mail2", "smtp2",
    "sandbox", "preview", "demo", "example", "temp", "tmp",
    "crm", "erp", "ldap", "active-directory", "ad",
]


class SubdomainDiscovery:
    def __init__(self, domain: str, output_dir: Path, timeout: int = 10, 
                 passive_only: bool = False, delay_range: tuple[float, float] | None = None):
        self.domain = domain
        self.output_dir = output_dir
        self.timeout = timeout
        self.passive_only = passive_only
        self.delay_range = delay_range
        self.subdomains: set = set()

    async def run(self) -> list[str]:
        display.info(f"Starting subdomain discovery for [bold]{self.domain}[/bold]")
        if self.delay_range:
            display.info(f"Execution jitter enabled: {self.delay_range[0]}-{self.delay_range[1]}s delay")

        tasks = [
            self._crt_sh(),
            self._hackertarget(),
            self._alienvault(),
            self._rapiddns(),
            self._threatcrowd(),
        ]

        # Add tool-based discovery if available
        if shutil.which("subfinder"):
            tasks.append(self._run_subfinder())
            # Add aggressive passive DNS for better coverage
            tasks.append(self._run_subfinder_passive_aggressive())
        if shutil.which("assetfinder"):
            tasks.append(self._run_assetfinder())
        if shutil.which("amass") and not self.passive_only:
            tasks.append(self._run_amass())

        # DNS brute-force (unless passive only)
        if not self.passive_only:
            tasks.append(self._dns_bruteforce())

        await asyncio.gather(*tasks, return_exceptions=True)

        # Always include the root domain
        self.subdomains.add(self.domain)

        # Validate discovered subdomains
        valid = await self._validate_subdomains()

        # Save results (only if not empty)
        if valid:
            out_file = self.output_dir / "subdomains.txt"
            out_file.write_text("\n".join(sorted(valid)))

        display.success(f"Subdomains discovered: [bold green]{len(valid)}[/bold green]")
        logger.info(f"[{self.domain}] Subdomains: {len(valid)}")
        return sorted(valid)

    # ── Passive Sources ───────────────────────────────────────────

    async def _apply_jitter(self):
        """Apply random delay if execution jitter is enabled."""
        if self.delay_range:
            await asyncio.sleep(random.uniform(*self.delay_range))

    async def _crt_sh(self):
        await self._apply_jitter()
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout * 2)
            ) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for entry in data:
                            names = entry.get("name_value", "")
                            for name in names.split("\n"):
                                name = name.strip().lower().lstrip("*.")
                                if name.endswith(f".{self.domain}") or name == self.domain:
                                    self.subdomains.add(name)
            logger.debug(f"crt.sh done for {self.domain}")
        except Exception as e:
            logger.warning(f"crt.sh failed: {e}")

    async def _hackertarget(self):
        await self._apply_jitter()
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.splitlines():
                            if "," in line:
                                sub = line.split(",")[0].strip().lower()
                                if sub.endswith(f".{self.domain}") or sub == self.domain:
                                    self.subdomains.add(sub)
        except Exception as e:
            logger.warning(f"hackertarget failed: {e}")

    async def _alienvault(self):
        await self._apply_jitter()
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for record in data.get("passive_dns", []):
                            hostname = record.get("hostname", "").lower()
                            if hostname.endswith(f".{self.domain}") or hostname == self.domain:
                                self.subdomains.add(hostname)
        except Exception as e:
            logger.warning(f"alienvault failed: {e}")

    async def _rapiddns(self):
        await self._apply_jitter()
        url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as session:
                async with session.get(url, headers={"User-Agent": "Mozilla/5.0"}) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        import re
                        matches = re.findall(
                            rf'([\w\-\.]+\.{re.escape(self.domain)})', text
                        )
                        for m in matches:
                            self.subdomains.add(m.lower())
        except Exception as e:
            logger.warning(f"rapiddns failed: {e}")

    async def _threatcrowd(self):
        await self._apply_jitter()
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for sub in data.get("subdomains", []):
                            sub = sub.strip().lower()
                            if sub.endswith(f".{self.domain}") or sub == self.domain:
                                self.subdomains.add(sub)
        except Exception as e:
            logger.warning(f"threatcrowd failed: {e}")

    # ── Tool-based Discovery ──────────────────────────────────────

    async def _run_subfinder(self):
        try:
            # Enhanced subfinder with aggressive passive sources
            # Use multiple sources and increase timeout for better coverage
            cmd = [
                "subfinder", "-d", self.domain, "-silent",
                "-sources", "all",  # Use all available sources
                "-timeout", "30",    # Increase timeout per source
                "-max-time", "300",  # Total max time 5 minutes
                "-rate-limit", "10", # Rate limit to avoid blocking
                "-active"           # Enable active enumeration
            ]
            
            # Try with enhanced configuration first
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            
            if proc.returncode == 0:
                for line in stdout.decode().splitlines():
                    sub = line.strip().lower()
                    if sub and self.domain in sub:
                        self.subdomains.add(sub)
                logger.debug(f"Enhanced subfinder found {len(stdout.decode().splitlines())} subdomains for {self.domain}")
            else:
                # Fallback to basic subfinder if enhanced fails
                logger.warning(f"Enhanced subfinder failed: {stderr.decode()}, trying basic mode")
                proc_fallback = await asyncio.create_subprocess_exec(
                    "subfinder", "-d", self.domain, "-silent",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout_fallback, _ = await asyncio.wait_for(proc_fallback.communicate(), timeout=120)
                for line in stdout_fallback.decode().splitlines():
                    sub = line.strip().lower()
                    if sub:
                        self.subdomains.add(sub)
                logger.debug(f"Basic subfinder fallback done for {self.domain}")
                
        except asyncio.TimeoutError:
            logger.warning(f"subfinder timeout for {self.domain} - using partial results")
        except Exception as e:
            logger.warning(f"subfinder failed: {e}")

    async def _run_subfinder_passive_aggressive(self):
        """Additional aggressive passive DNS enumeration."""
        try:
            # Run subfinder multiple times with different source configurations
            configs = [
                ["-sources", "shodan,censys,spyse,netlas,zoomeye"],  # Intelligence sources
                ["-sources", "virustotal,threatbook,maltiverse,urlscan"],  # Threat intel sources  
                ["-sources", "crtsh,ctsearch,google,bing,yahoo"],      # Certificate sources
                ["-sources", "github,gist,pastebin,gitlab"],           # Code sources
            ]
            
            for i, sources in enumerate(configs):
                try:
                    cmd = ["subfinder", "-d", self.domain, "-silent"] + sources
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=90)
                    
                    for line in stdout.decode().splitlines():
                        sub = line.strip().lower()
                        if sub and self.domain in sub:
                            self.subdomains.add(sub)
                    
                    logger.debug(f"Subfinder config {i+1} found {len(stdout.decode().splitlines())} subdomains")
                    await asyncio.sleep(2)  # Brief delay between configs
                    
                except Exception as e:
                    logger.debug(f"Subfinder config {i+1} failed: {e}")
                    continue
                    
        except Exception as e:
            logger.warning(f"Aggressive passive DNS failed: {e}")

    async def _run_assetfinder(self):
        try:
            proc = await asyncio.create_subprocess_exec(
                "assetfinder", "--subs-only", self.domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            for line in stdout.decode().splitlines():
                sub = line.strip().lower()
                if sub:
                    self.subdomains.add(sub)
            logger.debug(f"assetfinder done for {self.domain}")
        except Exception as e:
            logger.warning(f"assetfinder failed: {e}")

    async def _run_amass(self):
        try:
            proc = await asyncio.create_subprocess_exec(
                "amass", "enum", "-passive", "-d", self.domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
            for line in stdout.decode().splitlines():
                sub = line.strip().lower()
                if sub:
                    self.subdomains.add(sub)
            logger.debug(f"amass done for {self.domain}")
        except Exception as e:
            logger.warning(f"amass failed: {e}")

    # ── DNS Brute-force ───────────────────────────────────────────

    async def _dns_bruteforce(self):
        loop = asyncio.get_event_loop()
        semaphore = asyncio.Semaphore(50)

        async def resolve(sub):
            async with semaphore:
                fqdn = f"{sub}.{self.domain}"
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 3
                    resolver.lifetime = 3
                    await loop.run_in_executor(
                        None, lambda: resolver.resolve(fqdn, "A")
                    )
                    self.subdomains.add(fqdn)
                except Exception:
                    pass

        tasks = [resolve(sub) for sub in COMMON_SUBS]
        await asyncio.gather(*tasks, return_exceptions=True)
        logger.debug(f"DNS brute-force done for {self.domain}")

    # ── Validation ────────────────────────────────────────────────

    async def _validate_subdomains(self) -> list[str]:
        """Resolve each subdomain to filter out dead ones."""
        loop = asyncio.get_event_loop()
        semaphore = asyncio.Semaphore(50)
        valid = []

        async def check(sub):
            async with semaphore:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 3
                    resolver.lifetime = 3
                    await loop.run_in_executor(
                        None, lambda: resolver.resolve(sub, "A")
                    )
                    valid.append(sub)
                except Exception:
                    pass

        tasks = [check(sub) for sub in self.subdomains]
        await asyncio.gather(*tasks, return_exceptions=True)
        return sorted(valid)