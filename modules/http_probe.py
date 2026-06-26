"""
HTTP Probing & Endpoint Discovery Engine.
Probes live hosts, discovers endpoints, and detects API paths.
"""

import asyncio
import aiohttp
import shutil
import re
import random
from pathlib import Path
from urllib.parse import urljoin, urlparse
from core.display import Display
from core.logger import get_logger
from core.utils import get_stealth_headers, get_random_ua

logger = get_logger("http_probe")
display = Display()

# Extended ports to scan
EXTENDED_PORTS = [80, 443, 8080, 8443, 8888, 9000]

BASE_HEADERS = get_stealth_headers()

API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/graphql", "/swagger", "/swagger.json",
    "/swagger-ui", "/swagger-ui.html", "/openapi.json",
    "/v1", "/v2", "/v3",
    "/api/swagger", "/api/docs",
    "/wp-json", "/wp-json/wp/v2",
    "/_api", "/_rest",
]


class ProbeResult:
    def __init__(self, url: str, status: int, title: str, server: str,
                 content_type: str, redirect: str, length: int):
        self.url = url
        self.status = status
        self.title = title
        self.server = server
        self.content_type = content_type
        self.redirect = redirect
        self.length = length
        self.has_login = False
        self.has_admin = False
        self.is_api = False

    def __repr__(self):
        return f"<ProbeResult {self.url} [{self.status}]>"


class HTTPProbe:
    def __init__(self, subdomains: list[str], output_dir: Path,
                 timeout: int = 30, threads: int = 20,
                 delay_range: tuple[float, float] | None = None):
        self.subdomains = subdomains
        self.output_dir = output_dir
        self.timeout = timeout  # Increased to 30s for better reliability
        self.threads = threads
        # Optional jitter window between requests to play nicely with WAFs
        self.delay_range = delay_range
        self.results: list[ProbeResult] = []
        self.live_hosts: list[str] = []
        self.api_endpoints: list[str] = []
        self.redirected_hosts: set[str] = set()  # Track redirected domains

    async def run(self) -> tuple[list[ProbeResult], list[str]]:
        display.info(f"Probing [bold]{len(self.subdomains)}[/bold] hosts...")

        semaphore = asyncio.Semaphore(self.threads)
        connector = aiohttp.TCPConnector(ssl=False, limit=self.threads)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
        ) as session:
            tasks = [self._probe_host_extended(session, semaphore, sub) for sub in self.subdomains]
            await asyncio.gather(*tasks, return_exceptions=True)

        # Use httpx if available for better results
        if shutil.which("httpx"):
            await self._run_httpx()

        # Deduplicate live hosts
        seen_urls = set()
        unique_results = []
        for r in self.results:
            if r.url not in seen_urls:
                seen_urls.add(r.url)
                unique_results.append(r)
        self.results = unique_results

        self.live_hosts = [r.url for r in self.results if r.status in range(200, 500) or r.status in [403, 401]]

        # Add redirected hosts as live hosts
        self.live_hosts.extend(list(self.redirected_hosts))
        self.live_hosts = list(set(self.live_hosts))

        # Save live hosts (only if not empty)
        if self.live_hosts:
            live_file = self.output_dir / "live_hosts.txt"
            live_file.write_text("\n".join(self.live_hosts))

        # Discover APIs on live hosts
        await self._discover_apis(connector)

        # Save API endpoints (only if not empty)
        if self.api_endpoints:
            api_file = self.output_dir / "apis.txt"
            api_file.write_text("\n".join(sorted(set(self.api_endpoints))))

        # Save detailed probe results (only if not empty)
        if self.results:
            self._save_probe_results()

        display.success(f"Live hosts: [bold green]{len(self.live_hosts)}[/bold green]")
        display.success(f"API endpoints: [bold green]{len(self.api_endpoints)}[/bold green]")

        logger.info(f"Probe complete: {len(self.live_hosts)} live, {len(self.api_endpoints)} APIs")
        return self.results, self.api_endpoints

    async def _probe_host_extended(self, session, semaphore, subdomain: str):
        async with semaphore:
            # DNS delay to prevent flooding
            await asyncio.sleep(0.1)
            
            # Get fresh stealth headers for each request
            headers = get_stealth_headers()
            
            # Probe both HTTP and HTTPS for each port
            for port in EXTENDED_PORTS:
                for scheme in ["https", "http"]:
                    # Skip non-standard ports with wrong scheme
                    if port == 443 and scheme == "http":
                        continue
                    if port == 80 and scheme == "https":
                        continue
                    
                    # Construct URL with port
                    if port in [80, 443]:
                        url = f"{scheme}://{subdomain}"
                    else:
                        url = f"{scheme}://{subdomain}:{port}"
                    
                    # Retry mechanism (max 2 retries)
                    for attempt in range(3):
                        try:
                            if self.delay_range:
                                await asyncio.sleep(random.uniform(*self.delay_range))
                            
                            async with session.get(url, allow_redirects=True, max_redirects=5, headers=headers) as resp:
                                body = await resp.text(errors="ignore")
                                title = self._extract_title(body)
                                final_url = str(resp.url)
                                
                                result = ProbeResult(
                                    url=final_url,
                                    status=resp.status,
                                    title=title,
                                    server=resp.headers.get("Server", ""),
                                    content_type=resp.headers.get("Content-Type", ""),
                                    redirect=final_url if final_url != url else "",
                                    length=len(body),
                                )
                                result.has_login = self._detect_login(body, title)
                                result.has_admin = self._detect_admin(subdomain, body, title)
                                result.is_api = self._detect_api(url, body, resp.headers)
                                self.results.append(result)
                                
                                # Capture redirected domains as live hosts
                                if final_url != url:
                                    redirected_domain = urlparse(final_url).netloc
                                    if redirected_domain != subdomain:
                                        self.redirected_hosts.add(f"{urlparse(final_url).scheme}://{redirected_domain}")
                                
                                logger.debug(f"Probed: {url} [{resp.status}]")
                                
                                # If we got a successful response, no need to try other ports for this scheme
                                if resp.status in range(200, 500):
                                    return
                                
                        except asyncio.TimeoutError:
                            if attempt < 2:  # Retry on timeout
                                logger.debug(f"Timeout for {url}, retrying (attempt {attempt + 1})")
                                await asyncio.sleep(1)  # Wait before retry
                                continue
                            else:
                                logger.debug(f"Timeout for {url} after 3 attempts, skipping")
                                break
                        except Exception as e:
                            # HTTP 421 Fallback: If HTTP 421 status is detected, fallback to plain http://
                            if hasattr(e, 'status') and e.status == 421 and url.startswith("https://"):
                                http_url = url.replace("https://", "http://", 1)
                                logger.info(f"HTTP 421 detected, retrying {url} with HTTP")
                                try:
                                    async with session.get(http_url, allow_redirects=True, max_redirects=5, headers=headers) as resp:
                                        if resp.status in range(200, 500):
                                            body = await resp.text(errors="ignore")
                                            title = self._extract_title(body)
                                            final_url = str(resp.url)
                                            
                                            result = ProbeResult(
                                                url=final_url,
                                                status=resp.status,
                                                title=title,
                                                server=resp.headers.get("Server", ""),
                                                content_type=resp.headers.get("Content-Type", ""),
                                                redirect=final_url if final_url != http_url else "",
                                                length=len(body),
                                            )
                                            result.has_login = self._detect_login(body, title)
                                            result.has_admin = self._detect_admin(subdomain, body, title)
                                            result.is_api = self._detect_api(http_url, body, resp.headers)
                                            self.results.append(result)
                                            
                                            logger.debug(f"HTTP 421 fallback success: {http_url} [{resp.status}]")
                                            return
                                except Exception as retry_e:
                                    logger.debug(f"HTTP 421 retry failed for {http_url}: {retry_e}")
                            
                            if attempt < 2 and ("TimeoutError" in str(e) or "timeout" in str(e).lower()):
                                logger.debug(f"Timeout error for {url}, retrying (attempt {attempt + 1})")
                                await asyncio.sleep(1)
                                continue
                            else:
                                break

    async def _probe_host(self, session, semaphore, subdomain: str):
        """Legacy method for backward compatibility."""
        await self._probe_host_extended(session, semaphore, subdomain)

    async def _run_httpx(self):
        """Run httpx for additional probing if available."""
        hosts = [f"{sub}" for sub in self.subdomains]
        input_data = "\n".join(hosts)
        try:
            proc = await asyncio.create_subprocess_exec(
                "httpx", "-silent", "-status-code", "-title", "-server",
                "-content-length", "-follow-redirects",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(input_data.encode()), timeout=120
            )
            # Parse httpx output and merge into results
            # httpx outputs: URL [status] [title] [server] [length]
            for line in stdout.decode().splitlines():
                if line.strip():
                    logger.debug(f"httpx: {line}")
        except Exception as e:
            logger.warning(f"httpx failed: {e}")

    async def _discover_apis(self, connector):
        """Check common API paths on all live hosts."""
        semaphore = asyncio.Semaphore(self.threads)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
        ) as session:
            tasks = []
            for host_url in self.live_hosts[:50]:  # Top 50 live hosts
                for api_path in API_PATHS:
                    url = urljoin(host_url.rstrip("/") + "/", api_path.lstrip("/"))
                    tasks.append(self._check_api_path(session, semaphore, url))
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_api_path(self, session, semaphore, url: str):
        async with semaphore:
            try:
                if self.delay_range:
                    await asyncio.sleep(random.uniform(*self.delay_range))
                
                # Use fresh stealth headers for API checks
                headers = get_stealth_headers()
                
                async with session.get(url, allow_redirects=False, headers=headers) as resp:
                    if resp.status in [200, 201, 301, 302, 401, 403]:
                        self.api_endpoints.append(f"{url} [{resp.status}]")
            except Exception:
                pass

    def _extract_title(self, html: str) -> str:
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if match:
            return re.sub(r"\s+", " ", match.group(1)).strip()[:80]
        return ""

    def _detect_login(self, body: str, title: str) -> bool:
        body_lower = body.lower()
        title_lower = title.lower()
        keywords = ["login", "sign in", "signin", "log in", "password", "username", "email"]
        return any(k in body_lower or k in title_lower for k in keywords)

    def _detect_admin(self, host: str, body: str, title: str) -> bool:
        host_lower = host.lower()
        body_lower = body.lower()
        title_lower = title.lower()
        keywords = ["admin", "administrator", "dashboard", "control panel", "management"]
        return any(
            k in host_lower or k in body_lower or k in title_lower
            for k in keywords
        )

    def _detect_api(self, url: str, body: str, headers) -> bool:
        content_type = headers.get("Content-Type", "").lower()
        if "application/json" in content_type:
            return True
        if any(path in url for path in ["/api/", "/rest/", "/graphql"]):
            return True
        body_lower = body[:500].lower()
        return body_lower.startswith("{") or body_lower.startswith("[")

    def _save_probe_results(self):
        lines = []
        for r in sorted(self.results, key=lambda x: x.status):
            flags = []
            if r.has_login:
                flags.append("LOGIN")
            if r.has_admin:
                flags.append("ADMIN")
            if r.is_api:
                flags.append("API")
            flag_str = f" [{', '.join(flags)}]" if flags else ""
            lines.append(
                f"{r.status}  {r.url}  {r.length}b  "
                f"{r.server[:30] if r.server else 'unknown'}  "
                f"{r.title[:50] if r.title else ''}  {flag_str}"
            )
        out_file = self.output_dir / "probe_results.txt"
        out_file.write_text("\n".join(lines))