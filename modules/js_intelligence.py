"""
JavaScript Intelligence Engine — v1.3
Downloads and analyzes JS files to extract endpoints, parameters, and secrets.
Also extracts and analyzes inline <script> tag content from HTML pages.

v1.3 changes:
  - Inline script extraction: <script> tag *body* content from HTML pages is
    now analyzed directly (endpoints, params, secrets) without needing an
    external .js file reference. Covers index.php, login.html, etc.
  - New 'Bug Hunter' secret patterns: Firebase realtime DB URLs, S3 bucket
    URLs, Bearer tokens, and broad api_key / secret key patterns.
  - All existing v1.2 behaviour preserved (deep JS crawl, raw-string regex).
"""

import asyncio
import aiohttp
import re
import random
import jsbeautifier
from pathlib import Path
from urllib.parse import urljoin, urlparse
from config.settings import config
from core.display import Display
from core.logger import get_logger

# Guard bs4 import — module works even when beautifulsoup4 is not installed
try:
    from bs4 import BeautifulSoup
    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False

logger = get_logger("js_intelligence")
display = Display()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}

# ── All patterns use raw strings r"" to avoid SyntaxWarning ───────
ENDPOINT_PATTERNS = [
    # fetch('...'), axios.get('...')
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['"](\\/[^'"]+)['"]\s*""",
    # $.ajax({ url: '...' })
    r"""url\s*:\s*['"](\\/[^'"]{3,})['"]\s*""",
    # '/api/...' or "/api/..."
    r"""['"](\\/(?:api|rest|graphql|v\d|internal|admin)[^'"]{2,})['"]\s*""",
    # XMLHttpRequest .open("GET", "...")
    r"""\\.open\s*\(\s*['"]\w+['"]\s*,\s*['"](\\/[^'"]+)['"]\s*""",
    # template literals: `/api/${id}`
    r"""`(\\/(?:api|rest|v\d)[^`]+)`""",
    # router/route: path: '/...'
    r"""path\s*:\s*['"](\\/[^'"]+)['"]\s*""",
]

# Compile once at module load
_COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in ENDPOINT_PATTERNS]

PARAM_PATTERN = re.compile(r"""[?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})=""")

# ── Bug-Hunter Secret Patterns (appended to config.secret_patterns) ────
# These run against both JS files AND inline <script> content.
BUG_HUNTER_SECRET_PATTERNS: list[tuple[str, str]] = [
    # Firebase Realtime Database URLs
    (r"https?://[a-z0-9\-]+\.firebaseio\.com", "Firebase Realtime DB URL"),
    # AWS S3 Bucket URLs
    (r"https?://[a-z0-9\-\.]+\.s3\.amazonaws\.com", "S3 Bucket URL"),
    # Bearer / Authorization header values captured in JS
    (r"(?i)bearer\s+[A-Za-z0-9\-_\.=]{16,}", "Bearer Token"),
    # Generic api_key / apikey assignment
    (r"(?i)api[_\-]?key\s*[=:]\s*['\"][A-Za-z0-9\-_]{16,}['\"]", "API Key (generic)"),
    # Generic secret assignment
    (r"(?i)\bsecret\b\s*[=:]\s*['\"][A-Za-z0-9\-_!@#$%^&*]{8,}['\"]", "Secret (generic)"),
    # Google Maps / places API keys
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
    # Twilio Account SID / Auth Token style
    (r"(?i)(?:account[_-]?sid|auth[_-]?token)\s*[=:]\s*['\"][A-Za-z0-9]{32,}['\"]", "Twilio Credential"),
]

# Aggressive JS URL finder: catches src= and href= with any .js reference
_JS_URL_PATTERN = re.compile(
    r"""(?:src|href)=["']([^"']+\.js[^"']*)["']""",
    re.IGNORECASE,
)

# Inline <script> tag body extractor (no src= attribute → inline content)
_INLINE_SCRIPT_PATTERN = re.compile(
    r"""<script(?![^>]*\bsrc\b)[^>]*>([\s\S]*?)</script>""",
    re.IGNORECASE,
)


class JSAnalysisResult:
    def __init__(self, url: str):
        self.url = url
        self.endpoints: list[str] = []
        self.parameters: list[str] = []
        self.secrets: list[tuple] = []   # (pattern_name, match, line_number)


class JSIntelligence:
    def __init__(self, live_hosts: list[str], output_dir: Path,
                 timeout: int = 10, threads: int = 20,
                 fallback_urls: list[str] | None = None, **kwargs):
        self.live_hosts = live_hosts
        self.output_dir = output_dir
        self.timeout = timeout
        self.threads = threads
        # Accept delay_range from kwargs to prevent 'unexpected keyword argument' crashes
        self.delay_range = kwargs.get('delay_range', None)
        # Phase 3 URLs used for Deep JS Crawl when live_hosts give 0 JS files
        self.fallback_urls: list[str] = fallback_urls or []
        self.js_urls: set[str] = set()
        self.results: list[JSAnalysisResult] = []
        self.max_workers = min(max(5, min(7, threads)), max(len(self.live_hosts), 1))
        self.download_delay = 0.5

    async def run(self) -> list[JSAnalysisResult]:
        display.info("Starting JavaScript intelligence analysis...")

        # Step 1: Collect JS URLs from live hosts
        await self._collect_js_urls(self.live_hosts[:30])
        display.info(f"Found [bold]{len(self.js_urls)}[/bold] JavaScript files from live hosts")

        # ── Deep JS Crawl ─────────────────────────────────────────
        # Phase 1: If live hosts gave 0 JS files, scan ALL fallback URLs (up to 40)
        if not self.js_urls and self.fallback_urls:
            first_batch = self.fallback_urls[:40]
            display.warning(
                f"0 JS files from live hosts — Aggressive Deep JS Crawl: "
                f"scanning first [bold]{len(first_batch)}[/bold] URLs from discovered list..."
            )
            logger.info(f"Deep JS Crawl Pass 1: scanning {len(first_batch)} URLs")
            await self._collect_js_urls(first_batch)
            if self.js_urls:
                display.success(
                    f"Deep JS Crawl Pass 1 found [bold green]{len(self.js_urls)}[/bold green] "
                    "JavaScript files"
                )

        # Phase 2: Still 0? Random sample from remaining URLs for a second attempt
        if not self.js_urls and self.fallback_urls:
            remaining = self.fallback_urls[40:]
            if remaining:
                sample_size = random.randint(10, min(20, len(remaining)))
                url_sample = random.sample(remaining, sample_size)
                display.warning(
                    f"Still 0 JS files — Deep JS Crawl Pass 2: "
                    f"random sample of [bold]{sample_size}[/bold] remaining URLs..."
                )
                logger.info(f"Deep JS Crawl Pass 2: sampling {sample_size} URLs")
                await self._collect_js_urls(url_sample)
                if self.js_urls:
                    display.success(
                        f"Deep JS Crawl Pass 2 found [bold green]{len(self.js_urls)}[/bold green] "
                        "JavaScript files"
                    )
                else:
                    display.warning("Deep JS Crawl: no JS files found in sampled URLs either")
            else:
                display.warning("Deep JS Crawl: no additional URLs to sample")

        if not self.js_urls:
            display.warning("No JavaScript files found for analysis — skipping")
            return []

        # Step 2: Download and analyze each JS file with controlled concurrency
        connector = aiohttp.TCPConnector(ssl=False, limit=self.max_workers)

        async with aiohttp.ClientSession(
            connector=connector,
            headers=HEADERS,
            timeout=aiohttp.ClientTimeout(total=self.timeout * 2),
        ) as session:
            queue: asyncio.Queue[str] = asyncio.Queue()
            for url in self.js_urls:
                await queue.put(url)

            semaphore = asyncio.Semaphore(self.max_workers)
            workers = [
                asyncio.create_task(self._worker(session, queue, semaphore))
                for _ in range(self.max_workers)
            ]

            await queue.join()

            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

        self._save_results()

        total_endpoints = sum(len(r.endpoints) for r in self.results)
        total_secrets   = sum(len(r.secrets)   for r in self.results)

        display.success(f"JS files analyzed:  [bold green]{len(self.results)}[/bold green]")
        display.success(f"Endpoints found:    [bold green]{total_endpoints}[/bold green]")
        if total_secrets:
            display.warning(f"Possible secrets:   [bold yellow]{total_secrets}[/bold yellow]")

        logger.info(f"JS: {len(self.results)} files, {total_endpoints} endpoints, {total_secrets} secrets")
        return self.results

    # ──────────────────────────────────────────────────────────────
    # Collection helpers
    # ──────────────────────────────────────────────────────────────

    async def _collect_js_urls(self, targets: list[str]):
        """Scrape a list of URLs/hosts to find JS file references."""
        semaphore = asyncio.Semaphore(20)
        connector = aiohttp.TCPConnector(ssl=False, limit=20)

        async with aiohttp.ClientSession(
            connector=connector,
            headers=HEADERS,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
        ) as session:
            tasks = [self._find_js_in_page(session, semaphore, url) for url in targets]
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _find_js_in_page(self, session, semaphore, host_url: str):
        async with semaphore:
            try:
                async with session.get(host_url, allow_redirects=True) as resp:
                    # DEBUG: Print HTTP response codes
                    print(f"[DEBUG] HTTP {resp.status} for {host_url}")
                    logger.debug(f"HTTP {resp.status} for {host_url}")

                    # Accept any 2xx response (some hosts return 206, etc.)
                    if 200 <= resp.status < 300:
                        body = await resp.text(errors="ignore")

                        if _BS4_AVAILABLE:
                            soup = BeautifulSoup(body, "html.parser")

                            # ── Linked JS files ──────────────────────────
                            for script in soup.find_all("script", src=True):
                                src = script.get("src", "")
                                if src:
                                    full = urljoin(str(resp.url), src)
                                    if ".js" in full:
                                        self.js_urls.add(full)

                            # ── Inline <script> content ──────────────────
                            # Analyze script tag bodies directly (no external fetch needed)
                            for script_tag in soup.find_all("script", src=False):
                                inline_code = script_tag.get_text()
                                if inline_code and len(inline_code.strip()) > 20:
                                    self._analyze_inline_script(inline_code, host_url)
                        else:
                            # Aggressive regex fallback — no library required
                            self._extract_js_with_regex(body, str(resp.url))
                            # Also extract inline <script> content via regex
                            self._extract_inline_scripts_with_regex(body, host_url)

                    elif resp.status == 403:
                        logger.warning(f"403 Forbidden for {host_url} - may need different User-Agent")
                        print(f"[DEBUG] 403 Forbidden for {host_url} - User-Agent blocked")

            except Exception as e:
                logger.debug(f"Error fetching {host_url}: {e}")
                print(f"[DEBUG] Error fetching {host_url}: {e}")
                
                # HTTP 421 Fallback: If HTTP 421 status is detected, fallback to plain http://
                if hasattr(e, 'status') and e.status == 421:
                    if host_url.startswith("https://"):
                        http_url = host_url.replace("https://", "http://", 1)
                        logger.info(f"HTTP 421 detected, retrying {host_url} with HTTP")
                        print(f"[DEBUG] HTTP 421 fallback: {host_url} -> {http_url}")
                        try:
                            async with session.get(http_url, allow_redirects=True) as resp:
                                if 200 <= resp.status < 300:
                                    body = await resp.text(errors="ignore")
                                    if _BS4_AVAILABLE:
                                        soup = BeautifulSoup(body, "html.parser")
                                        for script in soup.find_all("script", src=True):
                                            src = script.get("src", "")
                                            if src:
                                                full = urljoin(str(resp.url), src)
                                                if ".js" in full:
                                                    self.js_urls.add(full)
                                        for script_tag in soup.find_all("script", src=False):
                                            inline_code = script_tag.get_text()
                                            if inline_code and len(inline_code.strip()) > 20:
                                                self._analyze_inline_script(inline_code, http_url)
                                    else:
                                        self._extract_js_with_regex(body, str(resp.url))
                                        self._extract_inline_scripts_with_regex(body, http_url)
                        except Exception as retry_e:
                            logger.debug(f"HTTP 421 retry also failed for {http_url}: {retry_e}")
                            pass
                
                # Deep JS Crawl Resilience: If HTTPS fails due to SSL, retry with HTTP
                elif host_url.startswith("https://") and ("SSL" in str(e) or "certificate" in str(e).lower() or "ssl" in str(e).lower()):
                    http_url = host_url.replace("https://", "http://", 1)
                    logger.info(f"Retrying {host_url} with HTTP due to SSL error")
                    print(f"[DEBUG] Retrying {host_url} with HTTP due to SSL error")
                    try:
                        async with session.get(http_url, allow_redirects=True) as resp:
                            if 200 <= resp.status < 300:
                                body = await resp.text(errors="ignore")
                                if _BS4_AVAILABLE:
                                    soup = BeautifulSoup(body, "html.parser")
                                    for script in soup.find_all("script", src=True):
                                        src = script.get("src", "")
                                        if src:
                                            full = urljoin(str(resp.url), src)
                                            if ".js" in full:
                                                self.js_urls.add(full)
                                    for script_tag in soup.find_all("script", src=False):
                                        inline_code = script_tag.get_text()
                                        if inline_code and len(inline_code.strip()) > 20:
                                            self._analyze_inline_script(inline_code, http_url)
                                else:
                                    self._extract_js_with_regex(body, str(resp.url))
                                    self._extract_inline_scripts_with_regex(body, http_url)
                    except Exception as retry_e:
                        logger.debug(f"HTTP retry also failed for {http_url}: {retry_e}")
                        pass
                pass

    async def _worker(self, session, queue: asyncio.Queue, semaphore: asyncio.Semaphore):
        while True:
            try:
                js_url = await queue.get()
            except asyncio.CancelledError:
                break

            try:
                async with semaphore:
                    await self._analyze_js(session, js_url)
                    await asyncio.sleep(self.download_delay)
            finally:
                queue.task_done()

    async def _analyze_js(self, session, js_url: str):
        try:
            async with session.get(js_url, allow_redirects=True) as resp:
                if resp.status != 200:
                    logger.debug(f"JS fetch failed for {js_url}: HTTP {resp.status}")
                    
                    # Try 421 fallback for endpoint extraction even if JS fetch fails
                    if resp.status == 421 or resp.status >= 400:
                        hidden_paths = await self._extract_paths_from_js_with_421_fallback(js_url, session)
                        if hidden_paths:
                            result = JSAnalysisResult(js_url)
                            result.endpoints = hidden_paths
                            self.results.append(result)
                            logger.info(f"421 fallback: extracted {len(hidden_paths)} paths from {js_url}")
                    return

                try:
                    content = await resp.text(errors="ignore")
                except Exception as e:
                    logger.debug(f"Failed reading JS body for {js_url}: {e}")
                    return

                if not content.strip():
                    logger.debug(f"Empty JS content for {js_url}")
                    return

                # Beautify minified JS for better analysis
                try:
                    content = jsbeautifier.beautify(content)
                except Exception:
                    pass  # Use raw content if beautifier fails

                result = JSAnalysisResult(js_url)
                result.endpoints  = self._extract_endpoints(content)
                result.parameters = self._extract_parameters(content)
                result.secrets    = self._detect_secrets(content)
                # Also run Bug Hunter patterns on every JS file
                result.secrets   += self._detect_bug_hunter_secrets(content)

                # If no endpoints found normally, try 421 fallback
                if not result.endpoints:
                    hidden_paths = await self._extract_paths_from_js_with_421_fallback(js_url, session)
                    if hidden_paths:
                        result.endpoints.extend(hidden_paths)
                        logger.info(f"Enhanced {js_url} with {len(hidden_paths)} hidden paths from fallback")

                if result.endpoints or result.secrets:
                    self.results.append(result)
                    logger.debug(
                        f"JS done: {js_url} — "
                        f"{len(result.endpoints)} endpoints, {len(result.secrets)} secrets"
                    )

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.debug(f"JS request error for {js_url}: {e}")
            
            # Try 421 fallback even on connection errors
            try:
                hidden_paths = await self._extract_paths_from_js_with_421_fallback(js_url, session)
                if hidden_paths:
                    result = JSAnalysisResult(js_url)
                    result.endpoints = hidden_paths
                    self.results.append(result)
                    logger.info(f"Connection error fallback: extracted {len(hidden_paths)} paths from {js_url}")
            except Exception:
                pass
                
        except Exception as e:
            logger.debug(f"JS analysis failed for {js_url}: {e}")

    # ──────────────────────────────────────────────────────────────
    # Regex helpers
    # ──────────────────────────────────────────────────────────────

    def _extract_js_with_regex(self, html: str, base_url: str):
        """
        Aggressive JS-URL extractor using pre-compiled raw-string pattern.
        Catches src= AND href= attributes containing .js references.
        Works without any external library.
        """
        for src in _JS_URL_PATTERN.findall(html):
            try:
                full = urljoin(base_url, src)
                if ".js" in full:
                    self.js_urls.add(full)
            except Exception:
                continue

    def _extract_inline_scripts_with_regex(self, html: str, page_url: str):
        """
        Regex-based fallback to extract and analyze inline <script> tag content.
        Used when BeautifulSoup is not available.
        """
        for match in _INLINE_SCRIPT_PATTERN.finditer(html):
            inline_code = match.group(1)
            if inline_code and len(inline_code.strip()) > 20:
                self._analyze_inline_script(inline_code, page_url)

    def _analyze_inline_script(self, code: str, source_url: str):
        """
        Analyze a block of JavaScript code extracted inline from an HTML page.
        Adds endpoints, parameters, and secrets directly to self.results.
        Runs Bug Hunter secret patterns in addition to config patterns.
        """
        try:
            beautified = jsbeautifier.beautify(code)
        except Exception:
            beautified = code

        result = JSAnalysisResult(f"inline://{source_url}")
        result.endpoints  = self._extract_endpoints(beautified)
        result.parameters = self._extract_parameters(beautified)
        result.secrets    = self._detect_secrets(beautified)
        result.secrets   += self._detect_bug_hunter_secrets(beautified)

        if result.endpoints or result.secrets:
            self.results.append(result)
            logger.debug(
                f"Inline script @ {source_url} — "
                f"{len(result.endpoints)} endpoints, {len(result.secrets)} secrets"
            )

    def _detect_bug_hunter_secrets(self, content: str) -> list[tuple]:
        """Run Bug Hunter secret patterns against JS / inline script content."""
        found = []
        for pattern_str, name in BUG_HUNTER_SECRET_PATTERNS:
            try:
                pattern = re.compile(pattern_str, re.MULTILINE | re.DOTALL | re.IGNORECASE)
                for match in pattern.finditer(content):
                    start_index = match.start()
                    line_number = content.count("\n", 0, start_index) + 1
                    val = match.group(0)
                    masked = val[:8] + "***" + val[-4:] if len(val) > 15 else "***"
                    found.append((name, masked, line_number))
            except Exception:
                pass
        return found

    def _extract_endpoints(self, content: str) -> list[str]:
        endpoints: set[str] = set()
        
        # Enhanced regex to find hidden paths even with 421 errors
        # Pattern: (['"])(/[^'"]+)\1 - captures paths in quotes
        hidden_paths_pattern = re.compile(r"(['\"])(/[^'\"]+)\1")
        
        # Extract hidden paths from JS content
        try:
            for match in hidden_paths_pattern.finditer(content):
                path = match.group(2).strip()
                # Filter out common false positives
                if (len(path) > 2 and 
                    not path.endswith((".js", ".css", ".png", ".jpg", ".gif", ".svg", ".ico")) and
                    not path.startswith(("//", "/*")) and
                    not any(x in path for x in ["http://", "https://", "data:"])):
                    endpoints.add(path)
        except Exception:
            pass
        
        # Apply existing compiled patterns
        for pattern in _COMPILED_PATTERNS:
            try:
                for m in pattern.findall(content):
                    m = m.strip()
                    if len(m) > 2 and not m.endswith((".js", ".css", ".png", ".jpg")):
                        endpoints.add(m)
            except Exception:
                pass
        
        return sorted(endpoints)
    
    async def _extract_paths_from_js_with_421_fallback(self, js_url: str, session):
        """Special method to extract paths from JS files even when main page returns 421."""
        try:
            # Try both HTTPS and HTTP for the JS file
            for scheme in ["https", "http"]:
                test_url = js_url.replace("https://", f"{scheme}://", 1).replace("http://", f"{scheme}://", 1)
                
                async with session.get(test_url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        content = await resp.text(errors="ignore")
                        if content.strip():
                            # Extract hidden paths using the enhanced regex
                            hidden_paths = set()
                            hidden_paths_pattern = re.compile(r"(['\"])(/[^'\"]+)\1")
                            
                            for match in hidden_paths_pattern.finditer(content):
                                path = match.group(2).strip()
                                if (len(path) > 2 and 
                                    not path.endswith((".js", ".css", ".png", ".jpg", ".gif", ".svg", ".ico")) and
                                    not path.startswith(("//", "/*")) and
                                    not any(x in path for x in ["http://", "https://", "data:"])):
                                    hidden_paths.add(path)
                            
                            if hidden_paths:
                                logger.info(f"Extracted {len(hidden_paths)} hidden paths from {js_url} via {scheme}")
                                return list(hidden_paths)
                    else:
                        logger.debug(f"JS file {test_url} returned {resp.status}")
        except Exception as e:
            logger.debug(f"Failed to extract paths from {js_url}: {e}")
        
        return []

    def _extract_parameters(self, content: str) -> list[str]:
        matches = PARAM_PATTERN.findall(content)
        return sorted(set(m.lower() for m in matches))

    def _detect_secrets(self, content: str) -> list[tuple]:
        """Detect secrets using multi-line aware regex over beautified JS."""
        found = []
        for pattern_str, name in config.secret_patterns:
            try:
                pattern = re.compile(pattern_str, re.MULTILINE | re.DOTALL)
                for match in pattern.finditer(content):
                    start_index = match.start()
                    line_number = content.count("\n", 0, start_index) + 1
                    val = match.group(0)
                    masked = val[:8] + "***" + val[-4:] if len(val) > 15 else "***"
                    found.append((name, masked, line_number))
            except Exception:
                pass
        return found

    def _save_results(self):
        lines = []
        secrets_lines = []

        for r in self.results:
            lines.append(f"\n{'='*60}")
            lines.append(f"File: {r.url}")
            lines.append(f"{'='*60}")

            if r.endpoints:
                lines.append(f"\nEndpoints ({len(r.endpoints)}):")
                for ep in r.endpoints:
                    lines.append(f"  {ep}")

            if r.parameters:
                lines.append(f"\nParameters ({len(r.parameters)}):")
                for p in r.parameters:
                    lines.append(f"  ?{p}=")

            if r.secrets:
                lines.append(f"\n[!] Possible Secrets ({len(r.secrets)}):")
                for name, val, lineno in r.secrets:
                    lines.append(f"  {name}  (line {lineno}):  {val}")
                    secrets_lines.append(f"{r.url}  [{name}]  line {lineno}:  {val}")

        # Save results (only if not empty)
        if lines:
            out_file = self.output_dir / "js_analysis.txt"
            out_file.write_text("\n".join(lines))

        if secrets_lines:
            secrets_file = self.output_dir / "secrets.txt"
            secrets_file.write_text("\n".join(secrets_lines))
            display.warning("Secrets saved to [bold]output/secrets.txt[/bold]")