"""
Asset Fingerprinting Module.
Identifies technologies, frameworks, and servers used by targets.
Includes Favicon Fingerprinting with MurmurHash3.
"""

import asyncio
import aiohttp
import re
from pathlib import Path
from urllib.parse import urljoin
from dataclasses import dataclass, field
from core.display import Display
from core.logger import get_logger

# Optional parsing helpers (fingerprinting still works without bs4).
try:
    from bs4 import BeautifulSoup  # type: ignore
    BS4_AVAILABLE = True
except Exception:
    BeautifulSoup = None  # type: ignore
    BS4_AVAILABLE = False

try:
    import mmh3  # MurmurHash3
    MMH3_AVAILABLE = True
except Exception:
    mmh3 = None  # type: ignore
    MMH3_AVAILABLE = False

logger = get_logger("fingerprinting")
display = Display()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}


@dataclass
class FingerprintResult:
    host: str
    server: str = ""
    framework: str = ""
    language: str = ""
    cms: str = ""
    cdn: str = ""
    waf: str = ""
    database: str = ""
    js_frameworks: list = field(default_factory=list)
    extra: list = field(default_factory=list)
    favicon: str = ""


# Technology signatures - Deep Fingerprinting Database (50+ signatures)
SIGNATURES = {
    # ── Web Servers ─────────────────────────────────────────────────────
    "server": {
        "nginx": "Nginx",
        "apache": "Apache",
        "microsoft-iis": "IIS",
        "cloudflare": "Cloudflare",
        "caddy": "Caddy",
        "litespeed": "LiteSpeed",
        "gunicorn": "Gunicorn",
        "openresty": "OpenResty",
        "envoy": "Envoy",
        "lighttpd": "Lighttpd",
        "tomcat": "Apache Tomcat",
        "jetty": "Jetty",
        "weblogic": "Oracle WebLogic",
        "websphere": "IBM WebSphere",
        "kestrel": "Kestrel",
        "cowboy": "Cowboy",
        "haproxy": "HAProxy",
        "traefik": "Traefik",
    },
    
    # ── X-Powered-By (Language/Framework Hints) ───────────────────────────
    "x-powered-by": {
        "php": "PHP",
        "asp.net": "ASP.NET",
        "express": "Node.js (Express)",
        "mono": "Mono/.NET",
        "rails": "Ruby on Rails",
        "java": "Java",
        "servlet": "Java Servlet",
        "jsp": "JSP",
        "python": "Python",
        "wsgi": "Python WSGI",
        "perl": "Perl",
    },
    
    # ── Set-Cookie (Session & Framework Detection) ─────────────────────────
    "set_cookie": {
        "laravel_session": "Laravel",
        "xsrf-token": "Laravel/XSRF",
        "csrf_token": "CSRF Framework",
        "csrftoken": "Django",
        "sessionid": "Django/Generic",
        "phpsessid": "PHP",
        "wp-settings": "WordPress",
        "wordpress_logged_in": "WordPress",
        "wp_": "WordPress",
        "drupal": "Drupal",
        "joomla": "Joomla",
        "ci_session": "CodeIgniter",
        "express.sid": "Express.js",
        "connect.sid": "Connect",
        "jsessionid": "Java EE",
        "asp.net_sessionid": "ASP.NET",
        ".aspxauth": "ASP.NET Auth",
        "rack.session": "Ruby Rack",
        "__cfduid": "Cloudflare",
        "__cflb": "Cloudflare LB",
        "__cfruid": "Cloudflare Ray",
    },
    
    # ── CMS Detection (Body + Headers) ────────────────────────────────────
    "cms": {
        # WordPress
        "wp-content": "WordPress",
        "wp-includes": "WordPress",
        "wp-json": "WordPress REST API",
        "wordpress": "WordPress",
        "wp-": "WordPress",
        # Joomla
        "joomla": "Joomla",
        "com_content": "Joomla",
        "com_users": "Joomla",
        # Drupal
        "drupal": "Drupal",
        "sites/default": "Drupal",
        "node/": "Drupal",
        # Ghost
        "ghost": "Ghost",
        "ghost.io": "Ghost",
        # Other CMS
        "magento": "Magento",
        "shopify": "Shopify",
        "bigcommerce": "BigCommerce",
        "prestashop": "PrestaShop",
        "opencart": "OpenCart",
        "woocommerce": "WooCommerce",
        "squarespace": "Squarespace",
        "wix": "Wix",
        "weebly": "Weebly",
        "typo3": "TYPO3",
        "concrete5": "Concrete5",
        "modx": "MODX",
        "cmsmade": "CMS Made Simple",
        "expressionengine": "ExpressionEngine",
        "processwire": "ProcessWire",
        "silverstripe": "SilverStripe",
    },
    
    # ── JavaScript Frameworks ─────────────────────────────────────────────
    "body_framework": {
        # React ecosystem
        r"react": "React",
        r"next\.js": "Next.js",
        r"nextjs": "Next.js",
        r"create-react-app": "Create React App",
        r"react\.lazy": "React",
        # Vue ecosystem
        r"vue": "Vue.js",
        r"nuxt": "Nuxt.js",
        r"nuxtjs": "Nuxt.js",
        r"vue-router": "Vue.js",
        # Angular
        r"angular": "Angular",
        r"ng-": "Angular",
        r"ngapp": "Angular",
        # Svelte
        r"svelte": "Svelte",
        r"sveltekit": "SvelteKit",
        # Backend frameworks
        r"laravel": "Laravel",
        r"symfony": "Symfony",
        r"codeigniter": "CodeIgniter",
        r"cakephp": "CakePHP",
        r"yii": "Yii",
        r"zend": "Zend",
        r"django": "Django",
        r"flask": "Flask",
        r"fastapi": "FastAPI",
        r"tornado": "Tornado",
        r"bottle": "Bottle",
        r"rails": "Ruby on Rails",
        r"sinatra": "Sinatra",
        r"spring": "Spring",
        r"struts": "Struts",
        r"hibernate": "Hibernate",
        # Other JS frameworks
        r"ember": "Ember.js",
        r"backbone": "Backbone.js",
        r"knockout": "Knockout.js",
        r"meteor": "Meteor",
        r"jquery": "jQuery",
        r"bootstrap": "Bootstrap",
        r"tailwind": "Tailwind CSS",
        r"bulma": "Bulma",
        r"foundation": "Foundation",
        r"material-ui": "Material-UI",
        r"antd": "Ant Design",
        r"axios": "Axios",
        r"lodash": "Lodash",
        r"moment": "Moment.js",
        r"webpack": "Webpack",
        r"rollup": "Rollup",
        r"parcel": "Parcel",
        r"vite": "Vite",
    },
    
    # ── Cloud & CDN ──────────────────────────────────────────────────────
    "cdn": {
        "cloudflare": "Cloudflare",
        "cf-ray": "Cloudflare",
        "cf-cache-status": "Cloudflare",
        "x-amz": "AWS CloudFront",
        "x-amz-cf": "AWS CloudFront",
        "x-cache": "CDN Cache",
        "fastly": "Fastly",
        "x-fastly": "Fastly",
        "akamai": "Akamai",
        "x-akamai": "Akamai",
        "x-azure": "Azure CDN",
        "x-ms": "Azure",
        "x-goog": "Google Cloud CDN",
        "gws": "Google Web Server",
        "keycdn": "KeyCDN",
        "maxcdn": "MaxCDN",
        "stackpath": "StackPath",
        "bunnycdn": "BunnyCDN",
        "incap": "Incapsula",
        "x-iinfo": "Incapsula",
        "edgecast": "EdgeCast",
        "limelight": "Limelight",
    },
    
    # ── WAF & Security ───────────────────────────────────────────────────
    "waf": {
        "x-sucuri-id": "Sucuri WAF",
        "x-sucuri-cache": "Sucuri",
        "x-protected-by": "WAF Protected",
        "x-waf": "WAF",
        "__cfduid": "Cloudflare WAF",
        "__cflb": "Cloudflare",
        "x-fw-hash": "Firewall",
        "mod_security": "ModSecurity",
        "modsecurity": "ModSecurity",
        "x-datadome": "DataDome",
        "x-imperva": "Imperva WAF",
        "x-cdn": "Imperva",
        "x-wzws-requested": "WangZhanWangShou (360)",
        "x-aws-waf": "AWS WAF",
        "x-amz-cf-pop": "AWS CloudFront",
        "x-akamai-request-id": "Akamai WAF",
        "x-distil-cs": "Distil Networks",
        "x-shape-protection": "Shape Security",
        "x-forter": "Forter",
        "x-sigsci": "Signal Sciences",
        "x-wallarm": "Wallarm",
        "x-fortinet": "Fortinet",
        "x-paloalto": "Palo Alto",
        "x-f5": "F5 BIG-IP",
    },
    
    # ── Database Hints ────────────────────────────────────────────────────
    "database": {
        "mysql": "MySQL",
        "postgresql": "PostgreSQL",
        "postgres": "PostgreSQL",
        "mongodb": "MongoDB",
        "mariadb": "MariaDB",
        "sqlite": "SQLite",
        "redis": "Redis",
        "cassandra": "Cassandra",
        "elasticsearch": "Elasticsearch",
        "solr": "Apache Solr",
        "couchdb": "CouchDB",
        "neo4j": "Neo4j",
        "oracle": "Oracle",
        "mssql": "Microsoft SQL Server",
    },
    
    # ── API Technologies ─────────────────────────────────────────────────
    "api": {
        "swagger": "Swagger/OpenAPI",
        "openapi": "OpenAPI",
        "graphql": "GraphQL",
        "rest": "REST API",
        "json-api": "JSON API",
        "grpc": "gRPC",
        "odata": "OData",
        "postgrest": "PostgREST",
    },
}


# ── TECH_PATTERNS: Native Fingerprinting Engine ─────────────────────────────
# Primary engine: headers + HTML meta + script tags.
TECH_PATTERNS = {
    "headers": {
        "server": SIGNATURES.get("server", {}),
        "x-powered-by": SIGNATURES.get("x-powered-by", {}),
        "set-cookie": SIGNATURES.get("set_cookie", {}),
        "cdn": SIGNATURES.get("cdn", {}),
        "waf": SIGNATURES.get("waf", {}),
        "database": SIGNATURES.get("database", {}),
        # fallback CMS hints (headers + body)
        "cms": SIGNATURES.get("cms", {}),
    },
    "meta": {
        # Seed mapping for common generator meta tags.
        "generator": {
            "wordpress": "WordPress",
            "drupal": "Drupal",
            "joomla": "Joomla",
            "shopify": "Shopify",
            "magento": "Magento",
        }
    },
    "scripts": {
        # Framework detection from <script> tags (src + inline content).
        "framework_regex": SIGNATURES.get("body_framework", {}),
    },
    # Body regex vectors (bonus patterns)
    "html_body": {
        r"wp-content": "WordPress",
        r"_next/static": "Next.js",
        r"django-cms": "Django",
        r"drupal": "Drupal",
        r"googletagmanager|(?:\bUA-\d{4,}-\d+\b)|(?:\bG-[A-Z0-9]+\b)": "Google Analytics",
        r"data-reactroot|react-dom": "React",
    },
}


# ── Favicon Fingerprinting: Internal MurmurHash3 DB ────────────────────────
# User-seeded mapping (MurmurHash3 32-bit, signed).
# Ref: https://wiki.shodan.io/Favicon_fingerprinting
FAVICON_HASHES = {
    0: "Spring Boot",
    815863126: "Jenkins",
    -602140411: "Jira",
    1158132545: "WordPress",
    -1343151326: "Apache",
    116323821: "Cloudflare",
}

class AssetFingerprinting:
    def __init__(self, live_hosts: list[str], output_dir: Path,
                 timeout: int = 30, threads: int = 20, delay_range=None):
        self.live_hosts = live_hosts
        self.output_dir = output_dir
        self.timeout = timeout  # Increased to 30s for better reliability
        self.threads = threads
        self.delay_range = delay_range
        self.results: dict[str, FingerprintResult] = {}

    async def run(self) -> dict[str, FingerprintResult]:
        display.info(f"Fingerprinting [bold]{len(self.live_hosts)}[/bold] hosts...")

        semaphore = asyncio.Semaphore(self.threads)
        connector = aiohttp.TCPConnector(ssl=False, limit=self.threads)

        async with aiohttp.ClientSession(
            connector=connector,
            headers=HEADERS,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
        ) as session:
            tasks = [self._fingerprint(session, semaphore, host) for host in self.live_hosts]
            await asyncio.gather(*tasks, return_exceptions=True)

        self._save_results()

        display.success(f"Fingerprinting complete: [bold green]{len(self.results)}[/bold green] hosts profiled")
        logger.info(f"Fingerprinting: {len(self.results)} hosts")
        return self.results

    async def _fingerprint(self, session, semaphore, host_url: str):
        async with semaphore:
            # DNS delay to prevent flooding
            await asyncio.sleep(0.1)
            
            # Retry mechanism (max 2 retries)
            for attempt in range(3):
                try:
                    async with session.get(host_url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                        headers = dict(resp.headers)
                        try:
                            body_raw = await resp.text(errors="ignore")
                        except Exception:
                            body_raw = ""
                        body = body_raw[:5000].lower()

                        result = FingerprintResult(host=host_url)

                        headers_blob = " ".join(
                            f"{k.lower()}:{v.lower()}" for k, v in headers.items()
                        )

                        # Extract HTML meta/title and script tags.
                        # If bs4 is unavailable, we fall back to regex re.findall.
                        meta_blob = ""
                        scripts_blob = ""
                        bs4_ok = False

                        if BS4_AVAILABLE and BeautifulSoup is not None:
                            try:
                                # Prefer lxml parser when available.
                                try:
                                    soup = BeautifulSoup(body_raw[:5000], "lxml")
                                except Exception:
                                    soup = BeautifulSoup(body_raw[:5000], "html.parser")

                                title_val = ""
                                if getattr(soup, "title", None):
                                    title_val = soup.title.get_text(strip=True) or ""

                                meta_chunks: list[str] = []
                                for m in soup.find_all("meta"):
                                    name = (m.get("name") or m.get("property") or m.get("http-equiv") or "").strip().lower()
                                    content = (m.get("content") or "").strip().lower()
                                    if content:
                                        meta_chunks.append(f"{name}:{content}" if name else content)

                                meta_blob = " ".join(meta_chunks + ([title_val] if title_val else []))

                                script_chunks: list[str] = []
                                for s in soup.find_all("script"):
                                    src = (s.get("src") or "").strip()
                                    if src:
                                        script_chunks.append(src.lower())
                                    inline_txt = (s.get_text(" ", strip=True) or "").lower()
                                    if inline_txt:
                                        script_chunks.append(inline_txt[:2000])
                                scripts_blob = " ".join(script_chunks)
                                bs4_ok = True
                            except Exception:
                                bs4_ok = False

                        # Regex fallback (explicitly uses re.findall) if bs4 fails/unavailable.
                        if not bs4_ok:
                            titles = re.findall(
                                r"<title[^>]*>(.*?)</title>",
                                body_raw[:5000],
                                flags=re.IGNORECASE | re.DOTALL,
                            )

                            meta_snippets = re.findall(
                                r"<meta\b[^>]*>",
                                body_raw[:5000],
                                flags=re.IGNORECASE,
                            )

                            meta_chunks: list[str] = []
                            for snippet in meta_snippets:
                                name_m = re.search(
                                    r"(?:name|property|http-equiv)\s*=\s*['\"]([^'\"]+)['\"]",
                                    snippet,
                                    flags=re.IGNORECASE,
                                )
                                content_m = re.search(
                                    r"content\s*=\s*['\"]([^'\"]*)['\"]",
                                    snippet,
                                    flags=re.IGNORECASE,
                                )
                                if content_m:
                                    content = (content_m.group(1) or "").lower()
                                    name = (name_m.group(1) if name_m else "").strip().lower()
                                    meta_chunks.append(f"{name}:{content}" if name else content)

                            meta_blob = " ".join(meta_chunks + [t.lower() for t in titles if t])

                            # Script extraction for native TECH_PATTERNS scripts engine
                            srcs = re.findall(
                                r"<script[^>]+\bsrc\s*=\s*['\"]([^'\"]+)['\"][^>]*>",
                                body_raw[:5000],
                                flags=re.IGNORECASE,
                            )
                            inline_scripts = re.findall(
                                r"<script(?![^>]+\bsrc\s*=)[^>]*>(.*?)</script>",
                                body_raw[:5000],
                                flags=re.IGNORECASE | re.DOTALL,
                            )
                            script_chunks = [s.lower() for s in srcs if s]
                            for chunk in inline_scripts:
                                if chunk:
                                    script_chunks.append(chunk.lower()[:2000])
                            scripts_blob = " ".join(script_chunks)

                        # ── Native TECH_PATTERNS: Headers ─────────────────────────
                        # Server
                        server_h = headers.get("Server", "").lower()
                        for sig, name in TECH_PATTERNS["headers"]["server"].items():
                            if sig in server_h:
                                result.server = name
                                break

                        # X-Powered-By (language/framework hints)
                        xpb = headers.get("X-Powered-By", "").lower()
                        for sig, name in TECH_PATTERNS["headers"]["x-powered-by"].items():
                            if sig in xpb:
                                result.language = name
                                break

                        # Cookie-based detection (Set-Cookie)
                        set_cookie = headers.get("Set-Cookie", "").lower()
                        for sig, name in TECH_PATTERNS["headers"]["set_cookie"].items():
                            if sig in set_cookie:
                                lname = name.lower()
                                if "laravel" in lname:
                                    result.framework = result.framework or "Laravel"
                                elif "django" in lname:
                                    result.framework = result.framework or "Django"
                                    result.language = result.language or "Python"
                                elif "express" in lname:
                                    result.framework = result.framework or "Express.js"
                                    result.language = result.language or "JavaScript"
                                elif "php" in lname:
                                    result.language = result.language or "PHP"
                                elif "java" in lname:
                                    result.language = result.language or "Java"
                                elif "asp.net" in lname:
                                    result.language = result.language or "ASP.NET"
                                elif "rack" in lname:
                                    result.language = result.language or "Ruby"
                                elif "wordpress" in lname:
                                    result.cms = result.cms or "WordPress"
                                break

                        # CDN detection
                        for sig, name in TECH_PATTERNS["headers"]["cdn"].items():
                            if sig in headers_blob:
                                result.cdn = name
                                break

                        # WAF detection
                        for sig, name in TECH_PATTERNS["headers"]["waf"].items():
                            if sig in headers_blob:
                                result.waf = name
                                break

                        # Database hints from error messages or headers
                        for sig, name in TECH_PATTERNS["headers"]["database"].items():
                            if sig in body or sig in headers_blob:
                                result.database = name
                                break

                        # ── Native TECH_PATTERNS: HTML Meta ─────────────────────
                        meta_lower = (meta_blob or "").lower()
                        for keyword, tech_name in TECH_PATTERNS["meta"]["generator"].items():
                            if keyword in meta_lower:
                                result.cms = result.cms or tech_name
                                break

                        # ── Native TECH_PATTERNS: Script Tags ─────────────────
                        # Framework detection uses script src + inline script content.
                        for pattern, name in TECH_PATTERNS["scripts"]["framework_regex"].items():
                            if re.search(pattern, scripts_blob, re.IGNORECASE):
                                if not result.framework:
                                    result.framework = name
                                elif name not in result.js_frameworks:
                                    result.js_frameworks.append(name)

                        # ── Native TECH_PATTERNS: HTML Body Regex ─────────────
                        for pattern, tech_name in TECH_PATTERNS["html_body"].items():
                            if re.search(pattern, body, re.IGNORECASE):
                                if tech_name in {"WordPress", "Drupal"}:
                                    result.cms = result.cms or tech_name
                                elif tech_name == "Next.js":
                                    result.framework = result.framework or tech_name
                                elif tech_name == "React":
                                    result.framework = result.framework or tech_name
                                elif tech_name == "Google Analytics":
                                    result.extra.append(tech_name)

                        # CMS fallback from body + headers
                        if not result.cms:
                            for sig, name in TECH_PATTERNS["headers"]["cms"].items():
                                if sig in body or sig in headers_blob:
                                    result.cms = name
                                    break

                        # Favicon Fingerprinting with MurmurHash3 (mmh3)
                        try:
                            favicon_url = urljoin(host_url, "/favicon.ico")
                            async with session.get(
                                favicon_url,
                                allow_redirects=True,
                                timeout=aiohttp.ClientTimeout(total=30),  # 30-second timeout for safety
                            ) as fav_resp:
                                if fav_resp.status == 200:
                                    favicon_data = await fav_resp.read()
                                    if favicon_data and MMH3_AVAILABLE:
                                        # Shodan-compatible MurmurHash3 32-bit, signed.
                                        fav_hash = mmh3.hash(favicon_data, signed=True)
                                        result.favicon = f"Hash: {fav_hash}"
                                        if fav_hash in FAVICON_HASHES:
                                            detected_tech = FAVICON_HASHES[fav_hash]
                                            display.info(
                                                f"Favicon fingerprint: {detected_tech} "
                                                f"(hash: {fav_hash})"
                                            )
                                            logger.info(
                                                f"Favicon match: {detected_tech} on {host_url}"
                                            )
                                            if detected_tech not in result.extra:
                                                result.extra.append(f"Favicon: {detected_tech}")
                        except Exception:
                            pass  # Favicon fingerprinting is best-effort

                        # Store the result
                        self.results[host_url] = result
                        return  # Success, exit retry loop

                except asyncio.TimeoutError:
                    if attempt < 2:  # Retry on timeout
                        logger.debug(f"Timeout for {host_url}, retrying (attempt {attempt + 1})")
                        await asyncio.sleep(1)  # Wait before retry
                        continue
                    else:
                        logger.debug(f"Timeout for {host_url} after 3 attempts, skipping")
                        break
                except Exception as e:
                    if attempt < 2 and ("TimeoutError" in str(e) or "timeout" in str(e).lower()):
                        logger.debug(f"Timeout error for {host_url}, retrying (attempt {attempt + 1})")
                        await asyncio.sleep(1)
                        continue
                    else:
                        logger.debug(f"Failed to fingerprint {host_url}: {e}")
                        break

    def _save_results(self):
        lines = []
        for host, r in sorted(self.results.items()):
            lines.append(f"\n{'─'*50}")
            lines.append(f"Host: {host}")
            lines.append(f"{'─'*50}")
            if r.server:
                lines.append(f"  Server:     {r.server}")
            if r.framework:
                lines.append(f"  Framework:  {r.framework}")
            if r.language:
                lines.append(f"  Language:   {r.language}")
            if r.cms:
                lines.append(f"  CMS:        {r.cms}")
            if r.cdn:
                lines.append(f"  CDN:        {r.cdn}")
            if r.waf:
                lines.append(f"  WAF:        {r.waf}")
            if r.js_frameworks:
                lines.append(f"  JS Libs:    {', '.join(r.js_frameworks)}")

        # Save results (only if not empty)
        if lines:
            out_file = self.output_dir / "fingerprints.txt"
            out_file.write_text("\n".join(lines))