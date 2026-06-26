"""Central configuration for Reco-Nova."""

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    # Directories
    output_dir: str = "output"
    graph_dir: str = "graphs"
    db_dir: str = "database"
    report_dir: str = "reports"
    log_dir: str = "logs"

    # Performance
    max_threads: int = 20
    timeout: int = 10
    max_retries: int = 2
    rate_limit_delay: float = 0.1   # seconds between requests

    # Scan options
    full_scan: bool = False
    generate_graph: bool = False
    screenshots: bool = True
    passive_only: bool = False
    verbose: bool = False

    # Sensitive files to check
    sensitive_files: list = field(default_factory=lambda: [
        ".env", ".env.local", ".env.production", ".env.backup",
        ".git/config", ".git/HEAD", ".git/",
        "backup.zip", "backup.tar.gz", "backup.sql", "backup.db",
        "database.sql", "db.sql", "dump.sql",
        "config.php", "config.json", "config.yml", "config.yaml",
        "wp-config.php", "configuration.php",
        "web.config", ".htaccess",
        "id_rsa", "id_dsa", ".ssh/id_rsa",
        "phpinfo.php", "info.php", "test.php",
        "admin/", "administrator/", "phpmyadmin/",
        "robots.txt", "sitemap.xml",
        ".DS_Store", "Thumbs.db",
        "credentials.json", "secrets.json",
        "composer.json", "package.json",
        "Dockerfile", "docker-compose.yml",
    ])

    # Admin keywords for prioritization
    admin_keywords: list = field(default_factory=lambda: [
        "admin", "administrator", "manage", "management",
        "dashboard", "panel", "control", "cp",
        "internal", "intranet", "private", "secret",
        "dev", "develop", "development", "staging", "stage", "stg",
        "test", "testing", "qa", "uat",
        "api", "backend", "server",
        "debug", "debugger", "trace",
        "login", "auth", "signin", "signup",
        "monitor", "monitoring", "grafana", "kibana",
        "jenkins", "gitlab", "bitbucket",
    ])

    # Parameter vulnerability mapping
    param_vulns: dict = field(default_factory=lambda: {
        # IDOR
        "id": ("IDOR", "High"),
        "user_id": ("IDOR", "High"),
        "uid": ("IDOR", "High"),
        "account_id": ("IDOR", "High"),
        "order_id": ("IDOR", "High"),
        "post_id": ("IDOR", "High"),
        "doc_id": ("IDOR", "High"),
        "file_id": ("IDOR", "High"),
        # Open Redirect
        "redirect": ("Open Redirect", "Medium"),
        "redirect_url": ("Open Redirect", "Medium"),
        "redirect_uri": ("Open Redirect", "Medium"),
        "next": ("Open Redirect", "Medium"),
        "url": ("Open Redirect", "Medium"),
        "return": ("Open Redirect", "Medium"),
        "returnTo": ("Open Redirect", "Medium"),
        "goto": ("Open Redirect", "Medium"),
        "target": ("Open Redirect", "Medium"),
        # Path Traversal / LFI
        "file": ("Path Traversal / LFI", "High"),
        "path": ("Path Traversal / LFI", "High"),
        "load": ("Path Traversal / LFI", "High"),
        "include": ("Path Traversal / LFI", "High"),
        "require": ("Path Traversal / LFI", "High"),
        "page": ("Path Traversal / LFI", "Medium"),
        "template": ("Path Traversal / LFI", "High"),
        # SQLi / XSS
        "query": ("SQLi / XSS", "High"),
        "search": ("SQLi / XSS", "High"),
        "q": ("SQLi / XSS", "High"),
        "keyword": ("SQLi / XSS", "High"),
        "term": ("SQLi / XSS", "Medium"),
        "filter": ("SQLi / XSS", "Medium"),
        "name": ("SQLi / XSS", "Medium"),
        # JSONP Injection
        "callback": ("JSONP Injection", "Medium"),
        "jsonp": ("JSONP Injection", "Medium"),
        "cb": ("JSONP Injection", "Medium"),
        # Secret / Credential Exposure
        "token": ("Token Exposure", "Critical"),
        "api_key": ("API Key Exposure", "Critical"),
        "key": ("Key Exposure", "Critical"),
        "secret": ("Secret Exposure", "Critical"),
        "password": ("Credential Exposure", "Critical"),
        "passwd": ("Credential Exposure", "Critical"),
        "pass": ("Credential Exposure", "Critical"),
        "auth": ("Auth Token Exposure", "Critical"),
        "access_token": ("Token Exposure", "Critical"),
        # SSRF
        "host": ("SSRF", "High"),
        "domain": ("SSRF", "High"),
        "ip": ("SSRF", "High"),
        "port": ("SSRF", "Medium"),
        "endpoint": ("SSRF", "High"),
        "uri": ("SSRF", "High"),
        "src": ("SSRF / Open Redirect", "High"),
        "dest": ("SSRF / Open Redirect", "High"),
    })

    # Secret patterns for JS analysis
    secret_patterns: list = field(default_factory=lambda: [
        (r"(?i)api[_-]?key\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]", "API Key"),
        (r"(?i)api[_-]?secret\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]", "API Secret"),
        (r"(?i)secret[_-]?key\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]", "Secret Key"),
        (r"(?i)access[_-]?token\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{16,})['\"]", "Access Token"),
        (r"(?i)auth[_-]?token\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]", "Auth Token"),
        (r"(?i)password\s*[:=]\s*['\"]([^\s'\"]{6,})['\"]", "Password"),
        (r"(?i)passwd\s*[:=]\s*['\"]([^\s'\"]{6,})['\"]", "Password"),
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
        (r"(?i)aws[_-]?secret\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]", "AWS Secret"),
        (r"(?i)private[_-]?key\s*[:=]\s*['\"]([^\s'\"]{16,})['\"]", "Private Key"),
        (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "PEM Private Key"),
        (r"(?i)jwt\s*[:=]\s*['\"]([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*)['\"]", "JWT Token"),
        (r"(?i)firebase[^\n]*['\"]AIza[0-9A-Za-z\-_]{35}['\"]", "Firebase Key"),
        (r"(?i)stripe[_-]?key\s*[:=]\s*['\"]sk_(live|test)_[A-Za-z0-9]{24,}['\"]", "Stripe Key"),
        (r"(?i)sendgrid[^\n]*SG\.[A-Za-z0-9\-_\.]{66}", "SendGrid Key"),
        (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Token"),
        (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token"),
        (r"(?i)slack[^\n]*xox[baprs]-[A-Za-z0-9\-]{10,}", "Slack Token"),
        (r"(?i)database[_-]?url\s*[:=]\s*['\"]([^\s'\"]{10,})['\"]", "Database URL"),
        (r"(?i)db[_-]?password\s*[:=]\s*['\"]([^\s'\"]{6,})['\"]", "DB Password"),
    ])


# Global config instance
config = Config()


def get_output_dirs(domain: str, base: str = "output") -> dict:
    """Return all output subdirs for a given domain scan."""
    base_path = Path(base) / domain
    dirs = {
        "base": base_path,
        "screenshots": base_path / "screenshots",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    return dirs