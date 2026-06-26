"""
Screenshot Intelligence Module — v1.4
Primary: httpx  (-ss -system-chrome) — avoids headless-browser conflicts.
Fallback: gowitness scan single --url [URL] --write-path [DIR] --delay 5
Last resort: Firefox headless.

v1.4 changes:
  - httpx promoted to PRIMARY screenshot tool (-ss -system-chrome -silent -nc)
  - gowitness becomes clean fallback (--url / --write-path flags)
  - Firefox demoted to last-resort only (was causing 'already running' errors)
  - All subprocess calls wrapped in try/except so scan always continues
  - Module-level timeout stays 30s per attempt
"""

import asyncio
import shutil
import os
from pathlib import Path
from urllib.parse import urlparse
from core.display import Display
from core.logger import get_logger
from core.utils import get_random_ua
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.live import Live

logger = get_logger("screenshots")
display = Display()

# Ordered list of Firefox binary paths to check
FIREFOX_BINARY_CANDIDATES = [
    "/usr/bin/firefox",
    "/usr/bin/firefox-esr",
    "/usr/bin/firefox-developer-edition",
    "/snap/bin/firefox",
    "/usr/local/bin/firefox",
    "/opt/firefox/firefox",
]


def _find_firefox_binary() -> str | None:
    """Return the first existing Firefox binary path, or None."""
    for path in FIREFOX_BINARY_CANDIDATES:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    # Also try PATH lookup as last resort
    for name in ("firefox", "firefox-esr", "firefox-developer-edition"):
        found = shutil.which(name)
        if found:
            return found
    return None


class ScreenshotCapture:
    def __init__(self, live_hosts: list[str], screenshot_dir: Path,
                 threads: int = 5, delay: int = 5,
                 all_urls: list[str] | None = None):
        self.live_hosts = list(live_hosts)
        self.screenshot_dir = screenshot_dir
        self.threads = threads
        self.delay = delay                     # DOM render wait (seconds)
        self.all_urls: list[str] = all_urls or []
        self.captured: list[Path] = []

    # ──────────────────────────────────────────────────────────────
    # Public entry point
    # ──────────────────────────────────────────────────────────────

    async def run(self) -> list[str]:
        # Screenshot Engine Diagnostic: Check for Chrome/Chromium dependency
        chrome_check = os.system('which google-chrome > /dev/null 2>&1')
        if chrome_check != 0:
            chrome_check_alt = os.system('which chromium > /dev/null 2>&1')
            if chrome_check_alt != 0:
                chrome_check_alt2 = os.system('which chrome > /dev/null 2>&1')
                if chrome_check_alt2 != 0:
                    display.error("[!] Screenshot tool dependency (Chrome/Chromium) missing")
                    logger.error("Chrome/Chromium not found - screenshots may fail")
                    display.warning("Please install Google Chrome or Chromium for screenshot functionality")
                    display.info("Install with: apt-get install google-chrome-stable OR chromium-browser")
                else:
                    logger.info("Chrome binary found")
            else:
                logger.info("Chromium binary found")
        else:
            logger.info("Google Chrome binary found")

        # Directory Setup: Ensure screenshot directory exists
        os.makedirs(self.screenshot_dir, exist_ok=True)
        logger.info(f"Screenshot directory ensured: {self.screenshot_dir}")

        # ── Force Logic ───────────────────────────────────────────
        if not self.live_hosts and self.all_urls:
            display.warning(
                "No live hosts found — Force Logic: extracting unique domains from URLs..."
            )
            extracted = self._extract_domains_from_urls(self.all_urls)
            if extracted:
                display.info(
                    f"Force Logic: [bold]{len(extracted)}[/bold] unique domains "
                    "queued for screenshot attempt"
                )
                self.live_hosts = extracted
            else:
                display.warning("Force Logic: no extractable domains — skipping screenshots")
                return []

        if not self.live_hosts:
            display.warning("No targets available for screenshot capture")
            return []

        # Detect tools
        httpx_available   = bool(shutil.which("httpx"))
        gowitness_avail   = bool(shutil.which("gowitness"))
        firefox_path      = _find_firefox_binary()

        if not httpx_available and not gowitness_avail and not firefox_path:
            display.error("No screenshot tool available (httpx / gowitness / firefox)")
            return []

        display.info(f"Capturing screenshots for [bold]{len(self.live_hosts)}[/bold] hosts...")

        # ── PRIMARY: httpx (-ss -system-chrome) ────────────────────
        if httpx_available:
            httpx_results = await self._run_httpx_screenshot()
            if httpx_results:
                return httpx_results
            display.warning("httpx screenshot returned 0 results — trying gowitness fallback...")
        else:
            display.warning("httpx not found — trying gowitness...")

        # ── FALLBACK: gowitness scan single ─────────────────────────
        if gowitness_avail:
            gw_results = await self._run_gowitness()
            if gw_results:
                return gw_results
            display.warning("gowitness failed — trying Firefox last resort...")
        else:
            display.warning("gowitness not found — trying Firefox last resort...")

        # ── LAST RESORT: Firefox headless ───────────────────────────
        if firefox_path or shutil.which("firefox"):
            return await self._run_firefox_screenshot(firefox_path)

        display.error("All screenshot methods failed (httpx, gowitness, firefox)")
        logger.warning("No screenshot tools available or all methods failed")
        return []

    # ──────────────────────────────────────────────────────────────
    # Firefox (primary)
    # ──────────────────────────────────────────────────────────────

    async def _run_firefox_screenshot(self, firefox_path: str | None) -> list[str]:
        """
        Primary screenshot method using Firefox Headless.
        Command: firefox --headless --screenshot [OUTPUT_PATH] [URL]
        30-second timeout for each screenshot attempt.
        """
        display.info("Using Firefox Headless for screenshot capture (firefox --headless --screenshot [PATH] [URL])...")
        
        results = []
        
        # Check if Firefox is available
        if not firefox_path and not shutil.which("firefox"):
            display.error("Firefox not found in PATH")
            logger.error("Firefox binary not found")
            return []
            
        firefox_binary = firefox_path or shutil.which("firefox")

        # Create progress bar for screenshots
        progress = display.progress_bar()

        with Live(progress, refresh_per_second=10):
            task_firefox = progress.add_task(f"Firefox Screenshots", total=len(self.live_hosts))

            # Process each URL individually for better control
            for i, host in enumerate(self.live_hosts):
                # Update progress
                progress.update(task_firefox, completed=i, description=f"Firefox Screenshots ({i+1}/{len(self.live_hosts)})")

                # Generate filename from URL
                filename = f"{host.replace('://', '_').replace('/', '_')}.png"
                filepath = self.screenshot_dir / filename

                # Firefox command: --headless --screenshot [OUTPUT_PATH] [URL]
                cmd = [
                    firefox_binary or "firefox",
                    "--headless",
                    "--screenshot", str(filepath),
                    host
                ]

                # Debugging: Log the exact command
                logger.info(f"Running command: {' '.join(cmd)}")

                try:
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                except FileNotFoundError as e:
                    display.error(f"Firefox binary not found: {e}")
                    logger.error(f"Firefox not found: {e}")
                    break
                except Exception as e:
                    display.error(f"Failed to start Firefox: {e}")
                    logger.error(f"Failed to start Firefox: {e}")
                    continue

                try:
                    # 30-second timeout for each screenshot attempt
                    stdout_bytes, stderr_bytes = await asyncio.wait_for(
                        proc.communicate(), timeout=30
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    display.warning(f"Firefox screenshot timed out for {host} (30s limit)")
                    logger.warning(f"Firefox screenshot timed out for {host}")
                    stdout_bytes, stderr_bytes = b"", b""

                stdout = stdout_bytes.decode(errors="ignore")
                stderr = stderr_bytes.decode(errors="ignore")

                if proc.returncode == 0 and filepath.exists():
                    results.append(str(filepath))
                    logger.info(f"Firefox screenshot captured: {filepath}")
                else:
                    display.warning(
                        f"Firefox failed for {host} with code [bold red]{proc.returncode}[/bold red]"
                    )
                    logger.error(
                        f"Firefox FAILED for {host} — exit code {proc.returncode}\n"
                        f"═══ STDERR ═══\n{stderr}\n"
                        f"═══ STDOUT ═══\n{stdout}"
                    )
                
        self.captured = list(self.screenshot_dir.glob("*.png"))
        count = len(self.captured)
        display.success(f"Firefox screenshots captured: [bold green]{count}[/bold green]")
        logger.info(f"Firefox screenshots: {count}")
        return [str(f) for f in self.captured]

    # ──────────────────────────────────────────────────────────────
    # gowitness  (fallback)
    # ──────────────────────────────────────────────────────────────

    async def _run_gowitness(self) -> list[str]:
        """
        Fallback screenshot using Gowitness.
        Command: gowitness scan single --url [URL] --write-path [DIR] --delay 5
        30-second timeout per host.
        """
        display.info("Using gowitness fallback (gowitness scan single --url [URL] --write-path [DIR] --delay 5)...")

        results = []

        for host in self.live_hosts:
            cmd = [
                "gowitness", "scan", "single",
                "-u", host,
                "-s", str(self.screenshot_dir),
                "--delay", "5",
            ]

            logger.info(f"Running command: {' '.join(cmd)}")

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError as e:
                display.warning(f"gowitness binary not found: {e}")
                logger.warning(f"gowitness not found: {e}")
                break
            except Exception as e:
                display.warning(f"Failed to start gowitness for {host}: {e}")
                logger.warning(f"gowitness start error for {host}: {e}")
                continue

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=30
                )
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass
                display.warning(f"gowitness timed out for {host} (30s limit)")
                logger.warning(f"gowitness timed out for {host}")
                stdout_bytes, stderr_bytes = b"", b""

            stdout = stdout_bytes.decode(errors="ignore")
            stderr = stderr_bytes.decode(errors="ignore")

            if proc.returncode not in (0, None):
                # Version resilience: If it complains about a flag, try a simpler command
                if "unknown flag" in stderr.lower() or "flag provided but not" in stderr.lower():
                    logger.warning(f"gowitness flag error detected for {host}, falling back to safer syntax...")
                    fallback_cmd = [
                        "gowitness", "single", host,
                        "-s", str(self.screenshot_dir)
                    ]
                    try:
                        f_proc = await asyncio.create_subprocess_exec(
                            *fallback_cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        f_stdout, f_stderr = await asyncio.wait_for(f_proc.communicate(), timeout=30)
                        if f_proc.returncode in (0, None):
                            continue  # Fallback succeeded
                    except Exception:
                        pass
                
                display.warning(
                    f"gowitness failed for {host} with code [bold red]{proc.returncode}[/bold red]"
                )
                logger.error(
                    f"gowitness FAILED for {host} — exit {proc.returncode}\n"
                    f"STDERR: {stderr}\nSTDOUT: {stdout}"
                )
                continue

            if stderr.strip():
                logger.warning(f"gowitness stderr for {host}: {stderr[:200]}")

        self.captured = list(self.screenshot_dir.glob("*.png"))
        count = len(self.captured)
        display.success(f"gowitness screenshots captured: [bold green]{count}[/bold green]")
        logger.info(f"gowitness screenshots: {count}")
        return [str(f) for f in self.captured]

    # ──────────────────────────────────────────────────────────────
    # httpx screenshot (tertiary fallback with stealth UA)
    # ──────────────────────────────────────────────────────────────

    async def _run_httpx_screenshot(self) -> list[str]:
        """
        PRIMARY screenshot method using httpx.
        Command: httpx -u [URL] -ss -system-chrome -screenshot-path [DIR] -silent -nc
        Uses -system-chrome to leverage the installed Chromium/Chrome instead of
        spawning its own headless instance (avoids 'already running' conflicts).
        Per-host calls so each URL gets a clean timeout and the scan never blocks.
        """
        display.info(
            "Using httpx PRIMARY screenshot "
            "(httpx -u [URL] -ss -system-chrome -screenshot-path [DIR] -silent -nc)..."
        )

        results = []

        for host in self.live_hosts:
            # Per-URL call: direct URL instead of -u flag
            cmd = [
                "httpx",
                host,
                "-ss",
                "-system-chrome",
                "-screenshot-path", str(self.screenshot_dir),
                "-silent",
                "-nc",
            ]

            logger.info(f"Running command: {' '.join(cmd)}")

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError as e:
                display.warning(f"httpx binary not found: {e}")
                logger.warning(f"httpx not found: {e}")
                return results  # Exit early — tool unavailable
            except Exception as e:
                display.warning(f"Failed to start httpx for {host}: {e}")
                logger.warning(f"httpx start error for {host}: {e}")
                continue   # Try next host

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=30
                )
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass
                display.warning(f"httpx timed out for {host} (30s limit)")
                logger.warning(f"httpx timed out for {host}")
                stdout_bytes, stderr_bytes = b"", b""

            stdout = stdout_bytes.decode(errors="ignore")
            stderr = stderr_bytes.decode(errors="ignore")

            if proc.returncode not in (0, None):
                # Version resilience: check if -system-chrome flag is rejected
                if "system-chrome" in stderr.lower() or "unknown flag" in stderr.lower():
                    logger.warning(f"httpx -system-chrome flag rejected for {host}, retrying without it...")
                    fallback_cmd = [
                        "httpx", host, "-ss",
                        "-screenshot-path", str(self.screenshot_dir),
                        "-silent", "-nc"
                    ]
                    try:
                        f_proc = await asyncio.create_subprocess_exec(
                            *fallback_cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        f_stdout, f_stderr = await asyncio.wait_for(f_proc.communicate(), timeout=30)
                        if f_proc.returncode in (0, None):
                            continue  # Fallback succeeded
                    except Exception:
                        pass

                logger.warning(
                    f"httpx non-zero exit {proc.returncode} for {host}\n"
                    f"STDERR: {stderr[:300]}\nSTDOUT: {stdout[:300]}"
                )
            elif stderr.strip():
                logger.debug(f"httpx stderr for {host}: {stderr[:200]}")

        # Collect whatever screenshots appeared
        self.captured = list(self.screenshot_dir.glob("*.png"))
        count = len(self.captured)
        display.success(f"httpx screenshots captured: [bold green]{count}[/bold green]")
        logger.info(f"httpx screenshots: {count}")
        return [str(f) for f in self.captured]

    # ──────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_domains_from_urls(urls: list[str]) -> list[str]:
        """Extract unique scheme://netloc pairs from a list of URLs."""
        seen: set[str] = set()
        result: list[str] = []
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    for scheme in ("https", "http"):
                        key = f"{scheme}://{parsed.netloc}"
                        if key not in seen:
                            seen.add(key)
                            result.append(key)
            except Exception:
                continue
        return result