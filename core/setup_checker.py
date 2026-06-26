"""
Dependency Verification & Auto-Installation Module — v1.2
Checks Python version, libraries, and external tools.

New in v1.2:
  - httpx screenshot command updated to use -args parameter
  - Root user detection for Chrome sandbox args
  - gowitness aggressive fallback with individual URL processing
  - Modern Chrome User-Agent for JS intelligence
  - Debug output for HTTP response codes in Deep Crawl
"""

import sys
import subprocess
import shutil
from rich.console import Console
from rich.table import Table
from rich import box
from modules.vulnerability_scanner import NucleiScanner

console = Console()

PYTHON_MIN = (3, 9)

PYTHON_LIBS = [
    ("requests",       "pip install requests"),
    ("aiohttp",        "pip install aiohttp"),
    ("beautifulsoup4", "pip install beautifulsoup4 --break-system-packages --force-reinstall"),
    # fingerprinting dependencies (native engine)
    ("mmh3",            "pip install mmh3 --break-system-packages --force-reinstall"),
    ("lxml",           "pip install lxml --break-system-packages --force-reinstall"),
    ("rich",           "pip install rich"),
    ("typer",          "pip install typer"),
    ("tldextract",     "pip install tldextract"),
    ("dnspython",      "pip install dnspython --break-system-packages"),
    ("jsbeautifier",   "pip install jsbeautifier"),
    ("jinja2",         "pip install jinja2"),
    ("aiofiles",       "pip install aiofiles"),
]

EXTERNAL_TOOLS = [
    ("subfinder",   "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ("httpx",       "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ("assetfinder", "go install -v github.com/tomnomnom/assetfinder@latest"),
    ("gowitness",   "go install github.com/sensepost/gowitness@latest"),
    ("amass",       "go install -v github.com/owasp-amass/amass/v4/...@master"),
    ("nuclei",      "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
]

# Critical libs that cannot be skipped; others are optional
NON_CRITICAL = {"dnspython"}


class SetupChecker:
    def __init__(self, silent: bool = False):
        self.silent = silent
        self.missing_libs: list[tuple[str, str]] = []
        self.missing_tools: list[tuple[str, str]] = []

    # ── Public API ────────────────────────────────────────────────

    def run(self):
        """Full setup check with output."""
        console.rule("[bold red] Reco-Nova Environment Setup [/bold red]")
        console.print()
        self._check_python()
        self._check_libs(auto_install=True)
        self._check_tools()
        self._update_nuclei_templates()
        self.verify_imports()   # Deep import verification
        self._print_summary()

    def quick_check(self) -> bool:
        """Silent check. Returns True if all critical deps are present."""
        self._check_python(quiet=True)
        self._check_libs(auto_install=False, quiet=True)
        self._check_tools(quiet=True)
        critical_missing = [
            lib for lib, _ in self.missing_libs
            if lib not in NON_CRITICAL
        ]
        return len(critical_missing) == 0

    # ── Import Verification ───────────────────────────────────────

    def verify_imports(self):
        """
        Verify core fingerprinting imports in the active environment.
        BeautifulSoup4 (bs4) is optional due to regex fallback.
        """
        console.print()
        console.print("  [bold]Import Verification[/bold]")

        all_ok = True

        # Check bs4 (import name is bs4, package name is beautifulsoup4)
        try:
            __import__("bs4")
            console.print("    [OK] BeautifulSoup4", style="green", markup=False)
        except ImportError as exc:
            # BS4 is optional: fingerprinting falls back to regex extraction.
            console.print(f"    [yellow][FAIL][/yellow] BeautifulSoup4 ([dim]{exc}[/dim])")

        # Check native fingerprinting deps: mmh3 + lxml.
        # Phase-6 should NOT get disabled just because bs4 is missing; it has regex fallback.
        # Only check critical dependencies, not optional ones
        critical_deps = [
            ("aiohttp", "aiohttp"),
        ]
        
        for import_name, display_name in critical_deps:
            try:
                __import__(import_name)
                console.print(f"    [green][OK][/green] {display_name}")
            except ImportError as exc:
                all_ok = False
                console.print(f"    [red][FAIL][/red] {display_name} ([dim]{exc}[/dim])")
        
        # Optional fingerprinting deps (mmh3, lxml) - don't fail if missing
        optional_deps = [
            ("mmh3", "mmh3"),
            ("lxml", "lxml"),
        ]
        
        for import_name, display_name in optional_deps:
            try:
                __import__(import_name)
                console.print(f"    [green][OK][/green] {display_name} [dim](optional)[/dim]")
            except ImportError as exc:
                console.print(f"    [yellow][MISSING][/yellow] {display_name} [dim](optional - fingerprinting will work with regex fallback)[/dim]")

        # Return status for bypass logic (fingerprinting enabled iff core hashing deps exist)
        return all_ok

    # ── Python version ────────────────────────────────────────────

    def _check_python(self, quiet=False):
        ver = sys.version_info
        ok = (ver.major, ver.minor) >= PYTHON_MIN
        if not quiet:
            status = "[green]OK[/green]" if ok else "[red]FAIL[/red]"
            console.print(f"  [{status}] Python {ver.major}.{ver.minor}.{ver.micro}", markup=True)
            if not ok:
                console.print(f"       [red]Requires Python {PYTHON_MIN[0]}.{PYTHON_MIN[1]}+[/red]")
                sys.exit(1)

    # ── Python libraries ──────────────────────────────────────────

    def _check_libs(self, auto_install: bool = True, quiet: bool = False):
        if not quiet:
            console.print()
            console.print("  [bold]Python Libraries[/bold]")

        for lib, install_cmd in PYTHON_LIBS:
            # Handle special import-name aliases
            if lib == "beautifulsoup4":
                import_name = "bs4"
            else:
                import_name = "dns" if lib == "dnspython" else lib

            try:
                __import__(import_name)
                if not quiet:
                    console.print(f"    [green][OK][/green]  {lib}")
            except ImportError:
                self.missing_libs.append((lib, install_cmd))
                if not quiet:
                    console.print(f"    [yellow][!][/yellow]  {lib} [dim]— missing[/dim]")
                    if auto_install:
                        console.print(f"         Installing {lib}...")
                        success = self._pip_install(install_cmd, import_name)
                        if success:
                            console.print(f"         [green]Installed successfully[/green]")
                        else:
                            console.print(f"         [red]Failed to install {lib}[/red]")

    def _pip_install(self, cmd: str, import_name: str) -> bool:
        """
        Install package using sys.executable -m pip.

        For beautifulsoup4:
          always uses --break-system-packages --force-reinstall
        For others:
          tries with --break-system-packages first, then plain fallback.
        """
        parts = cmd.split()

        # Extract the package name (last token that is not a flag)
        package = next(
            (p for p in reversed(parts) if not p.startswith("-")),
            parts[-1],
        )

        force_flags = ["--break-system-packages", "--force-reinstall"]
        is_special = any(flag in parts for flag in ["--force-reinstall"])

        # Build the install command
        install_args = [sys.executable, "-m", "pip", "install", package, "--quiet"]

        if "--break-system-packages" in parts:
            install_args.append("--break-system-packages")
        if "--force-reinstall" in parts:
            install_args.append("--force-reinstall")

        try:
            subprocess.run(install_args, check=True, capture_output=True)
        except subprocess.CalledProcessError:
            try:
                # Fallback: plain install without extra flags
                fallback = [sys.executable, "-m", "pip", "install", package, "--quiet"]
                subprocess.run(fallback, check=True, capture_output=True)
            except Exception as e:
                console.print(f"         [red]Installation failed: {e}[/red]")
                return False
        except Exception as e:
            console.print(f"         [red]Installation failed: {e}[/red]")
            return False

        # Verify the library can be imported after installation
        try:
            __import__(import_name)
            return True
        except ImportError:
            console.print(
                f"         [red]Library installed but cannot be imported: "
                f"{import_name}[/red]"
            )
            return False

    # ── External tools ────────────────────────────────────────────

    def _check_tools(self, quiet: bool = False):
        if not quiet:
            console.print()
            console.print("  [bold]External Tools[/bold]")

        for tool, install_cmd in EXTERNAL_TOOLS:
            found = shutil.which(tool) is not None
            if found:
                if not quiet:
                    console.print(f"    [green][OK][/green]  {tool}")
            else:
                self.missing_tools.append((tool, install_cmd))
                if not quiet:
                    console.print(
                        f"    [yellow][!][/yellow]  {tool} [dim]— not found "
                        f"(install: {install_cmd})[/dim]"
                    )

    def _update_nuclei_templates(self):
        """Update nuclei templates if nuclei binary is available."""
        console.print()
        console.print("  [bold]Nuclei Templates[/bold]")
        if not NucleiScanner.is_available():
            console.print("    [yellow][!][/yellow] nuclei not found — template update skipped")
            return

        console.print("    [cyan][*][/cyan] Updating nuclei templates (nuclei -ut)...")
        if NucleiScanner.update_templates():
            console.print("    [green][OK][/green] nuclei templates updated")
        else:
            console.print("    [yellow][!][/yellow] nuclei template update failed")

    # ── Summary ───────────────────────────────────────────────────

    def _print_summary(self):
        console.print()
        if not self.missing_libs and not self.missing_tools:
            console.print("  [bold green]Environment ready.[/bold green] All dependencies satisfied.\n")
        else:
            if self.missing_tools:
                console.print("  [yellow]Missing external tools (manual install may be needed):[/yellow]")
                for tool, cmd in self.missing_tools:
                    console.print(f"    [red]{tool}[/red] — {cmd}")
            console.print()
            console.print("  [dim]Some tools use passive fallbacks when external binaries are unavailable.[/dim]\n")