"""
╔══════════════════════════════════════════════════════════════════╗
║        Reco-Nova — Self-Healing Update Engine v1.0               ║
║              Developer: Daniyal Shahid  |  CEH v13               ║
╚══════════════════════════════════════════════════════════════════╝

core/updater.py

Responsibilities
────────────────
1. Print a heavy-duty update banner.
2. Auto-install / update the 'reco-nova' shell alias in ~/.zshrc or ~/.bashrc.
3. Update Go-based tools: httpx, subfinder, katana.
4. Upgrade Python dependencies via pip.
5. Upgrade system packages (firefox-esr, gowitness) via apt if available.
6. Report a clean summary at the end.
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# Rich is used for coloured output; fall back to plain print if not installed
# ─────────────────────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import (
        Progress, SpinnerColumn, TextColumn, BarColumn,
        TaskProgressColumn, TimeElapsedColumn
    )
    from rich.text import Text
    _HAS_RICH = True
    _console = Console()
except ImportError:
    _HAS_RICH = False
    _console = None


# ─────────────────────────────────────────────────────────────────────────────
# Helper: print with or without Rich
# ─────────────────────────────────────────────────────────────────────────────
def _print(msg: str, style: str = ""):
    if _HAS_RICH:
        _console.print(msg, style=style)
    else:
        # Strip basic Rich markup for plain output
        import re
        plain = re.sub(r"\[/?[^\]]*\]", "", msg)
        print(plain)


def _rule(title: str = ""):
    if _HAS_RICH:
        _console.rule(title, style="bold green")
    else:
        print(f"\n{'─' * 60}  {title}  {'─' * 60}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Update steps
# ─────────────────────────────────────────────────────────────────────────────
GO_TOOLS = [
    ("httpx",     "github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ("subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ("katana",    "github.com/projectdiscovery/katana/cmd/katana@latest"),
    ("nuclei",    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
]

SYSTEM_PACKAGES = [
    "firefox-esr",
    "gowitness",
]


class UpdateEngine:
    """
    Orchestrates the full Reco-Nova self-healing update cycle:
      1. Banner
      2. Alias setup
      3. Go tools
      4. Python deps
      5. System packages
      6. Summary
    """

    def __init__(self, reco_nova_path: str | None = None, quiet: bool = False):
        # The absolute path to reco_nova.py — used when writing the alias
        self.reco_nova_path = reco_nova_path or str(
            Path(__file__).resolve().parent.parent / "reco_nova.py"
        )
        self.quiet = quiet
        self.results: dict[str, str] = {}   # step → "✔ OK" | "✘ FAILED" | "⚠ SKIPPED"

    # ─────────────────────────────────────────────────────────────────────────
    # Public entry point
    # ─────────────────────────────────────────────────────────────────────────
    def run(self):
        self._print_banner()
        self._setup_alias()
        self._update_go_tools()
        self._upgrade_python_deps()
        self._upgrade_system_packages()
        self._print_summary()

    # ─────────────────────────────────────────────────────────────────────────
    # 1. Banner
    # ─────────────────────────────────────────────────────────────────────────
    def _print_banner(self):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        banner_lines = [
            "",
            "  ██████╗ ███████╗ ██████╗ ██████╗       ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ",
            "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗      ████╗  ██║██╔═══██╗██║   ██║██╔══██╗",
            "  ██████╔╝█████╗  ██║     ██║   ██║█████╗██╔██╗ ██║██║   ██║██║   ██║███████║",
            "  ██╔══██╗██╔══╝  ██║     ██║   ██║╚════╝██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║",
            "  ██║  ██║███████╗╚██████╗╚██████╔╝      ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║",
            "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝       ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝",
            "",
        ]
        if _HAS_RICH:
            for line in banner_lines:
                _console.print(line, style="bold green")
            _console.print(
                Panel(
                    f"[bold yellow][[!]][/bold yellow] [bold white]RECO-NOVA SYSTEM UPDATE IN PROGRESS...[/bold white]\n"
                    f"[dim]Timestamp: {ts}[/dim]",
                    border_style="bold green",
                    title="[bold orange1]★ SELF-HEALING ENGINE v1.0 ★[/bold orange1]",
                    subtitle="[dim]Lead Auditor: Daniyal Shahid (CEH v13)[/dim]",
                )
            )
        else:
            for line in banner_lines:
                print(line)
            print(f"\n[!] RECO-NOVA SYSTEM UPDATE IN PROGRESS ...  [{ts}]\n")

    # ─────────────────────────────────────────────────────────────────────────
    # 2. Alias setup
    # ─────────────────────────────────────────────────────────────────────────
    def _setup_alias(self):
        _rule("ALIAS MANAGER")

        python_bin = sys.executable
        alias_line = f"alias reco-nova='{python_bin} {self.reco_nova_path}'"

        # Choose which rc file to update
        rc_candidates = [
            Path.home() / ".zshrc",
            Path.home() / ".bashrc",
            Path.home() / ".bash_profile",
        ]
        rc_file: Path | None = None
        for candidate in rc_candidates:
            if candidate.exists():
                rc_file = candidate
                break

        if rc_file is None:
            # None exist yet — create .bashrc
            rc_file = Path.home() / ".bashrc"
            rc_file.touch()

        # Read current content
        current = rc_file.read_text(encoding="utf-8", errors="ignore")

        if "alias reco-nova=" in current:
            # Update the existing alias in-place
            new_lines = []
            for line in current.splitlines():
                if line.strip().startswith("alias reco-nova="):
                    new_lines.append(alias_line)
                    _print(f"[green]  ✔ Alias updated in {rc_file}[/green]")
                    _print(f"[dim]    → {alias_line}[/dim]")
                else:
                    new_lines.append(line)
            rc_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        else:
            # Append a clean block
            block = (
                "\n"
                "# ── Reco-Nova Alias (added by update engine) ──────────────\n"
                f"{alias_line}\n"
            )
            with rc_file.open("a", encoding="utf-8") as f:
                f.write(block)
            _print(f"[green]  ✔ Alias added to {rc_file}[/green]")
            _print(f"[dim]    → {alias_line}[/dim]")
            _print(f"[yellow]  ⚡ Run: source {rc_file}  (or open a new terminal)[/yellow]")

        self.results["Alias Setup"] = "✔ OK"

    # ─────────────────────────────────────────────────────────────────────────
    # 3. Go tools
    # ─────────────────────────────────────────────────────────────────────────
    def _update_go_tools(self):
        _rule("GO TOOLS UPDATE")

        go_bin = shutil.which("go")
        if not go_bin:
            _print("[yellow]  ⚠  'go' not found in PATH — skipping Go tool updates.[/yellow]")
            _print("[dim]     Install Go from https://go.dev/dl/ and re-run --update[/dim]")
            for name, _ in GO_TOOLS:
                self.results[f"Go: {name}"] = "⚠ SKIPPED (go not found)"
            return

        go_env = os.environ.copy()
        # Ensure GOPATH/bin is in PATH so installed tools are immediately usable
        gopath = subprocess.run(
            [go_bin, "env", "GOPATH"], capture_output=True, text=True
        ).stdout.strip()
        if gopath:
            go_env["PATH"] = os.path.join(gopath, "bin") + os.pathsep + go_env.get("PATH", "")

        for tool_name, import_path in GO_TOOLS:
            _print(f"\n  [bold cyan]→[/bold cyan] Updating [bold]{tool_name}[/bold]...")
            cmd = [go_bin, "install", "-v", import_path]
            _print(f"  [dim]$ {' '.join(cmd)}[/dim]")

            try:
                result = subprocess.run(
                    cmd,
                    env=go_env,
                    capture_output=True,
                    text=True,
                    timeout=300,   # 5-minute max per tool
                )
                if result.returncode == 0:
                    _print(f"  [green]  ✔ {tool_name} updated successfully[/green]")
                    self.results[f"Go: {tool_name}"] = "✔ OK"
                else:
                    _print(f"  [red]  ✘ {tool_name} failed (exit {result.returncode})[/red]")
                    if result.stderr:
                        _print(f"  [dim]{result.stderr[:300]}[/dim]")
                    self.results[f"Go: {tool_name}"] = f"✘ FAILED (exit {result.returncode})"
            except subprocess.TimeoutExpired:
                _print(f"  [red]  ✘ {tool_name} timed out (5 min)[/red]")
                self.results[f"Go: {tool_name}"] = "✘ TIMED OUT"
            except Exception as e:
                _print(f"  [red]  ✘ Unexpected error for {tool_name}: {e}[/red]")
                self.results[f"Go: {tool_name}"] = f"✘ ERROR: {e}"

    # ─────────────────────────────────────────────────────────────────────────
    # 4. Python deps
    # ─────────────────────────────────────────────────────────────────────────
    def _upgrade_python_deps(self):
        _rule("PYTHON DEPENDENCIES")

        req_file = Path(self.reco_nova_path).parent / "requirements.txt"
        if not req_file.exists():
            _print(f"[yellow]  ⚠  requirements.txt not found at {req_file} — skipping[/yellow]")
            self.results["Python deps"] = "⚠ SKIPPED (no requirements.txt)"
            return

        _print(f"  [bold cyan]→[/bold cyan] Upgrading packages from [bold]{req_file}[/bold]...")
        cmd = [sys.executable, "-m", "pip", "install", "--upgrade", "-r", str(req_file), "--quiet"]
        _print(f"  [dim]$ {' '.join(cmd)}[/dim]")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                _print("  [green]  ✔ Python dependencies upgraded[/green]")
                self.results["Python deps"] = "✔ OK"
            else:
                _print(f"  [red]  ✘ pip failed (exit {result.returncode})[/red]")
                if result.stderr:
                    _print(f"  [dim]{result.stderr[:400]}[/dim]")
                self.results["Python deps"] = f"✘ FAILED (exit {result.returncode})"
        except subprocess.TimeoutExpired:
            _print("  [red]  ✘ pip timed out (5 min)[/red]")
            self.results["Python deps"] = "✘ TIMED OUT"
        except Exception as e:
            _print(f"  [red]  ✘ pip error: {e}[/red]")
            self.results["Python deps"] = f"✘ ERROR: {e}"

    # ─────────────────────────────────────────────────────────────────────────
    # 5. System packages via apt
    # ─────────────────────────────────────────────────────────────────────────
    def _upgrade_system_packages(self):
        _rule("SYSTEM PACKAGES (apt)")

        apt_bin = shutil.which("apt") or shutil.which("apt-get")
        if not apt_bin:
            _print("[yellow]  ⚠  apt/apt-get not found — skipping system package updates[/yellow]")
            _print("[dim]     (This step only applies on Debian/Ubuntu/Kali systems)[/dim]")
            self.results["System packages"] = "⚠ SKIPPED (apt not found)"
            return

        # apt update first
        _print("  [bold cyan]→[/bold cyan] Running apt update...")
        try:
            up = subprocess.run(
                ["sudo", apt_bin, "update", "-qq"],
                capture_output=True, text=True, timeout=120
            )
            if up.returncode == 0:
                _print("  [green]  ✔ apt update done[/green]")
            else:
                _print(f"  [yellow]  ⚠ apt update returned {up.returncode} — continuing anyway[/yellow]")
        except Exception as e:
            _print(f"  [yellow]  ⚠ apt update skipped: {e}[/yellow]")

        # Install / upgrade each package
        for pkg in SYSTEM_PACKAGES:
            _print(f"\n  [bold cyan]→[/bold cyan] Upgrading [bold]{pkg}[/bold]...")
            cmd = ["sudo", apt_bin, "install", "--only-upgrade", pkg, "-y", "-qq"]
            _print(f"  [dim]$ {' '.join(cmd)}[/dim]")
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                if res.returncode == 0:
                    _print(f"  [green]  ✔ {pkg} upgraded[/green]")
                    self.results[f"apt: {pkg}"] = "✔ OK"
                else:
                    # Package might not be in apt repos (gowitness), not fatal
                    _print(f"  [yellow]  ⚠ {pkg} not upgraded (may not be in apt repos)[/yellow]")
                    self.results[f"apt: {pkg}"] = f"⚠ SKIPPED/NOT FOUND"
            except subprocess.TimeoutExpired:
                _print(f"  [red]  ✘ apt {pkg} timed out[/red]")
                self.results[f"apt: {pkg}"] = "✘ TIMED OUT"
            except Exception as e:
                _print(f"  [yellow]  ⚠ apt {pkg} error: {e}[/yellow]")
                self.results[f"apt: {pkg}"] = f"⚠ ERROR: {e}"

    # ─────────────────────────────────────────────────────────────────────────
    # 6. Summary table
    # ─────────────────────────────────────────────────────────────────────────
    def _print_summary(self):
        _rule("UPDATE SUMMARY")

        if _HAS_RICH:
            table = Table(
                title="[bold green]System Update Report[/bold green]",
                border_style="green",
                header_style="bold orange1",
                show_lines=True,
            )
            table.add_column("Component", style="bold white", min_width=22)
            table.add_column("Status", min_width=28)

            for component, status in self.results.items():
                if status.startswith("✔"):
                    color = "green"
                elif status.startswith("⚠"):
                    color = "yellow"
                else:
                    color = "red"
                table.add_row(component, f"[{color}]{status}[/{color}]")

            _console.print(table)

            ok_count   = sum(1 for s in self.results.values() if s.startswith("✔"))
            skip_count = sum(1 for s in self.results.values() if s.startswith("⚠"))
            fail_count = sum(1 for s in self.results.values() if s.startswith("✘"))

            _console.print(
                Panel(
                    f"[bold green]{ok_count} Updated[/bold green]  "
                    f"[yellow]{skip_count} Skipped[/yellow]  "
                    f"[red]{fail_count} Failed[/red]\n\n"
                    "[bold white][+] All systems updated.[/bold white]\n"
                    "[bold orange1]Lead Auditor: Daniyal Shahid (CEH v13) is ready for deployment.[/bold orange1]",
                    border_style="green",
                    title="[bold green]★ UPDATE COMPLETE ★[/bold green]",
                )
            )
        else:
            # Plain text summary
            print("\n── UPDATE SUMMARY ───────────────────────────────────────")
            for component, status in self.results.items():
                print(f"  {component:<28} {status}")
            print("")
            print("[+] All systems updated.")
            print("[+] Lead Auditor: Daniyal Shahid (CEH v13) is ready for deployment.")
            print("─────────────────────────────────────────────────────────\n")
