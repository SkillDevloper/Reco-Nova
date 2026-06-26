"""
Rich-based terminal display helpers for Reco-Nova v1.2.
Professional CLI UI with icons, panels, and progress bars.
"""

import threading
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.live import Live
from rich.text import Text
from rich import box
from rich.columns import Columns
from rich.status import Status
from rich.align import Align
from rich.tree import Tree


# Thread-safe console with lock for multiprocessing
console = Console()
console_lock = threading.Lock()

# Global live display management to prevent multiple active displays
_live_instance = None
_current_status = None


# Professional Icons (no emojis - using symbols/ASCII art)
ICONS = {
    # Phase Icons
    "subdomain": "[bold blue][/bold blue]",
    "probe": "[bold yellow]~[/bold yellow]",
    "url": "[bold cyan][#][/bold cyan]",
    "js": "[bold green]{js}[/bold green]",
    "sensitive": "[bold red][!][/bold red]",
    "fingerprint": "[bold magenta][f][/bold magenta]",
    "screenshot": "[bold cyan][ss][/bold cyan]",
    "report": "[bold white][rpt][/bold white]",
    
    # Status Icons
    "info": "[bold cyan][*][/bold cyan]",
    "success": "[bold green][+][/bold green]",
    "warning": "[bold yellow][!][/bold yellow]",
    "error": "[bold red][-][/bold red]",
    "found": "[bold magenta][FOUND][/bold magenta]",
    "scanning": "[bold blue]>>[/bold blue]",
    "complete": "[bold green]OK[/bold green]",
    "pending": "[bold dim]...[bold dim]",
}


class Display:
    def __init__(self, debug: bool = False):
        self.console = console
        self.debug = debug
        self.current_status = None

    def _safe_print(self, *args, **kwargs):
        """Thread-safe print using console lock."""
        with console_lock:
            self.console.print(*args, **kwargs)

    def _stop_existing_displays(self):
        """Stop any existing live displays or status indicators."""
        global _live_instance, _current_status
        
        # Stop live instance
        if _live_instance:
            try:
                _live_instance.stop()
            except:
                pass
            _live_instance = None
            
        # Stop status
        if _current_status:
            try:
                _current_status.stop()
            except:
                pass
            _current_status = None

    # ── Standard Messages ───────────────────────────────────────────
    
    def info(self, msg: str):
        self._safe_print(f"  {ICONS['info']} {msg}")

    def success(self, msg: str):
        self._safe_print(f"  {ICONS['success']} {msg}")

    def warning(self, msg: str):
        self._safe_print(f"  {ICONS['warning']} {msg}")

    def error(self, msg: str):
        self._safe_print(f"  {ICONS['error']} {msg}")

    def found(self, msg: str):
        self._safe_print(f"  {ICONS['found']} {msg}")

    def debug(self, msg: str):
        """Only print debug messages if debug mode is enabled."""
        if self.debug:
            self._safe_print(f"  [dim][DEBUG] {msg}[/dim]")

    def section(self, title: str, icon: str = ""):
        """Display a section header with optional icon."""
        icon_str = ICONS.get(icon, "")
        self.console.print()
        self.console.rule(f"[bold red] {icon_str} {title} [/bold red]")
        self.console.print()

    def panel(self, content: str, title: str = "", style: str = "cyan"):
        """Display content in a bordered panel."""
        self.console.print(Panel(content, title=title, border_style=style))

    def info_panel(self, title: str, items: dict, style: str = "blue"):
        """Display information in a boxed panel with key-value pairs."""
        lines = []
        for key, value in items.items():
            lines.append(f"[bold]{key}:[/bold] {value}")
        
        self.console.print(Panel(
            "\n".join(lines),
            title=f"[bold]{title}[/bold]",
            border_style=style,
            box=box.ROUNDED,
            padding=(1, 2),
        ))

    def stats_columns(self, stats: dict):
        """Display statistics in columns layout."""
        panels = []
        for label, value in stats.items():
            color = "green" if isinstance(value, (int, float)) and value > 0 else "dim"
            panel = Panel(
                f"[bold {color}]{value}[/bold {color}]",
                title=f"[dim]{label}[/dim]",
                border_style="dim",
                box=box.SQUARE,
                padding=(1, 3),
            )
            panels.append(panel)
        
        self.console.print(Columns(panels, equal=True, expand=True))

    def result_table(self, title: str, rows: list, columns: list) -> Table:
        table = Table(
            title=title,
            box=box.ROUNDED,
            border_style="dim",
            header_style="bold cyan",
            show_lines=True,
        )
        for col in columns:
            table.add_column(col)
        for row in rows:
            table.add_row(*[str(c) for c in row])
        self.console.print(table)
        return table

    def spinner(self, description: str) -> Progress:
        """Create a simple spinner progress."""
        return Progress(
            SpinnerColumn(style="bold red", spinner_name="dots"),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=self.console,
        )

    def progress_bar(self, title: str = "Progress") -> Progress:
        """Create a full progress bar with time elapsed."""
        self._stop_existing_displays()
        return Progress(
            SpinnerColumn(style="bold red"),
            TextColumn("[bold blue]{task.description}[/bold blue]"),
            BarColumn(bar_width=30, style="red", complete_style="green"),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=self.console,
        )

    def status(self, message: str) -> Status:
        """Create a status spinner for ongoing operations."""
        global _current_status
        
        self._stop_existing_displays()
        
        # Create new status
        _current_status = Status(
            f"[bold blue]{message}[/bold blue]",
            spinner="dots",
            spinner_style="blue",
            console=self.console,
        )
        return _current_status

    def phase_start(self, phase_num: int, total: int, name: str, icon: str):
        """Display phase start with consistent formatting."""
        icon_str = ICONS.get(icon, ICONS['info'])
        self.console.print(f"\n[bold red][Phase {phase_num}/{total}][/bold red] {icon_str} [bold]{name}[/bold]")

    def phase_complete(self, results: str = ""):
        """Display phase completion."""
        if results:
            self.console.print(f"  {ICONS['success']} Phase complete: {results}")
        else:
            self.console.print(f"  {ICONS['success']} Phase complete")

    def summary_box(self, domain: str, stats: dict):
        """Display final scan summary (Rich, 3-column grid)."""

        def _style_value(value: int, stat_key: str) -> str:
            # Security rules (strict)
            secrets = int(stats.get("Secrets Found", 0) or 0)
            critical = int(stats.get("Critical Targets", 0) or 0)
            high = int(stats.get("High Targets", 0) or 0)
            vuln_critical = int(stats.get("Vuln Critical", 0) or 0)
            vuln_high = int(stats.get("Vuln High", 0) or 0)

            if stat_key == "Secrets Found" and secrets > 0:
                return "bold red"
            if stat_key == "Critical Targets" and critical > 0:
                return "bold red"
            if stat_key == "High Targets" and high > 0:
                return "bold red"
            if stat_key == "Vulnerabilities Found" and (vuln_critical > 0 or vuln_high > 0):
                return "bold red"

            # General rules
            if value > 0:
                return "bold green" if stat_key in {"Subdomains", "Live Hosts"} else "bold cyan"
            return "dim"

        def _value_text(value: int, stat_key: str) -> Text:
            style = _style_value(value, stat_key)
            return Text(str(value), style=style)

        # Discovery / Analysis / Security (exact category keys as requested)
        discovery = [
            ("Subdomains", f"🌐 Subdomains", int(stats.get("Subdomains", 0) or 0)),
            ("Live Hosts", f"⚡ Live Hosts", int(stats.get("Live Hosts", 0) or 0)),
            ("Cloud Assets", f"☁️ Cloud Assets", int(stats.get("Cloud Assets", 0) or 0)),
        ]
        analysis = [
            ("URLs", f"🔎 URLs", int(stats.get("URLs", 0) or 0)),
            ("Parameters", f"🧩 Parameters", int(stats.get("Parameters", 0) or 0)),
            ("JS Files", f"⚙️ JS Files", int(stats.get("JS Files", 0) or 0)),
        ]
        security = [
            ("Secrets Found", f"🔑 Secrets", int(stats.get("Secrets Found", 0) or 0)),
            ("Sensitive Files", f"🧷 Sensitive Files", int(stats.get("Sensitive Files", 0) or 0)),
            ("Critical Targets", f"🛑 Critical Targets", int(stats.get("Critical Targets", 0) or 0)),
            ("High Targets", f"⚠️ High Targets", int(stats.get("High Targets", 0) or 0)),
            ("Vulnerabilities Found", f"🧨 Vulnerabilities Found", int(stats.get("Vulnerabilities Found", 0) or 0)),
        ]

        def _category_table(items: list[tuple[str, str, int]]) -> Table:
            t = Table.grid(expand=True)
            t.add_column(justify="left")
            t.add_column(justify="right")
            for stat_key, label, value in items:
                t.add_row(
                    Text(label, style="bold"),
                    _value_text(value, stat_key),
                )
            return t

        discovery_t = _category_table(discovery)
        analysis_t = _category_table(analysis)
        security_t = _category_table(security)

        out_dir = str(stats.get("Output Directory", "") or "")
        out_link = out_dir
        if out_dir:
            out_norm = out_dir.replace("\\", "/")
            # Windows drive paths: C:/... -> file:///C:/...
            if len(out_norm) >= 2 and out_norm[1] == ":":
                out_link = f"[link=file:///{out_norm}]{out_dir}[/link]"
            else:
                out_link = f"[link=file://{out_norm}]{out_dir}[/link]"

        summary_content = Group(
            f"[bold white]Target:[/bold white] [cyan]{domain}[/cyan]",
            Columns(
                [
                    Group(Text("Discovery", style="bold blue"), discovery_t),
                    Group(Text("Analysis", style="bold cyan"), analysis_t),
                    Group(Text("Security", style="bold magenta"), security_t),
                ],
                equal=True,
                expand=True,
            ),
            Text.from_markup(f"Output Directory: {out_link}", style="dim"),
            Text(f"Scan Duration: {stats.get('Scan Duration', '')}", style="dim"),
        )

        self.console.print()
        self.console.print(
            Panel(
                summary_content,
                title="[bold red]SCAN SUMMARY[/bold red]",
                border_style="red",
                box=box.ROUNDED,
                padding=(1, 2),
            )
        )

    def final_output(self, domain: str, files: list, elapsed: float):
        """Display final output with file locations."""
        file_lines = []
        for desc, path in files:
            file_lines.append(f"  {ICONS['info']} [dim]{desc}:[/dim] [cyan]{path}[/cyan]")
        
        self.console.print(Panel(
            f"[bold]Target:[/bold] {domain}\n"
            f"[bold]Elapsed:[/bold] {elapsed:.1f}s\n\n"
            + "\n".join(file_lines),
            title="[bold green] RESULTS [/bold green]",
            border_style="green",
            box=box.ROUNDED,
            padding=(1, 2),
        ))

    def live_progress(self, message: str, progress: Progress):
        """Display live progress with proper display management."""
        self._stop_existing_displays()
        self.console.print(f"[bold blue]{message}[/bold blue]")
        self.console.print(progress)