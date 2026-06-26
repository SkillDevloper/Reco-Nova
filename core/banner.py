"""Banner and branding for Reco-Nova."""

from rich.console import Console
from rich.text import Text

console = Console()


def print_banner():
    banner = r"""
 ██████╗ ███████╗ ██████╗ ██████╗       ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ 
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗      ████╗  ██║██╔═══██╗██║   ██║██╔══██╗
 ██████╔╝█████╗  ██║     ██║   ██║█████╗██╔██╗ ██║██║   ██║██║   ██║███████║
 ██╔══██╗██╔══╝  ██║     ██║   ██║╚════╝██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
 ██║  ██║███████╗╚██████╗╚██████╔╝      ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝       ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝
"""
    console.print(banner, style="bold red")
    console.print(
        "  [bold white]Reconnaissance Intelligence Framework[/bold white]  "
        "[dim]|[/dim]  [cyan]Developer: Daniyal Shahid[/cyan]  "
        "[dim]|[/dim]  [yellow]v1.2[/yellow]\n",
        justify="center"
    )
    console.print(
        "  [dim]Use only against authorized targets. "
        "Unauthorized use is illegal.[/dim]\n",
        justify="center"
    )
    console.rule(style="dim red")
    console.print()