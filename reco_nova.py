#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║        Reco-Nova — Reconnaissance Intelligence Framework         ║
║              Developer: Daniyal Shahid  |  v1.2                  ║
╚══════════════════════════════════════════════════════════════════╝

v1.2 — Bulletproof edition
  - sys.path patched with site.getusersitepackages() at startup to
    ensure all pip-installed libraries (bs4, native deps, etc.) are found
  - Global crash protection: any unhandled exception saves partial report
"""

import sys
import site
import os
import asyncio
import argparse
import webbrowser
from pathlib import Path

# ── PATH FIX — must happen before ANY local imports ──────────────
# Appends the user-level site-packages so pip-installed libs like bs4
# and native fingerprinting deps are always discoverable, regardless of how the script
# is invoked (direct python3, alias, sudo, virtualenv mismatch, etc.)
try:
    _user_site = site.getusersitepackages()
    if _user_site not in sys.path:
        sys.path.append(_user_site)
except Exception:
    pass  # Non-fatal — continue without it

# VENV ENFORCEMENT (Python 3.13)
# Some users run this script from outside the venv, so we explicitly
# append the expected 3.13 site-packages path.
try:
    sys.path.append(os.path.join(os.getcwd(), 'venv/lib/python3.13/site-packages'))
except Exception:
    pass

# Add project root to path (must come after the site fix)
sys.path.insert(0, str(Path(__file__).parent))

from core.banner import print_banner
from core.setup_checker import SetupChecker
from core.input_handler import InputHandler
from core.scan_engine import ScanEngine
from core.reporter import Reporter
from core.logger import get_logger
from core.display import Display

logger = get_logger("main")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="reco-nova",
        description="Reco-Nova — Reconnaissance Intelligence Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  reco-nova -d example.com
  reco-nova -d example.com --full
  reco-nova -l domains.txt
  reco-nova -d example.com --graph
  reco-nova monitor example.com
  reco-nova report example.com
  reco-nova setup
        """
    )

    subparsers = parser.add_subparsers(dest="command")

    # Setup command
    subparsers.add_parser("setup", help="Verify and install all dependencies")

    # Monitor command
    monitor_parser = subparsers.add_parser("monitor", help="Enable continuous monitoring mode")
    monitor_parser.add_argument("domain", help="Target domain to monitor")
    monitor_parser.add_argument("--interval", type=int, default=3600,
                                help="Monitoring interval in seconds (default: 3600)")

    # Report command
    report_parser = subparsers.add_parser("report", help="Generate final report for a domain")
    report_parser.add_argument("domain", help="Domain to generate report for")

    # Main scan arguments
    parser.add_argument("-d", "--domain",  help="Single target domain")
    parser.add_argument("-l", "--list",    help="File containing list of domains")
    parser.add_argument("--full",          action="store_true", help="Run full recon (all modules)")
    parser.add_argument("--graph",         action="store_true", help="Generate attack surface graph")
    parser.add_argument("--threads",       type=int, default=20,  help="Number of threads (default: 20)")
    parser.add_argument("--timeout",       type=int, default=15,  help="Request timeout in seconds (default: 15)")
    parser.add_argument("--delay",         action="store_true",   help="Enable execution jitter (0.5-2s random delay between requests)")
    parser.add_argument("--output",        default="output",      help="Output directory (default: output)")
    parser.add_argument("--no-screenshots",action="store_true",   help="Skip screenshot capture")
    parser.add_argument("--passive-only",  action="store_true",   help="Use passive sources only")
    parser.add_argument("--nuclei",        action="store_true",   help="Run Nuclei vulnerability scan after fingerprinting")
    parser.add_argument("--simple",        action="store_true",   help="Use simple/classic HTML report (modern report is default)")
    parser.add_argument("--debug",         action="store_true",   help="Enable debug output with verbose logging")
    parser.add_argument("-v", "--verbose", action="store_true",   help="Verbose output")
    parser.add_argument("-U", "--update",  action="store_true",   help="Run the Self-Healing Update Engine")

    return parser


async def run_scan(args, targets):
    engine = ScanEngine(
        targets=targets,
        threads=args.threads,
        timeout=args.timeout,
        output_dir=args.output,
        full_scan=args.full,
        generate_graph=args.graph,
        screenshots=not args.no_screenshots,
        passive_only=args.passive_only,
        nuclei=args.nuclei,
        verbose=args.verbose,
        simple_report=args.simple,
        debug=args.debug,
        delay=args.delay,
    )
    await engine.run()
    
    # Auto-open reports after successful scan
    for target in targets:
        domain = target.replace("https://", "").replace("http://", "").strip("/")
        output_dir = Path(args.output) / domain

        # Clear any stuck headless browser processes before report opens
        # (prevents 'already running' / 'profile locked' errors in subsequent runs)
        try:
            os.system('pkill -f chrome || pkill -f chromium || true')
        except Exception:
            pass

        # Open HTML report
        if args.simple:
            report_path = output_dir / "report.html"
        else:
            report_path = output_dir / "report_modern.html"

        if report_path.exists():
            display = Display()
            report_abs_path = os.path.abspath(report_path)
            display.info(f"Opening report: {report_abs_path}")
            webbrowser.open("file://" + report_abs_path)
            print(f"[+] Technical Audit Complete. Lead Auditor: Daniyal Shahid (CEH v13)")
            print(f"[+] Report: {report_abs_path}")
        
        # Open interactive graph if generated
        if args.graph:
            graph_path = output_dir / "graphs" / f"{domain}_graph.html"
            if graph_path.exists():
                display = Display()
                display.info(f"Opening graph: {graph_path}")
                webbrowser.open(f"file://{graph_path.absolute()}")


def main():
    print_banner()

    parser = build_parser()
    args = parser.parse_args()

    display = Display()

    # ── Update command ─────────────────────────────────────────────
    if args.update:
        from core.updater import UpdateEngine
        updater = UpdateEngine()
        updater.run()
        return

    # ── Setup command ──────────────────────────────────────────────
    if args.command == "setup":
        checker = SetupChecker()
        checker.run()
        return

    # ── Report command ─────────────────────────────────────────────
    if args.command == "report":
        reporter = Reporter(args.domain)
        reporter.generate()
        return

    # ── Monitor command ────────────────────────────────────────────
    if args.command == "monitor":
        from core.monitor import Monitor
        monitor = Monitor(args.domain, interval=args.interval)
        asyncio.run(monitor.run())
        return

    # ── Scan command ───────────────────────────────────────────────
    handler = InputHandler()

    if not sys.stdin.isatty():
        targets = handler.from_stdin()
    elif args.domain:
        targets = handler.from_domain(args.domain)
    elif args.list:
        targets = handler.from_file(args.list)
    else:
        targets = handler.interactive()

    if not targets:
        display.error("No valid targets found. Exiting.")
        sys.exit(1)

    display.info(f"Loaded {len(targets)} target(s)")

    # Dependency check (non-blocking)
    checker = SetupChecker(silent=True)
    if not checker.quick_check():
        display.warning("Some dependencies missing. Run 'reco-nova setup' to install them.")

    # ── Global crash protection ────────────────────────────────────
    # The scan engine itself wraps each phase in try/except so it will
    # always reach the report even if individual phases fail.
    # This outer layer catches truly unexpected top-level failures.
    try:
        asyncio.run(run_scan(args, targets))
    except KeyboardInterrupt:
        display.warning("\nScan interrupted by user. Partial results may have been saved.")
        sys.exit(0)
    except Exception as e:
        # Log to error.log for debugging
        import traceback
        from datetime import datetime
        
        error_log_file = Path("error.log")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        error_details = f"""
═══════════════════════════════════════════════════════════════════════════
RECO-NOVA CRASH REPORT - {timestamp}
Target(s): {', '.join(targets[:3])}{'...' if len(targets) > 3 else ''}
Error: {str(e)}
Type: {type(e).__name__}
═══════════════════════════════════════════════════════════════════════════
{traceback.format_exc()}
═══════════════════════════════════════════════════════════════════════════
"""
        
        try:
            error_log_file.write_text(error_details, encoding='utf-8')
        except Exception:
            pass  # If we can't even write the error log, continue
        
        logger.exception("Unexpected top-level error during scan")
        display.error(
            f"[bold red]Scan Terminated Unexpectedly[/bold red]\n"
            f"Error: {str(e)}\n"
            f"A crash report has been saved to [bold]error.log[/bold]\n"
            f"The scan engine attempted to save partial results. "
            f"Check the output/ directory and logs/ for details."
        )
        sys.exit(1)


if __name__ == "__main__":
    main()