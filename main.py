"""USB Security Monitor entry point.

Phase 1 provides project initialization and logging only.
Monitoring, analysis, storage, and CLI commands are added in later phases.
"""

from __future__ import annotations

import argparse
import sys

from usb_monitor import __app_name__, __version__
from usb_monitor.utils.logger import get_logger, setup_logging


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments for the Phase 1 skeleton."""
    parser = argparse.ArgumentParser(
        prog="usb-security-monitor",
        description=(
            "Defensive endpoint-security tool that monitors USB and "
            "removable-storage activity on the local computer you are "
            "authorized to administer."
        ),
        epilog=(
            "This tool does not exploit devices, execute USB contents, "
            "or send data off the local machine."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{__app_name__} {__version__}",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging on the console.",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Show warnings and errors only on the console.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the Phase 1 application skeleton."""
    args = parse_args(argv)
    setup_logging(verbose=args.verbose, quiet=args.quiet)
    logger = get_logger("main")

    logger.info("%s %s started", __app_name__, __version__)
    logger.info("Phase 1: initialization only; no device monitoring yet")
    logger.debug("Verbose logging is enabled")

    print(f"{__app_name__} v{__version__}")
    print("Phase 1 complete: project initialized.")
    print("Later phases will add monitoring, inventory, analysis, and CLI commands.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        raise SystemExit(130)
