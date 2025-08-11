import os
import sys

# Verbose logging with optional ANSI colors
VERBOSE = os.environ.get("VERBOSE", "1") != "0"
RESET = "\033[0m"; BOLD = "\033[1m"; GREY = "\033[90m"; RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"; BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"
COLOR_ENABLED = (os.environ.get("NO_COLOR", "") == "" and (sys.stdout.isatty() or os.environ.get("FORCE_COLOR") == "1" or os.environ.get("CLICOLOR_FORCE") == "1"))

def vprint(msg: str, color: str = "") -> None:
    """Prints a message to stdout if VERBOSE is enabled."""
    if not VERBOSE:
        return
    prefix = color if (COLOR_ENABLED and color) else ""
    suffix = RESET if (COLOR_ENABLED and color) else ""
    print(f"{prefix}{msg}{suffix}" if prefix else msg)
    try:
        sys.stdout.flush()
    except Exception:
        pass
