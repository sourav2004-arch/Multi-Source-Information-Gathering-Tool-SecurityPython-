"""
helpers.py — Utility functions for the OSINT Tool.

Provides input validation, colored terminal output, logging setup,
and shared formatting helpers used across all modules.
"""

import re
import socket
import logging
from datetime import datetime

from colorama import Fore, Style, init as colorama_init

# Initialize colorama for cross-platform colored output
colorama_init(autoreset=True)

# ─────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────
TOOL_NAME = "OSINT Recon Tool"
VERSION = "1.0.0"
AUTHOR = "Security Researcher"

# Regex patterns for validation
DOMAIN_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
)
IP_V4_PATTERN = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# ─────────────────────────────────────────────────────────────
# Input Validation
# ─────────────────────────────────────────────────────────────

def validate_domain(domain: str) -> bool:
    """
    Validate a domain name against RFC-compliant regex.

    Args:
        domain: Domain string to validate (e.g. 'example.com').

    Returns:
        True if domain is syntactically valid, False otherwise.
    """
    if not domain or len(domain) > 253:
        return False
    return bool(DOMAIN_PATTERN.match(domain))


def validate_ip(ip: str) -> bool:
    """
    Validate an IPv4 address.

    Args:
        ip: IP address string to validate.

    Returns:
        True if ip is a valid IPv4 address, False otherwise.
    """
    return bool(IP_V4_PATTERN.match(ip))


def resolve_target(target: str) -> str | None:
    """
    Resolve a domain name to its IPv4 address.

    If the target is already an IP address, return it directly.
    Otherwise attempt DNS resolution.

    Args:
        target: Domain name or IP address.

    Returns:
        Resolved IPv4 address string, or None on failure.
    """
    if validate_ip(target):
        return target
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


# ─────────────────────────────────────────────────────────────
# Colored CLI Output Helpers
# ─────────────────────────────────────────────────────────────

def print_banner() -> None:
    """Display the tool's ASCII banner with version info."""
    banner = rf"""
{Fore.CYAN}{Style.BRIGHT}
  ╔══════════════════════════════════════════════════════════════╗
  ║                                                              ║
  ║    ██████╗ ███████╗██╗███╗   ██╗████████╗                    ║
  ║   ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝                   ║
  ║   ██║   ██║███████╗██║██╔██╗ ██║   ██║                      ║
  ║   ██║   ██║╚════██║██║██║╚██╗██║   ██║                      ║
  ║   ╚██████╔╝███████║██║██║ ╚████║   ██║                      ║
  ║    ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝  ╚═╝                     ║
  ║                                                              ║
  ║   {Fore.YELLOW}Multi-Source Information Gathering Tool{Fore.CYAN}                   ║
  ║   {Fore.WHITE}Version : {VERSION}  |  Author : {AUTHOR}{Fore.CYAN}          ║
  ║                                                              ║
  ╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
    print(banner)


def print_section_header(title: str) -> None:
    """Print a visually distinct section header."""
    width = 60
    print(f"\n{Fore.CYAN}{'═' * width}")
    print(f"  ▶  {Style.BRIGHT}{title.upper()}")
    print(f"{'═' * width}{Style.RESET_ALL}")


def print_result(label: str, value: str) -> None:
    """Print a key-value result row."""
    print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {Fore.WHITE}{label:<22}{Style.RESET_ALL}: {Fore.YELLOW}{value}")


def print_error(message: str) -> None:
    """Print a red error message."""
    print(f"  {Fore.RED}[✗] ERROR: {message}{Style.RESET_ALL}")


def print_warning(message: str) -> None:
    """Print a yellow warning message."""
    print(f"  {Fore.YELLOW}[!] WARNING: {message}{Style.RESET_ALL}")


def print_success(message: str) -> None:
    """Print a green success message."""
    print(f"  {Fore.GREEN}[✓] {message}{Style.RESET_ALL}")


def print_info(message: str) -> None:
    """Print a blue informational message."""
    print(f"  {Fore.BLUE}[i] {message}{Style.RESET_ALL}")


# ─────────────────────────────────────────────────────────────
# Logging Setup
# ─────────────────────────────────────────────────────────────

def setup_logger(name: str = "osint_tool", log_file: str = "osint_tool.log") -> logging.Logger:
    """
    Configure and return a logger that writes to both file and console.

    Args:
        name: Logger name.
        log_file: Path to the log file.

    Returns:
        Configured logging.Logger instance.
    """
    logger = logging.getLogger(name)

    # Avoid adding duplicate handlers if called multiple times
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # File handler — captures all log levels
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_fmt)

    # Console handler — only warnings and above
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_fmt = logging.Formatter("%(levelname)s: %(message)s")
    console_handler.setFormatter(console_fmt)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


# ─────────────────────────────────────────────────────────────
# Time Formatting
# ─────────────────────────────────────────────────────────────

def format_elapsed_time(seconds: float) -> str:
    """
    Convert elapsed seconds into a human-readable string.

    Args:
        seconds: Elapsed time in seconds.

    Returns:
        Formatted string like '2.34s' or '1m 12.50s'.
    """
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes = int(seconds // 60)
    remaining = seconds % 60
    return f"{minutes}m {remaining:.2f}s"
