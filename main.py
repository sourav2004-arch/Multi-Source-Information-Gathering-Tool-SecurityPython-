"""
main.py — Entry point for the Multi-Source Information Gathering Tool.

Provides an interactive CLI menu that lets the user select reconnaissance
operations against a target domain or IP address.

Usage:
    python main.py
"""

import sys
import time

from colorama import Fore, Style, init as colorama_init

# Initialize colorama early for Windows ANSI support
colorama_init(autoreset=True)

from utils.helpers import (
    print_banner,
    print_section_header,
    print_error,
    print_info,
    print_success,
    print_warning,
    setup_logger,
    validate_domain,
    validate_ip,
    format_elapsed_time,
)
from modules.ip_lookup import IPLookup
from modules.dns_lookup import DNSLookup
from modules.port_scanner import PortScanner
from modules.ssl_checker import SSLChecker
from modules.whois_lookup import WhoisLookup

# ─────────────────────────────────────────────────────────────
# Logger
# ─────────────────────────────────────────────────────────────
logger = setup_logger()


# ─────────────────────────────────────────────────────────────
# Menu Definitions
# ─────────────────────────────────────────────────────────────
MENU_OPTIONS = {
    "1": ("IP Intelligence Lookup", "ip"),
    "2": ("DNS Record Lookup", "dns"),
    "3": ("Port Scanner", "port"),
    "4": ("SSL Certificate Analysis", "ssl"),
    "5": ("WHOIS Domain Lookup", "whois"),
    "6": ("Run ALL Scans", "all"),
    "0": ("Exit", "exit"),
}


def display_menu() -> None:
    """Print the interactive operation menu."""
    print(f"\n{Fore.CYAN}{'─' * 50}")
    print(f"  {Style.BRIGHT}Select an Operation:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─' * 50}{Style.RESET_ALL}")

    for key, (label, _) in MENU_OPTIONS.items():
        if key == "0":
            color = Fore.RED
        elif key == "6":
            color = Fore.MAGENTA
        else:
            color = Fore.GREEN

        print(f"  {color}[{key}]{Style.RESET_ALL}  {label}")

    print(f"{Fore.CYAN}{'─' * 50}{Style.RESET_ALL}")


def get_target() -> str:
    """Prompt the user for a target domain or IP address."""
    while True:
        target = input(f"\n  {Fore.YELLOW}Enter target (domain or IP): {Style.RESET_ALL}").strip()

        if not target:
            print_error("Target cannot be empty.")
            continue

        # Basic validation
        if validate_domain(target) or validate_ip(target):
            return target

        # Could be a valid hostname not matching strict domain regex — allow it
        print_warning(f"'{target}' may not be a standard domain/IP. Proceeding anyway.")
        return target


# ─────────────────────────────────────────────────────────────
# Operation Runners
# ─────────────────────────────────────────────────────────────

def run_ip_lookup(target: str) -> None:
    """Execute the IP Intelligence module."""
    IPLookup(target).lookup()


def run_dns_lookup(target: str) -> None:
    """Execute the DNS Lookup module."""
    DNSLookup(target).lookup()


def run_port_scan(target: str) -> None:
    """Execute the Port Scanner module."""
    PortScanner(target).scan()


def run_ssl_check(target: str) -> None:
    """Execute the SSL Certificate Analysis module."""
    SSLChecker(target).check()


def run_whois_lookup(target: str) -> None:
    """Execute the WHOIS Lookup module."""
    WhoisLookup(target).lookup()


def run_all(target: str) -> None:
    """Run every reconnaissance module sequentially."""
    print_info("Running ALL reconnaissance modules ...\n")
    run_ip_lookup(target)
    run_dns_lookup(target)
    run_port_scan(target)
    run_ssl_check(target)
    run_whois_lookup(target)


# Map menu keys to runner functions
OPERATION_MAP = {
    "ip": run_ip_lookup,
    "dns": run_dns_lookup,
    "port": run_port_scan,
    "ssl": run_ssl_check,
    "whois": run_whois_lookup,
    "all": run_all,
}


# ─────────────────────────────────────────────────────────────
# Main Loop
# ─────────────────────────────────────────────────────────────

def main() -> None:
    """Launch the interactive CLI loop."""
    print_banner()
    print_info("Type '0' at any prompt to exit.\n")

    target = get_target()
    logger.info("Session started — target: %s", target)

    while True:
        display_menu()

        choice = input(f"\n  {Fore.YELLOW}Your choice ▶ {Style.RESET_ALL}").strip()

        if choice not in MENU_OPTIONS:
            print_error("Invalid option. Please try again.")
            continue

        label, op_key = MENU_OPTIONS[choice]

        if op_key == "exit":
            print(f"\n  {Fore.CYAN}Thanks for using the OSINT Recon Tool. Stay safe! 🔐{Style.RESET_ALL}\n")
            logger.info("Session ended by user")
            sys.exit(0)

        # Execute the selected operation with timing
        print_info(f"Starting: {label}")
        logger.info("Operation: %s | Target: %s", label, target)

        start = time.perf_counter()

        try:
            OPERATION_MAP[op_key](target)
        except KeyboardInterrupt:
            print_warning("\nOperation cancelled by user.")
            logger.warning("Operation interrupted: %s", label)
        except Exception as exc:
            print_error(f"Unhandled error: {exc}")
            logger.exception("Unhandled exception in %s", label)

        elapsed = time.perf_counter() - start
        print(f"\n  {Fore.BLUE}⏱  Completed in {format_elapsed_time(elapsed)}{Style.RESET_ALL}")
        logger.info("Operation '%s' finished in %s", label, format_elapsed_time(elapsed))

        # Ask whether to change target or continue
        change = input(f"\n  {Fore.YELLOW}Change target? (y/N): {Style.RESET_ALL}").strip().lower()
        if change in ("y", "yes"):
            target = get_target()
            logger.info("Target changed to: %s", target)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {Fore.RED}Interrupted. Exiting ...{Style.RESET_ALL}\n")
        sys.exit(130)
