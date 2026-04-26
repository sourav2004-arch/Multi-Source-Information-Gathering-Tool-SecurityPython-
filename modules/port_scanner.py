"""
port_scanner.py — Multithreaded Port Scanner Module.

Implements concurrent TCP port scanning using Python's threading module,
significantly improving performance over sequential scanning.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.helpers import (
    print_section_header,
    print_result,
    print_error,
    print_info,
    print_success,
    print_warning,
    setup_logger,
    resolve_target,
)

from colorama import Fore, Style

logger = setup_logger("osint.port_scanner")

# Well-known ports with service names
DEFAULT_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Connection timeout per port (seconds)
SCAN_TIMEOUT = 1.5

# Maximum concurrent threads for scanning
MAX_WORKERS = 100


class PortScanner:
    """
    Concurrent TCP port scanner.

    Uses a ``ThreadPoolExecutor`` to probe multiple ports simultaneously,
    improving scan speed proportionally to the thread pool size.
    """

    def __init__(self, target: str, ports: list[int] | None = None, timeout: float = SCAN_TIMEOUT) -> None:
        """
        Args:
            target:  Domain name or IPv4 address.
            ports:   List of port numbers to scan. Defaults to ``DEFAULT_PORTS``.
            timeout: Socket timeout in seconds per port.
        """
        self.target = target
        self.ip = resolve_target(target)
        self.ports = ports or sorted(DEFAULT_PORTS.keys())
        self.timeout = timeout

    # ──────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────

    def scan(self) -> dict[int, bool]:
        """
        Scan all configured ports concurrently.

        Returns:
            dict mapping port number → True (open) / False (closed).
        """
        print_section_header("Port Scanner")

        if self.ip is None:
            print_error(f"Could not resolve target '{self.target}'.")
            logger.error("DNS resolution failed for %s", self.target)
            return {}

        total = len(self.ports)
        print_info(f"Scanning {total} ports on {self.ip} ({self.target}) ...")
        print_info(f"Concurrency: {min(MAX_WORKERS, total)} threads  |  Timeout: {self.timeout}s")
        logger.info("Port scan starting — target=%s  ports=%d  workers=%d", self.ip, total, MAX_WORKERS)

        results: dict[int, bool] = {}

        # ── Concurrent scanning using ThreadPoolExecutor ──
        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, total)) as executor:
            future_to_port = {
                executor.submit(self._probe_port, port): port
                for port in self.ports
            }

            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open = future.result()
                    results[port] = is_open
                except Exception as exc:
                    results[port] = False
                    logger.debug("Exception scanning port %d: %s", port, exc)

        self._display(results)
        open_count = sum(1 for v in results.values() if v)
        print_success(f"Scan complete — {open_count}/{total} ports open.")
        logger.info("Port scan finished: %d/%d open", open_count, total)

        return results

    # ──────────────────────────────────────────────
    # Private Helpers
    # ──────────────────────────────────────────────

    def _probe_port(self, port: int) -> bool:
        """
        Attempt a TCP connection to a single port.

        Args:
            port: Port number to probe.

        Returns:
            True if the port accepted the connection, False otherwise.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.ip, port))
                return result == 0
        except (socket.timeout, OSError):
            return False

    @staticmethod
    def _display(results: dict[int, bool]) -> None:
        """Print a formatted table of scan results."""
        print(f"\n  {'PORT':<8} {'SERVICE':<14} {'STATUS'}")
        print(f"  {'─' * 8} {'─' * 14} {'─' * 10}")

        for port in sorted(results.keys()):
            service = DEFAULT_PORTS.get(port, "Unknown")
            is_open = results[port]

            if is_open:
                status = f"{Fore.GREEN}OPEN{Style.RESET_ALL}"
            else:
                status = f"{Fore.RED}CLOSED{Style.RESET_ALL}"

            print(f"  {port:<8} {service:<14} {status}")
