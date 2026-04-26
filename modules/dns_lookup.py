"""
dns_lookup.py — DNS Lookup Module.

Resolves A, MX, NS, AAAA, TXT, and CNAME records for a given domain
using the dnspython library with socket fallback.
"""

import socket

try:
    import dns.resolver

    DNS_PYTHON_AVAILABLE = True
except ImportError:
    DNS_PYTHON_AVAILABLE = False

from utils.helpers import (
    print_section_header,
    print_result,
    print_error,
    print_warning,
    print_info,
    print_success,
    setup_logger,
    validate_domain,
)

logger = setup_logger("osint.dns_lookup")

# Record types to query when using dnspython
RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


class DNSLookup:
    """
    Resolve DNS records for a domain.

    Uses ``dnspython`` when available; falls back to ``socket.getaddrinfo``
    for basic A-record resolution.
    """

    def __init__(self, domain: str) -> None:
        self.domain = domain.strip().lower()

    # ──────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────

    def lookup(self) -> dict:
        """
        Perform the DNS lookup for all supported record types.

        Returns:
            dict mapping record type → list of values.
        """
        print_section_header("DNS Lookup")

        if not validate_domain(self.domain):
            print_error(f"'{self.domain}' is not a valid domain name.")
            logger.error("Invalid domain: %s", self.domain)
            return {}

        print_info(f"Resolving DNS records for {self.domain} ...")
        logger.info("Starting DNS lookup for %s", self.domain)

        if DNS_PYTHON_AVAILABLE:
            results = self._lookup_dnspython()
        else:
            print_warning("dnspython not installed — using socket fallback (A records only).")
            results = self._lookup_socket_fallback()

        if not any(results.values()):
            print_warning("No DNS records found.")
        else:
            print_success("DNS lookup complete.")

        logger.info("DNS lookup finished for %s", self.domain)
        return results

    # ──────────────────────────────────────────────
    # Private Helpers
    # ──────────────────────────────────────────────

    def _lookup_dnspython(self) -> dict:
        """Query multiple record types using dnspython."""
        results: dict[str, list[str]] = {}

        for rtype in RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(self.domain, rtype)
                records = [str(rdata) for rdata in answers]
                results[rtype] = records

                for record in records:
                    print_result(f"{rtype} Record", record)
                logger.debug("%s records for %s: %s", rtype, self.domain, records)

            except dns.resolver.NoAnswer:
                results[rtype] = []
            except dns.resolver.NXDOMAIN:
                print_error(f"Domain '{self.domain}' does not exist (NXDOMAIN).")
                logger.warning("NXDOMAIN for %s", self.domain)
                return {rtype: [] for rtype in RECORD_TYPES}
            except dns.resolver.Timeout:
                print_warning(f"Timeout querying {rtype} records.")
                results[rtype] = []
                logger.warning("Timeout for %s/%s", self.domain, rtype)
            except Exception as exc:
                results[rtype] = []
                logger.debug("Error resolving %s/%s: %s", self.domain, rtype, exc)

        return results

    def _lookup_socket_fallback(self) -> dict:
        """Basic A-record resolution via socket."""
        results: dict[str, list[str]] = {"A": []}
        try:
            addr_info = socket.getaddrinfo(self.domain, None, socket.AF_INET)
            ips = sorted({info[4][0] for info in addr_info})
            results["A"] = ips
            for ip in ips:
                print_result("A Record", ip)
        except socket.gaierror as exc:
            print_error(f"Resolution failed: {exc}")
            logger.error("Socket fallback failed for %s: %s", self.domain, exc)

        return results
