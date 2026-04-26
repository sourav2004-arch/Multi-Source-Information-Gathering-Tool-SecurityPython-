"""
whois_lookup.py — WHOIS Domain Registration Lookup Module.

Retrieves domain registration details (registrar, creation/expiry dates,
name servers, status) using the python-whois library.
"""

from datetime import datetime

try:
    import whois

    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

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

logger = setup_logger("osint.whois_lookup")


class WhoisLookup:
    """
    Fetch WHOIS registration data for a given domain.
    """

    def __init__(self, domain: str) -> None:
        self.domain = domain.strip().lower()

    # ──────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────

    def lookup(self) -> dict | None:
        """
        Query the WHOIS database and display results.

        Returns:
            dict with WHOIS fields, or None on failure.
        """
        print_section_header("WHOIS Lookup")

        if not WHOIS_AVAILABLE:
            print_error("python-whois is not installed. Run: pip install python-whois")
            logger.error("python-whois library not available")
            return None

        if not validate_domain(self.domain):
            print_error(f"'{self.domain}' is not a valid domain name.")
            logger.error("Invalid domain for WHOIS: %s", self.domain)
            return None

        print_info(f"Querying WHOIS data for {self.domain} ...")
        logger.info("WHOIS lookup for %s", self.domain)

        try:
            w = whois.whois(self.domain)

            if w.domain_name is None:
                print_warning("No WHOIS data found for this domain.")
                logger.warning("Empty WHOIS response for %s", self.domain)
                return None

            parsed = self._parse(w)
            self._display(parsed)
            print_success("WHOIS lookup complete.")
            logger.info("WHOIS lookup finished for %s", self.domain)
            return parsed

        except whois.parser.PywhoisError as exc:
            print_error(f"WHOIS query failed: {exc}")
            logger.error("PywhoisError for %s: %s", self.domain, exc)
        except ConnectionResetError:
            print_error("Connection reset by the WHOIS server.")
            logger.error("Connection reset during WHOIS for %s", self.domain)
        except Exception as exc:
            print_error(f"Unexpected error: {exc}")
            logger.exception("Unexpected WHOIS error for %s", self.domain)

        return None

    # ──────────────────────────────────────────────
    # Private Helpers
    # ──────────────────────────────────────────────

    @staticmethod
    def _normalize(value) -> str:
        """Return a clean string representation of a WHOIS field."""
        if value is None:
            return "N/A"
        if isinstance(value, list):
            # Some fields come as lists; take the first entry
            return str(value[0]) if value else "N/A"
        if isinstance(value, datetime):
            return value.strftime("%Y-%m-%d %H:%M:%S UTC")
        return str(value)

    def _parse(self, w) -> dict:
        """Extract key fields from the whois response object."""
        # Name servers may be a list or a single string
        name_servers = w.name_servers
        if isinstance(name_servers, list):
            ns_display = ", ".join(sorted({ns.lower() for ns in name_servers}))
        elif name_servers:
            ns_display = str(name_servers).lower()
        else:
            ns_display = "N/A"

        # Status may be a list
        status = w.status
        if isinstance(status, list):
            status_display = ", ".join(status[:3])
            if len(status) > 3:
                status_display += f" (+{len(status) - 3} more)"
        elif status:
            status_display = str(status)
        else:
            status_display = "N/A"

        return {
            "domain_name": self._normalize(w.domain_name),
            "registrar": self._normalize(w.registrar),
            "creation_date": self._normalize(w.creation_date),
            "expiration_date": self._normalize(w.expiration_date),
            "updated_date": self._normalize(w.updated_date),
            "name_servers": ns_display,
            "status": status_display,
            "registrant_country": self._normalize(getattr(w, "country", None)),
            "emails": self._normalize(getattr(w, "emails", None)),
        }

    @staticmethod
    def _display(parsed: dict) -> None:
        """Pretty-print WHOIS results."""
        print_result("Domain Name", parsed["domain_name"])
        print_result("Registrar", parsed["registrar"])
        print_result("Created", parsed["creation_date"])
        print_result("Expires", parsed["expiration_date"])
        print_result("Updated", parsed["updated_date"])
        print_result("Name Servers", parsed["name_servers"])
        print_result("Status", parsed["status"])
        print_result("Country", parsed["registrant_country"])
        print_result("Contact Email", parsed["emails"])
