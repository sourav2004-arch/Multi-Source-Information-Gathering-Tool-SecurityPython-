"""
ssl_checker.py — SSL/TLS Certificate Analysis Module.

Connects to a host over TLS and extracts the X.509 certificate details
including issuer, subject, validity period, serial number, and SANs.
"""

import ssl
import socket
from datetime import datetime, timezone

from utils.helpers import (
    print_section_header,
    print_result,
    print_error,
    print_info,
    print_success,
    print_warning,
    setup_logger,
    validate_domain,
)

logger = setup_logger("osint.ssl_checker")

# Default HTTPS port
SSL_PORT = 443
CONNECT_TIMEOUT = 10


class SSLChecker:
    """
    Retrieve and analyse the SSL/TLS certificate of a remote host.
    """

    def __init__(self, domain: str, port: int = SSL_PORT) -> None:
        """
        Args:
            domain: Hostname to connect to.
            port:   Port number (default 443).
        """
        self.domain = domain.strip().lower()
        self.port = port

    # ──────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────

    def check(self) -> dict | None:
        """
        Fetch and display the SSL certificate.

        Returns:
            dict with parsed certificate fields, or None on error.
        """
        print_section_header("SSL Certificate Analysis")

        if not validate_domain(self.domain):
            print_error(f"'{self.domain}' is not a valid domain name.")
            logger.error("Invalid domain for SSL check: %s", self.domain)
            return None

        print_info(f"Connecting to {self.domain}:{self.port} over TLS ...")
        logger.info("SSL check for %s:%d", self.domain, self.port)

        try:
            cert = self._fetch_certificate()
            if cert is None:
                return None

            parsed = self._parse_certificate(cert)
            self._display(parsed)
            logger.info("SSL check complete for %s", self.domain)
            return parsed

        except ssl.SSLCertVerificationError as exc:
            print_warning(f"Certificate verification failed: {exc}")
            logger.warning("SSL verification error: %s", exc)
        except ssl.SSLError as exc:
            print_error(f"SSL error: {exc}")
            logger.error("SSL error for %s: %s", self.domain, exc)
        except ConnectionRefusedError:
            print_error(f"Connection refused on {self.domain}:{self.port}.")
            logger.error("Connection refused: %s:%d", self.domain, self.port)
        except socket.timeout:
            print_error("Connection timed out.")
            logger.error("Timeout connecting to %s:%d", self.domain, self.port)
        except OSError as exc:
            print_error(f"Network error: {exc}")
            logger.error("OS error during SSL check: %s", exc)

        return None

    # ──────────────────────────────────────────────
    # Private Helpers
    # ──────────────────────────────────────────────

    def _fetch_certificate(self) -> dict | None:
        """
        Open a TLS connection and retrieve the peer certificate as a dict.
        """
        context = ssl.create_default_context()

        with socket.create_connection((self.domain, self.port), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=self.domain) as tls_sock:
                cert = tls_sock.getpeercert()
                if not cert:
                    print_error("No certificate returned by the server.")
                    return None
                return cert

    def _parse_certificate(self, cert: dict) -> dict:
        """
        Extract human-readable fields from the raw certificate dict.
        """
        # Flatten RDN tuples from issuer / subject
        issuer = self._flatten_rdn(cert.get("issuer", ()))
        subject = self._flatten_rdn(cert.get("subject", ()))

        # Parse dates
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")
        expiry_dt = self._parse_cert_date(not_after)

        # Determine validity
        now = datetime.now(timezone.utc)
        if expiry_dt:
            days_remaining = (expiry_dt - now).days
            is_valid = days_remaining > 0
        else:
            days_remaining = None
            is_valid = None

        # Subject Alternative Names
        san_entries = [entry[1] for entry in cert.get("subjectAltName", ())]

        return {
            "subject": subject,
            "issuer": issuer,
            "serial_number": cert.get("serialNumber", "N/A"),
            "version": cert.get("version", "N/A"),
            "not_before": not_before,
            "not_after": not_after,
            "days_remaining": days_remaining,
            "is_valid": is_valid,
            "san": san_entries,
        }

    @staticmethod
    def _flatten_rdn(rdn_sequence: tuple) -> str:
        """Convert nested RDN tuples into a single comma-separated string."""
        parts = []
        for rdn in rdn_sequence:
            for attr_type, attr_value in rdn:
                parts.append(f"{attr_type}={attr_value}")
        return ", ".join(parts)

    @staticmethod
    def _parse_cert_date(date_str: str) -> datetime | None:
        """Parse the OpenSSL date format used in Python's ssl module."""
        # Typical format: 'Sep  8 00:00:00 2025 GMT'
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
            try:
                return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None

    @staticmethod
    def _display(parsed: dict) -> None:
        """Pretty-print the parsed certificate fields."""
        print_result("Subject", parsed["subject"])
        print_result("Issuer", parsed["issuer"])
        print_result("Serial Number", parsed["serial_number"])
        print_result("Valid From", parsed["not_before"])
        print_result("Valid Until", parsed["not_after"])

        if parsed["is_valid"] is True:
            print_success(f"Certificate is VALID  ({parsed['days_remaining']} days remaining)")
        elif parsed["is_valid"] is False:
            print_error(f"Certificate is EXPIRED  ({abs(parsed['days_remaining'])} days ago)")
        else:
            print_warning("Could not determine certificate validity.")

        if parsed["san"]:
            print_result("SANs", ", ".join(parsed["san"][:5]))
            if len(parsed["san"]) > 5:
                print_info(f"... and {len(parsed['san']) - 5} more SAN entries")
