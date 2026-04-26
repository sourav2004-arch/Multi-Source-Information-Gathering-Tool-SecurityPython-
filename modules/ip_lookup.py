"""
ip_lookup.py — IP Intelligence Module.

Fetches public IP geolocation data, ISP details, and network info
using the ip-api.com free JSON API.
"""

import requests

from utils.helpers import (
    print_section_header,
    print_result,
    print_error,
    print_info,
    setup_logger,
    validate_ip,
    resolve_target,
)

logger = setup_logger("osint.ip_lookup")

# Free, key-less API with generous rate limits (45 req/min)
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query"


class IPLookup:
    """
    Retrieve geolocation and network intelligence for an IP address
    or domain using the ip-api.com service.
    """

    def __init__(self, target: str) -> None:
        """
        Args:
            target: Domain name or IPv4 address to look up.
        """
        self.target = target
        self.ip = resolve_target(target)

    # ──────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────

    def lookup(self) -> dict | None:
        """
        Perform the IP geolocation lookup.

        Returns:
            dict with geolocation fields on success, None on failure.
        """
        print_section_header("IP Intelligence")

        if self.ip is None:
            print_error(f"Could not resolve target '{self.target}'.")
            logger.error("DNS resolution failed for %s", self.target)
            return None

        print_info(f"Querying geolocation data for {self.ip} ...")
        logger.info("Starting IP lookup for %s (resolved: %s)", self.target, self.ip)

        try:
            response = requests.get(
                IP_API_URL.format(ip=self.ip),
                timeout=10,
            )
            response.raise_for_status()
            data: dict = response.json()

            if data.get("status") == "fail":
                msg = data.get("message", "Unknown API error")
                print_error(f"API returned failure: {msg}")
                logger.warning("ip-api failure: %s", msg)
                return None

            self._display(data)
            logger.info("IP lookup completed for %s", self.ip)
            return data

        except requests.ConnectionError:
            print_error("Network unreachable — check your internet connection.")
            logger.error("Connection error during IP lookup")
        except requests.Timeout:
            print_error("Request timed out.")
            logger.error("Timeout during IP lookup for %s", self.ip)
        except requests.RequestException as exc:
            print_error(f"HTTP error: {exc}")
            logger.exception("Unexpected request error")

        return None

    # ──────────────────────────────────────────────
    # Private Helpers
    # ──────────────────────────────────────────────

    @staticmethod
    def _display(data: dict) -> None:
        """Pretty-print the geolocation results."""
        print_result("IP Address", data.get("query", "N/A"))
        print_result("Country", data.get("country", "N/A"))
        print_result("Region", data.get("regionName", "N/A"))
        print_result("City", data.get("city", "N/A"))
        print_result("ZIP Code", data.get("zip", "N/A"))
        print_result("Latitude", str(data.get("lat", "N/A")))
        print_result("Longitude", str(data.get("lon", "N/A")))
        print_result("Timezone", data.get("timezone", "N/A"))
        print_result("ISP", data.get("isp", "N/A"))
        print_result("Organization", data.get("org", "N/A"))
        print_result("AS Number", data.get("as", "N/A"))
