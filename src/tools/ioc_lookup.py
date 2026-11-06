import os

import requests
from dotenv import load_dotenv

from src.models.schemas import Confidence, IOCResult, Severity


load_dotenv()


class IOCLookup:
    """AlienVault OTX IOC lookup tool."""

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key=None, timeout=None):
        self.api_key = api_key or os.getenv("OTX_API_KEY")
        self.timeout =  timeout or int(os.getenv("OTX_TIMEOUT", "30"))

        if not self.api_key:
            raise ValueError(
                "OTX_API_KEY is not configured."
            )

    def _headers(self):
        return {
            "X-OTX-API-KEY": self.api_key,
            "Accept": "application/json",
        }

    def _detect_ioc_type(self, ioc):
        """Determine the OTX indicator type."""

        if ":" in ioc:
            return "IPv6"

        parts = ioc.split(".")

        if len(parts) == 4 and all(
            part.isdigit() and 0 <= int(part) <= 255
            for part in parts
        ):
            return "IPv4"

        if "@" in ioc:
            return "email"

        if "/" in ioc:
            return "URI"

        return "domain"

    def lookup(self, ioc):
        """Look up an IOC using AlienVault OTX."""

        ioc = ioc.strip()

        if not ioc:
            raise ValueError("IOC cannot be empty.")

        ioc_type = self._detect_ioc_type(ioc)

        url = (
            f"{self.BASE_URL}/indicators/"
            f"{ioc_type}/{ioc}/general"
        )

        try:
            response = requests.get(
                url,
                headers=self._headers(),
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise RuntimeError(
                f"OTX API request failed: {exc}"
            ) from exc

        if response.status_code == 404:
            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                reputation="Unknown",
                risk=Severity.LOW,
                confidence=Confidence.LOW,
                sources=["AlienVault OTX"],
            )

        if response.status_code == 401:
            raise RuntimeError(
                "OTX API authentication failed. "
                "Check OTX_API_KEY."
            )

        if response.status_code == 429:
            raise RuntimeError(
                "OTX API rate limit exceeded."
            )

        if not response.ok:
            raise RuntimeError(
                f"OTX API returned HTTP {response.status_code}."
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise RuntimeError(
                "OTX API returned invalid JSON."
            ) from exc

        return self._normalize_response(
            ioc=ioc,
            ioc_type=ioc_type,
            data=data,
        )

    def _normalize_response(self, ioc, ioc_type, data):
        """Convert OTX data into our standard IOCResult."""

        pulse_count = data.get("pulse_info", {}).get(
            "count",
            0,
        )

        if pulse_count >= 5:
            risk = Severity.CRITICAL
            reputation = "Malicious"
            confidence = Confidence.VERY_HIGH

        elif pulse_count >= 2:
            risk = Severity.HIGH
            reputation = "Suspicious"
            confidence = Confidence.HIGH

        elif pulse_count == 1:
            risk = Severity.MEDIUM
            reputation = "Suspicious"
            confidence = Confidence.MEDIUM

        else:
            risk = Severity.LOW
            reputation = "No known malicious pulses"
            confidence = Confidence.MEDIUM

        return IOCResult(
            ioc=ioc,
            ioc_type=ioc_type,
            reputation=reputation,
            risk=risk,
            confidence=confidence,
            sources=["AlienVault OTX"],
        )