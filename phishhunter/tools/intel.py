"""Deterministic offline threat-intelligence provider.

Every lookup is served from a local JSON fixture (``data/mock_intel.json`` by
default).  The provider is deliberately boring:

* it never performs network I/O, never sleeps and never prints;
* an IOC that is not in the fixture returns ``{"found": False}``;
* values are copied and defaulted, so callers cannot mutate the fixture.

Normalization rules (shared with the tool layer):

* domains are lower-cased and lose a trailing dot;
* URLs are unwrapped from markdown ``[text](url)``, trimmed, lower-cased and
  compared without a trailing slash;
* hashes accept an optional ``sha256:`` prefix and are lower-cased.
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Iterable

from ..config import DEFAULT_INTEL_PATH
from ..models import clean_url, split_markdown_link

_SHA_PREFIX_RE = re.compile(r"^sha256\s*:\s*", re.IGNORECASE)
_WRAPPING_CHARS = " \t\r\n<>[]()'\"“”‘’"


# --------------------------------------------------------------------------- #
# normalization helpers (also used by tools)
# --------------------------------------------------------------------------- #


def url_host(value: str) -> str:
    """Return the lower-case host of a URL or bare domain, or ``""``."""
    from urllib.parse import urlparse

    text = clean_url(str(value or ""))
    if not text:
        return ""
    if "://" not in text:
        text = "http://" + text
    try:
        host = urlparse(text).hostname or ""
    except ValueError:
        return ""
    return host.strip().lower().rstrip(".")


def normalize_domain(value: Any) -> str:
    """Normalize a domain (tolerating URLs, userinfo and ports)."""
    text = str(value or "").strip().lower()
    text = text.strip(_WRAPPING_CHARS)
    if not text:
        return ""
    if "://" in text:
        text = url_host(text)
    text = text.split("/", 1)[0].split("\\", 1)[0]
    if "@" in text:
        text = text.rsplit("@", 1)[-1]
    # Strip a numeric port from a plain host (never touch IPv6 literals).
    if text.count(":") == 1:
        host, port = text.rsplit(":", 1)
        if port.isdigit():
            text = host
    return text.strip(_WRAPPING_CHARS).rstrip(".")


def normalize_url(value: Any) -> str:
    """Normalize a URL for case-insensitive, trailing-slash-insensitive lookup."""
    text = str(value or "")
    if not text.strip():
        return ""
    unwrapped, _anchor = split_markdown_link(text)
    text = clean_url(unwrapped).strip(_WRAPPING_CHARS)
    if not text:
        return ""
    return text.rstrip("/").lower()


def normalize_hash(value: Any) -> str:
    """Normalize a SHA-256 value, accepting an optional ``sha256:`` prefix."""
    text = str(value or "").strip()
    text = _SHA_PREFIX_RE.sub("", text)
    return text.strip().lower()


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(str(host or "").strip().strip("[]"))
        return True
    except ValueError:
        return False


def require_text_param(params: dict[str, Any], key: str, tool_name: str) -> str:
    """Read a required, non-empty string parameter.

    Only malformed parameters raise; lookups that miss simply return
    ``found=False`` from the provider.
    """
    value = (params or {}).get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{tool_name}: parameter '{key}' is required")
    return value.strip()


# --------------------------------------------------------------------------- #
# provider
# --------------------------------------------------------------------------- #

_WHOIS_DEFAULTS: dict[str, Any] = {
    "found": True,
    "age_days": None,
    "created": "",
    "registrar": "",
    "privacy": None,
    "nameservers": [],
    "vt_malicious": None,
    "category": "",
    "brand": "",
}

_DNS_DEFAULTS: dict[str, Any] = {
    "found": True,
    "spf": "",
    "dkim": "",
    "dmarc": "",
    "spf_valid": None,
    "dmarc_policy": "",
}

_URL_DEFAULTS: dict[str, Any] = {
    "found": True,
    "resolved": "",
    "vt_malicious": None,
    "safebrowsing": "",
    "categories": [],
    "first_seen_days": None,
    "category": "",
}

_SANDBOX_DEFAULTS: dict[str, Any] = {
    "found": True,
    "final_url": "",
    "redirects": [],
    "has_password_form": False,
    "requests_credentials": False,
    "downloads": [],
    "verdict": "",
    "risk": None,
}

_FILE_DEFAULTS: dict[str, Any] = {
    "found": True,
    "verdict": "",
    "malware_family": "",
    "vt_malicious": None,
    "file_type": "",
    "names": [],
}


class MockIntelProvider:
    """Read-only fixture-backed lookups with tolerant parsing."""

    def __init__(self, data_path: str | Path | None = None) -> None:
        self.data_path = Path(data_path) if data_path is not None else DEFAULT_INTEL_PATH
        self._loaded = False
        self._data: dict[str, Any] = {}
        self._domains: dict[str, dict[str, Any]] = {}
        self._dns: dict[str, dict[str, Any]] = {}
        self._urls: dict[str, dict[str, Any]] = {}
        self._sandbox: dict[str, dict[str, Any]] = {}
        self._files: dict[str, dict[str, Any]] = {}
        self._load()

    # -- loading ----------------------------------------------------------- #

    def _load(self) -> None:
        try:
            raw = json.loads(self.data_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return
        if not isinstance(raw, dict):
            return
        self._data = raw
        self._loaded = True
        self._domains = self._build_index("domains", normalize_domain)
        self._dns = self._build_index("dns", normalize_domain)
        self._urls = self._build_index("urls", normalize_url)
        self._sandbox = self._build_index("sandbox", normalize_url)
        self._files = self._build_index("files", normalize_hash)

    def _build_index(self, section: str, normalizer: Any) -> dict[str, dict[str, Any]]:
        raw = self._data.get(section)
        if not isinstance(raw, dict):
            return {}
        index: dict[str, dict[str, Any]] = {}
        for key, value in raw.items():
            if not isinstance(value, dict):
                continue
            normalized = normalizer(key)
            if normalized:
                index[normalized] = value
        return index

    @property
    def loaded(self) -> bool:
        return self._loaded

    # -- lookup helpers ---------------------------------------------------- #

    @staticmethod
    def _present(index: dict[str, dict[str, Any]], key: str) -> dict[str, Any] | None:
        if not key:
            return None
        record = index.get(key)
        if record is None:
            return None
        if record.get("found") is False:
            return None
        return record

    @staticmethod
    def _merge(record: dict[str, Any], defaults: dict[str, Any]) -> dict[str, Any]:
        """Return a fresh dict with schema defaults plus the fixture fields."""
        data = dict(defaults)
        for key, value in record.items():
            if key == "found":
                continue
            data[key] = value
        data["found"] = True
        return data

    @staticmethod
    def _missing() -> dict[str, Any]:
        return {"found": False}

    # -- public API -------------------------------------------------------- #

    def whois(self, domain: str) -> dict[str, Any]:
        record = self._present(self._domains, normalize_domain(domain))
        if record is None:
            return self._missing()
        return self._merge(record, _WHOIS_DEFAULTS)

    def dns(self, domain: str) -> dict[str, Any]:
        record = self._present(self._dns, normalize_domain(domain))
        if record is None:
            return self._missing()
        return self._merge(record, _DNS_DEFAULTS)

    def url_reputation(self, url: str) -> dict[str, Any]:
        record = self._present(self._urls, normalize_url(url))
        if record is None:
            return self._missing()
        return self._merge(record, _URL_DEFAULTS)

    def sandbox(self, url: str) -> dict[str, Any]:
        record = self._present(self._sandbox, normalize_url(url))
        if record is None:
            return self._missing()
        return self._merge(record, _SANDBOX_DEFAULTS)

    def file_reputation(self, sha256: str) -> dict[str, Any]:
        record = self._present(self._files, normalize_hash(sha256))
        if record is None:
            return self._missing()
        return self._merge(record, _FILE_DEFAULTS)

    def similar_campaigns(
        self,
        text: str,
        domains: list[str] | None = None,
        limit: int = 3,
    ) -> list[dict[str, Any]]:
        """Rank historical campaigns by keyword and domain overlap.

        Similarity is deliberately explainable::

            similarity = min(1, 0.75 * keyword_hit_ratio + 0.35 * domain_hit)

        A campaign only relying on a domain match therefore scores 0.35, while
        a full keyword match alone scores 0.75.
        """
        campaigns = self._data.get("campaigns")
        if not isinstance(campaigns, list):
            return []
        try:
            bounded_limit = max(0, min(int(limit), 10))
        except (TypeError, ValueError):
            bounded_limit = 3
        if bounded_limit == 0:
            return []

        query = str(text or "").lower()[:20000]
        domain_set = {
            normalize_domain(item)
            for item in (domains or [])
            if normalize_domain(item)
        }

        matches: list[dict[str, Any]] = []
        for entry in campaigns:
            if not isinstance(entry, dict):
                continue
            keywords = self._string_list(entry.get("keywords"))
            hit_keywords = [kw for kw in keywords if kw.lower() in query]
            keyword_score = (
                len(hit_keywords) / len(keywords) if keywords else 0.0
            )
            campaign_domains = {
                normalize_domain(item)
                for item in self._string_list(entry.get("domains"))
                if normalize_domain(item)
            }
            domain_hit = 1.0 if domain_set & campaign_domains else 0.0
            similarity = min(1.0, 0.75 * keyword_score + 0.35 * domain_hit)
            if similarity <= 0.0:
                continue
            matches.append(
                {
                    "id": str(entry.get("id") or ""),
                    "name": str(entry.get("name") or "未命名活动"),
                    "summary": str(entry.get("summary") or ""),
                    "similarity": round(similarity, 3),
                    "matched_keywords": hit_keywords,
                }
            )

        matches.sort(key=lambda item: (-item["similarity"], item["id"]))
        return matches[:bounded_limit]

    @staticmethod
    def _string_list(value: Any) -> list[str]:
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list):
            return []
        return [str(item).strip() for item in value if str(item).strip()]


def build_provider(data_path: str | Path | None = None) -> MockIntelProvider:
    """Small convenience alias used by the registry."""
    return MockIntelProvider(data_path)


def collect_hosts(values: Iterable[Any]) -> list[str]:
    """Return non-empty hosts from URLs/domains (used by sandbox tools)."""
    hosts: list[str] = []
    for value in values or []:
        host = url_host(str(value or ""))
        if host:
            hosts.append(host)
    return hosts