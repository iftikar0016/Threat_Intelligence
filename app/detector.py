import re
from enum import Enum
from urllib.parse import urlparse


class IndicatorType(str, Enum):
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    HASH = "hash"
    UNKNOWN = "unknown"


# Regexes for validation
IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$")
IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")  # loose; refined below
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$"
)
HASH_RE = re.compile(r"^[a-fA-F0-9]+$")


def detect_indicator_type(value: str) -> IndicatorType:
    value = value.strip()

    # 1. URL
    if value.lower().startswith(("http://", "https://", "ftp://")):
        return IndicatorType.URL

    # 2. Hash (md5=32, sha1=40, sha256=64)
    if HASH_RE.match(value) and len(value) in (32, 40, 64):
        return IndicatorType.HASH

    # 3. IPv4
    if IPV4_RE.match(value):
        return IndicatorType.IP

    # 4. IPv6 (rough check)
    if ":" in value and IPV6_RE.match(value) and value.count(":") >= 2:
        return IndicatorType.IP

    # 5. Domain
    if DOMAIN_RE.match(value):
        return IndicatorType.DOMAIN

    # 6. Fallback rough check for domains without protocol (e.g. google.com or test.org)
    # If it contains dots, does not start with digits (to avoid confusion with invalid IPs),
    # and matches DOMAIN_RE, let's treat it as a domain.
    if "." in value and not value[0].isdigit() and DOMAIN_RE.match(value):
        return IndicatorType.DOMAIN

    return IndicatorType.UNKNOWN


def normalize(value: str, kind: IndicatorType) -> str:
    """Normalize for cache key + downstream calls."""
    value = value.strip()
    if kind == IndicatorType.URL:
        return value
    if kind == IndicatorType.HASH:
        return value.lower()
    if kind == IndicatorType.DOMAIN:
        return value.lower()
    if kind == IndicatorType.IP:
        return value.lower()
    return value


def url_id_for_vt(url: str) -> str:
    """VirusTotal v3 wants base64url-encoded URL without padding."""
    import base64
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def domain_from_url(url: str) -> str:
    parsed = urlparse(url)
    # Handle cases where protocol was missing, e.g. "example.com"
    if not parsed.scheme:
        parsed = urlparse("http://" + url)
    return parsed.hostname or ""
