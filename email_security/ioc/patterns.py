import ipaddress
import re


URL_PATTERN = re.compile(
    r"(?<![\w])https?://[^\s<>'\"]+",
    re.IGNORECASE,
)

EMAIL_PATTERN = re.compile(
    r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@"
    r"[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
    r"(?![A-Za-z0-9-])",
    re.IGNORECASE,
)

DOMAIN_PATTERN = re.compile(
    r"(?<![@\w-])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}"
    r"(?![\w.-])",
    re.IGNORECASE,
)

IPV4_PATTERN = re.compile(
    r"(?<![\w.])"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"(?![\w.])",
)

IPV6_PATTERN = re.compile(
    r"(?<![\w:])"
    r"(?:"
    r"(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}"
    r"|[0-9A-Fa-f]{1,4}:(?:(?::[0-9A-Fa-f]{1,4}){1,6})"
    r"|:(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:)"
    r")"
    r"(?![\w:])",
)

MD5_PATTERN = re.compile(
    r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}(?![0-9A-Fa-f])",
)

SHA1_PATTERN = re.compile(
    r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{40}(?![0-9A-Fa-f])",
)

SHA256_PATTERN = re.compile(
    r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])",
)


def is_valid_ip(value: str) -> bool:
    """Return whether value is a syntactically valid IPv4 or IPv6 address."""

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False

    return True


def normalize_domain(value: str) -> str:
    """Normalize a domain for deterministic IOC deduplication."""

    return value.strip().rstrip(".").lower()


def normalize_url(value: str) -> str:
    """Normalize a URL without performing network access."""

    return value.strip().rstrip(".,;:!?)]}>").lower()


def normalize_email(value: str) -> str:
    """Normalize an email address for deterministic deduplication."""

    return value.strip().lower()


def normalize_ip(value: str) -> str:
    """Normalize an IP address using ipaddress canonical formatting."""

    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return value.strip().lower()


def normalize_hash(value: str) -> str:
    """Normalize a hexadecimal hash."""

    return value.strip().lower()
