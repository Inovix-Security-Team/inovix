from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


AUTHENTICATION_RESULTS = frozenset(
    {
        "pass",
        "fail",
        "softfail",
        "neutral",
        "none",
        "temperror",
        "permerror",
    }
)

INDICATOR_SEVERITIES = frozenset({"INFO", "LOW", "MEDIUM", "HIGH"})


@dataclass(frozen=True)
class ReceivedHop:
    """A single parsed Received header."""

    raw_header: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    is_private_or_reserved: bool = False
    parse_successful: bool = True


@dataclass(frozen=True)
class AuthenticationResult:
    """Generic authentication evidence extracted from headers."""

    result: Optional[str] = None
    raw_evidence: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.result is not None and self.result.lower() not in AUTHENTICATION_RESULTS:
            raise ValueError(f"Unsupported authentication result: {self.result}")


@dataclass(frozen=True)
class SPFAnalysis:
    result: Optional[str] = None
    mail_from: Optional[str] = None
    raw_evidence: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.result is not None and self.result.lower() not in AUTHENTICATION_RESULTS:
            raise ValueError(f"Unsupported SPF result: {self.result}")


@dataclass(frozen=True)
class DKIMAnalysis:
    result: Optional[str] = None
    signing_domain: Optional[str] = None
    selector: Optional[str] = None
    raw_evidence: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.result is not None and self.result.lower() not in AUTHENTICATION_RESULTS:
            raise ValueError(f"Unsupported DKIM result: {self.result}")


@dataclass(frozen=True)
class DMARCAnalysis:
    result: Optional[str] = None
    policy: Optional[str] = None
    header_from: Optional[str] = None
    raw_evidence: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.result is not None and self.result.lower() not in AUTHENTICATION_RESULTS:
            raise ValueError(f"Unsupported DMARC result: {self.result}")


@dataclass(frozen=True)
class IdentityAnalysis:
    from_address: Optional[str] = None
    from_domain: Optional[str] = None
    reply_to_addresses: tuple[str, ...] = field(default_factory=tuple)
    reply_to_domains: tuple[str, ...] = field(default_factory=tuple)
    return_path: Optional[str] = None
    return_path_domain: Optional[str] = None
    reply_to_domain_match: Optional[bool] = None
    return_path_domain_match: Optional[bool] = None


@dataclass(frozen=True)
class ForensicEvidence:
    """Preserved evidence used to explain a forensic finding."""

    source: str
    raw_value: str
    parsed_value: Optional[str]
    reason: str


@dataclass(frozen=True)
class ForensicIndicator:
    code: str
    severity: str
    title: str
    description: str
    evidence: tuple[ForensicEvidence, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.severity not in INDICATOR_SEVERITIES:
            raise ValueError(f"Unsupported forensic severity: {self.severity}")


@dataclass(frozen=True)
class EmailForensicResult:
    """Complete passive forensic analysis of an EmailMessageData object."""

    received_hops: tuple[ReceivedHop, ...] = field(default_factory=tuple)
    candidate_origin_ip: Optional[str] = None

    spf: SPFAnalysis = field(default_factory=SPFAnalysis)
    dkim: DKIMAnalysis = field(default_factory=DKIMAnalysis)
    dmarc: DMARCAnalysis = field(default_factory=DMARCAnalysis)

    identity_analysis: IdentityAnalysis = field(
        default_factory=IdentityAnalysis
    )

    anomalies: tuple[ForensicIndicator, ...] = field(default_factory=tuple)
    evidence: tuple[ForensicEvidence, ...] = field(default_factory=tuple)