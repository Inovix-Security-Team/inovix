from __future__ import annotations

import ipaddress
import re
from email.utils import getaddresses
from typing import Iterable, Optional

from email_security.email_models.email_models import EmailMessageData

from .models import (
    AUTHENTICATION_RESULTS,
    DMARCAnalysis,
    DKIMAnalysis,
    EmailForensicResult,
    ForensicEvidence,
    ForensicIndicator,
    IdentityAnalysis,
    ReceivedHop,
    SPFAnalysis,
)


class EmailForensicsAnalyzer:
    """
    Perform passive forensic analysis on structured EmailMessageData.

    No DNS lookups, network requests, URL following, attachment execution,
    external binaries, mailbox modifications, or message transmission occur.
    """

    _RESULT_PATTERN = re.compile(
        r"\b(?P<method>spf|dkim|dmarc)\s*=\s*"
        r"(?P<result>pass|fail|softfail|neutral|none|temperror|permerror)\b",
        re.IGNORECASE,
    )

    _SPF_MAILFROM_PATTERN = re.compile(
        r"\bsmtp\.mailfrom\s*=\s*(?P<value>[^;\s]+)",
        re.IGNORECASE,
    )

    _DMARC_HEADER_FROM_PATTERN = re.compile(
        r"\bheader\.from\s*=\s*(?P<value>[^;\s]+)",
        re.IGNORECASE,
    )

    _DMARC_POLICY_PATTERN = re.compile(
        r"\bpolicy\s*=\s*(?P<value>none|quarantine|reject)\b",
        re.IGNORECASE,
    )

    _DKIM_TAG_PATTERN = re.compile(
        r"(?:^|;)\s*(?P<tag>[a-zA-Z])\s*=\s*(?P<value>[^;]+)"
    )

    _IP_CANDIDATE_PATTERN = re.compile(
        r"""
        (?:
            (?<![\w.])
            (?:\d{1,3}\.){3}\d{1,3}
            (?![\w.])
        )
        |
        (?:
            \[
            [0-9A-Fa-f:]+
            \]
        )
        |
        (?:
            (?<![\w:])
            [0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){2,7}
            (?![\w:])
        )
        """,
        re.VERBOSE,
    )

    _HOST_PATTERN = re.compile(
        r"\b(?:from|by)\s+(?P<host>[A-Za-z0-9][A-Za-z0-9._-]*)",
        re.IGNORECASE,
    )

    def analyze(self, email: EmailMessageData) -> EmailForensicResult:
        """Analyze an already-parsed EmailMessageData object."""

        received_hops = self._analyze_received_headers(email.received)
        candidate_origin_ip = self._extract_origin_ip(received_hops)

        spf = self._parse_spf(email.authentication_headers)
        dkim = self._parse_dkim(email.authentication_headers)
        dmarc = self._parse_dmarc(email.authentication_headers)

        identity = self._analyze_sender_identity(
            sender=email.sender,
            reply_to=email.reply_to,
            return_path=email.return_path,
        )

        evidence = self._build_evidence(
            received_hops=received_hops,
            spf=spf,
            dkim=dkim,
            dmarc=dmarc,
            identity=identity,
        )

        anomalies = self._detect_anomalies(
            received_hops=received_hops,
            spf=spf,
            dkim=dkim,
            dmarc=dmarc,
            identity=identity,
        )

        return EmailForensicResult(
            received_hops=tuple(received_hops),
            candidate_origin_ip=candidate_origin_ip,
            spf=spf,
            dkim=dkim,
            dmarc=dmarc,
            identity_analysis=identity,
            anomalies=tuple(anomalies),
            evidence=tuple(evidence),
        )

    def _analyze_received_headers(
        self,
        received_headers: Optional[Iterable[str]],
    ) -> list[ReceivedHop]:
        """Parse every Received header while preserving original order."""

        if not received_headers:
            return []

        hops: list[ReceivedHop] = []

        for raw_header in received_headers:
            raw = str(raw_header).strip()

            if not raw:
                hops.append(
                    ReceivedHop(
                        raw_header=raw,
                        parse_successful=False,
                    )
                )
                continue

            ip_address = self._extract_ip(raw)
            hostname = self._extract_hostname(raw)

            parse_successful = bool(hostname or ip_address)
            private_or_reserved = False

            if ip_address:
                try:
                    address = ipaddress.ip_address(ip_address)
                    private_or_reserved = (
                        address.is_private or address.is_reserved
                    )
                except ValueError:
                    private_or_reserved = False

            hops.append(
                ReceivedHop(
                    raw_header=raw,
                    hostname=hostname,
                    ip_address=ip_address,
                    is_private_or_reserved=private_or_reserved,
                    parse_successful=parse_successful,
                )
            )

        return hops

    def _extract_ip(self, value: str) -> Optional[str]:
        """Extract the first syntactically valid IPv4 or IPv6 address."""

        for candidate in self._IP_CANDIDATE_PATTERN.findall(value):
            normalized = candidate.strip("[]")

            try:
                return str(ipaddress.ip_address(normalized))
            except ValueError:
                continue

        return None

    def _extract_hostname(self, value: str) -> Optional[str]:
        """Extract the first hostname associated with a Received hop."""

        match = self._HOST_PATTERN.search(value)

        if not match:
            return None

        hostname = match.group("host").strip().rstrip(".")

        return hostname or None

    def _extract_origin_ip(
        self,
        received_hops: Iterable[ReceivedHop],
    ) -> Optional[str]:
        """
        Select a candidate originating IP.

        The oldest usable external address is searched from the end of the
        preserved Received-header sequence.

        This is only a forensic candidate and is not attacker attribution.
        """

        hops = list(received_hops)

        for hop in reversed(hops):
            if hop.ip_address and not hop.is_private_or_reserved:
                return hop.ip_address

        for hop in reversed(hops):
            if hop.ip_address:
                return hop.ip_address

        return None

    def _authentication_results_headers(
        self,
        authentication_headers: Optional[dict],
    ) -> list[str]:
        """Return Authentication-Results evidence only."""

        if not authentication_headers:
            return []

        values: list[str] = []

        for key, raw_value in authentication_headers.items():
            if str(key).lower() not in {
                "authentication-results",
                "arc-authentication-results",
            }:
                continue

            if isinstance(raw_value, (list, tuple)):
                values.extend(str(item) for item in raw_value)
            else:
                values.append(str(raw_value))

        return values

    def _parse_spf(
        self,
        authentication_headers: Optional[dict],
    ) -> SPFAnalysis:
        """Extract SPF result and smtp.mailfrom evidence."""

        evidence = self._authentication_results_headers(
            authentication_headers
        )

        result: Optional[str] = None
        mail_from: Optional[str] = None

        for header in evidence:
            for match in self._RESULT_PATTERN.finditer(header):
                if match.group("method").lower() == "spf":
                    result = match.group("result").lower()
                    break

            mail_match = self._SPF_MAILFROM_PATTERN.search(header)

            if mail_match and mail_from is None:
                mail_from = mail_match.group("value").strip("<>")

            if result is not None and mail_from is not None:
                break

        return SPFAnalysis(
            result=result if result in AUTHENTICATION_RESULTS else None,
            mail_from=mail_from,
            raw_evidence=tuple(evidence),
        )

    def _parse_dkim(
        self,
        authentication_headers: Optional[dict],
    ) -> DKIMAnalysis:
        """Extract DKIM result, signing domain, and selector."""

        auth_results = self._authentication_results_headers(
            authentication_headers
        )

        dkim_headers = self._get_header_values(
            authentication_headers,
            {"dkim-signature", "domainkey-signature"},
        )

        result: Optional[str] = None

        for header in auth_results:
            for match in self._RESULT_PATTERN.finditer(header):
                if match.group("method").lower() == "dkim":
                    result = match.group("result").lower()
                    break

            if result is not None:
                break

        signing_domain: Optional[str] = None
        selector: Optional[str] = None

        for header in dkim_headers:
            tags = self._parse_semicolon_tags(header)

            if signing_domain is None:
                signing_domain = tags.get("d")

            if selector is None:
                selector = tags.get("s")

            if signing_domain and selector:
                break

        return DKIMAnalysis(
            result=result if result in AUTHENTICATION_RESULTS else None,
            signing_domain=signing_domain,
            selector=selector,
            raw_evidence=tuple(auth_results + dkim_headers),
        )

    def _parse_dmarc(
        self,
        authentication_headers: Optional[dict],
    ) -> DMARCAnalysis:
        """Extract DMARC result, policy, and header.from evidence."""

        evidence = self._authentication_results_headers(
            authentication_headers
        )

        result: Optional[str] = None
        policy: Optional[str] = None
        header_from: Optional[str] = None

        for header in evidence:
            for match in self._RESULT_PATTERN.finditer(header):
                if match.group("method").lower() == "dmarc":
                    result = match.group("result").lower()
                    break

            if header_from is None:
                from_match = self._DMARC_HEADER_FROM_PATTERN.search(header)

                if from_match:
                    header_from = from_match.group("value").strip("<>")

            if policy is None:
                policy_match = self._DMARC_POLICY_PATTERN.search(header)

                if policy_match:
                    policy = policy_match.group("value").lower()

            if result is not None and header_from is not None:
                break

        return DMARCAnalysis(
            result=result if result in AUTHENTICATION_RESULTS else None,
            policy=policy,
            header_from=header_from,
            raw_evidence=tuple(evidence),
        )

    def _get_header_values(
        self,
        headers: Optional[dict],
        names: set[str],
    ) -> list[str]:
        if not headers:
            return []

        values: list[str] = []

        for key, raw_value in headers.items():
            if str(key).lower() not in names:
                continue

            if isinstance(raw_value, (list, tuple)):
                values.extend(str(item) for item in raw_value)
            else:
                values.append(str(raw_value))

        return values

    def _parse_semicolon_tags(self, value: str) -> dict[str, str]:
        """Parse simple RFC-style key=value semicolon tags."""

        tags: dict[str, str] = {}

        for match in self._DKIM_TAG_PATTERN.finditer(value):
            tag = match.group("tag").lower()
            tags[tag] = match.group("value").strip()

        return tags

    def _analyze_sender_identity(
        self,
        sender: Optional[str],
        reply_to: Optional[Iterable[str]],
        return_path: Optional[str],
    ) -> IdentityAnalysis:
        """Compare From, Reply-To, and Return-Path domains."""

        from_addresses = self._extract_addresses(sender)
        reply_addresses = self._extract_addresses(reply_to)
        return_addresses = self._extract_addresses(return_path)

        from_address = from_addresses[0] if from_addresses else None
        from_domain = self._domain_from_address(from_address)

        reply_domains = tuple(
            sorted(
                {
                    domain
                    for address in reply_addresses
                    if (domain := self._domain_from_address(address))
                }
            )
        )

        return_path_address = (
            return_addresses[0] if return_addresses else None
        )
        return_path_domain = self._domain_from_address(return_path_address)

        if from_domain and reply_domains:
            reply_match = all(
                domain == from_domain for domain in reply_domains
            )
        else:
            reply_match = None

        if from_domain and return_path_domain:
            return_match = from_domain == return_path_domain
        else:
            return_match = None

        return IdentityAnalysis(
            from_address=from_address,
            from_domain=from_domain,
            reply_to_addresses=tuple(reply_addresses),
            reply_to_domains=reply_domains,
            return_path=return_path_address,
            return_path_domain=return_path_domain,
            reply_to_domain_match=reply_match,
            return_path_domain_match=return_match,
        )

    def _extract_addresses(
        self,
        values: Optional[Iterable[str] | str],
    ) -> list[str]:
        if not values:
            return []

        if isinstance(values, str):
            values = [values]

        addresses: list[str] = []

        for _, address in getaddresses(
            [str(value) for value in values]
        ):
            address = address.strip()

            if address:
                addresses.append(address)

        return addresses

    def _domain_from_address(
        self,
        address: Optional[str],
    ) -> Optional[str]:
        if not address or "@" not in address:
            return None

        domain = address.rsplit("@", 1)[1].strip().lower()

        return domain.rstrip(".") or None

    def _build_evidence(
        self,
        received_hops: Iterable[ReceivedHop],
        spf: SPFAnalysis,
        dkim: DKIMAnalysis,
        dmarc: DMARCAnalysis,
        identity: IdentityAnalysis,
    ) -> list[ForensicEvidence]:
        evidence: list[ForensicEvidence] = []

        for index, hop in enumerate(received_hops):
            parsed_parts = []

            if hop.hostname:
                parsed_parts.append(f"hostname={hop.hostname}")

            if hop.ip_address:
                parsed_parts.append(f"ip={hop.ip_address}")

            if hop.is_private_or_reserved:
                parsed_parts.append("private_or_reserved=true")

            evidence.append(
                ForensicEvidence(
                    source=f"Received[{index}]",
                    raw_value=hop.raw_header,
                    parsed_value=(
                        ", ".join(parsed_parts)
                        if parsed_parts
                        else None
                    ),
                    reason=(
                        "Preserved Received header for hop-level "
                        "forensic analysis."
                    ),
                )
            )

        for source, values in (
            ("SPF", spf.raw_evidence),
            ("DKIM", dkim.raw_evidence),
            ("DMARC", dmarc.raw_evidence),
        ):
            for value in values:
                evidence.append(
                    ForensicEvidence(
                        source=source,
                        raw_value=value,
                        parsed_value=None,
                        reason=(
                            f"Preserved {source} authentication "
                            "evidence from message headers."
                        ),
                    )
                )

        if identity.from_address:
            evidence.append(
                ForensicEvidence(
                    source="From",
                    raw_value=identity.from_address,
                    parsed_value=identity.from_domain,
                    reason="Extracted sender address and domain.",
                )
            )

        if identity.reply_to_addresses:
            evidence.append(
                ForensicEvidence(
                    source="Reply-To",
                    raw_value=", ".join(identity.reply_to_addresses),
                    parsed_value=", ".join(identity.reply_to_domains),
                    reason="Extracted Reply-To addresses and domains.",
                )
            )

        if identity.return_path:
            evidence.append(
                ForensicEvidence(
                    source="Return-Path",
                    raw_value=identity.return_path,
                    parsed_value=identity.return_path_domain,
                    reason="Extracted Return-Path address and domain.",
                )
            )

        return evidence

    def _detect_anomalies(
        self,
        received_hops: Iterable[ReceivedHop],
        spf: SPFAnalysis,
        dkim: DKIMAnalysis,
        dmarc: DMARCAnalysis,
        identity: IdentityAnalysis,
    ) -> list[ForensicIndicator]:
        indicators: list[ForensicIndicator] = []

        if identity.reply_to_domain_match is False:
            indicators.append(
                self._indicator(
                    code="FROM_REPLY_TO_MISMATCH",
                    severity="MEDIUM",
                    title="From and Reply-To domains differ",
                    description=(
                        "The Reply-To domain does not match the From "
                        "domain."
                    ),
                    source="Reply-To",
                    raw_value=", ".join(identity.reply_to_addresses),
                    parsed_value=", ".join(identity.reply_to_domains),
                    reason=(
                        f"From domain is {identity.from_domain!r}, "
                        f"while Reply-To domains are "
                        f"{identity.reply_to_domains!r}."
                    ),
                )
            )

        if identity.return_path_domain_match is False:
            indicators.append(
                self._indicator(
                    code="FROM_RETURN_PATH_MISMATCH",
                    severity="MEDIUM",
                    title="From and Return-Path domains differ",
                    description=(
                        "The Return-Path domain differs from the From "
                        "domain."
                    ),
                    source="Return-Path",
                    raw_value=identity.return_path or "",
                    parsed_value=identity.return_path_domain,
                    reason=(
                        f"From domain is {identity.from_domain!r}, "
                        f"while Return-Path domain is "
                        f"{identity.return_path_domain!r}."
                    ),
                )
            )

        if spf.result == "fail":
            indicators.append(
                self._indicator(
                    code="SPF_FAILURE",
                    severity="HIGH",
                    title="SPF authentication failed",
                    description=(
                        "Authentication-Results reports SPF failure."
                    ),
                    source="SPF",
                    raw_value=" | ".join(spf.raw_evidence),
                    parsed_value=spf.result,
                    reason="SPF result was explicitly reported as fail.",
                )
            )

        if dkim.result == "fail":
            indicators.append(
                self._indicator(
                    code="DKIM_FAILURE",
                    severity="HIGH",
                    title="DKIM authentication failed",
                    description=(
                        "Authentication-Results reports DKIM failure."
                    ),
                    source="DKIM",
                    raw_value=" | ".join(dkim.raw_evidence),
                    parsed_value=dkim.result,
                    reason="DKIM result was explicitly reported as fail.",
                )
            )

        if dmarc.result == "fail":
            indicators.append(
                self._indicator(
                    code="DMARC_FAILURE",
                    severity="HIGH",
                    title="DMARC authentication failed",
                    description=(
                        "Authentication-Results reports DMARC failure."
                    ),
                    source="DMARC",
                    raw_value=" | ".join(dmarc.raw_evidence),
                    parsed_value=dmarc.result,
                    reason="DMARC result was explicitly reported as fail.",
                )
            )

        if (
            spf.result is None
            and dkim.result is None
            and dmarc.result is None
        ):
            indicators.append(
                self._indicator(
                    code="AUTHENTICATION_EVIDENCE_MISSING",
                    severity="INFO",
                    title="Authentication evidence missing",
                    description=(
                        "No meaningful SPF, DKIM or DMARC result was "
                        "available in the supplied authentication headers."
                    ),
                    source="Authentication-Results",
                    raw_value="",
                    parsed_value=None,
                    reason="No supported authentication result was found.",
                )
            )

        malformed_received = [
            hop for hop in received_hops if not hop.parse_successful
        ]

        if malformed_received:
            indicators.append(
                self._indicator(
                    code="MALFORMED_RECEIVED_HEADER",
                    severity="LOW",
                    title="Malformed Received header",
                    description=(
                        "One or more Received headers could not be "
                        "meaningfully parsed."
                    ),
                    source="Received",
                    raw_value=" | ".join(
                        hop.raw_header for hop in malformed_received
                    ),
                    parsed_value=None,
                    reason=(
                        "The affected header contained neither a "
                        "recognizable hostname nor a valid IP address."
                    ),
                )
            )

        private_received = [
            hop
            for hop in received_hops
            if hop.ip_address and hop.is_private_or_reserved
        ]

        if private_received:
            indicators.append(
                self._indicator(
                    code="PRIVATE_OR_RESERVED_RECEIVED_IP",
                    severity="INFO",
                    title="Private or reserved Received IP",
                    description=(
                        "A Received header contains a private or "
                        "reserved IP address. This is informational "
                        "unless supported by additional evidence."
                    ),
                    source="Received",
                    raw_value=" | ".join(
                        hop.raw_header for hop in private_received
                    ),
                    parsed_value=", ".join(
                        hop.ip_address
                        for hop in private_received
                        if hop.ip_address
                    ),
                    reason=(
                        "The extracted address was classified as "
                        "private or reserved by ipaddress."
                    ),
                )
            )

        return indicators

    def _indicator(
        self,
        *,
        code: str,
        severity: str,
        title: str,
        description: str,
        source: str,
        raw_value: str,
        parsed_value: Optional[str],
        reason: str,
    ) -> ForensicIndicator:
        if severity not in {"INFO", "LOW", "MEDIUM", "HIGH"}:
            raise ValueError(
                f"Unsupported forensic severity: {severity}"
            )

        evidence = ForensicEvidence(
            source=source,
            raw_value=raw_value,
            parsed_value=parsed_value,
            reason=reason,
        )

        return ForensicIndicator(
            code=code,
            severity=severity,
            title=title,
            description=description,
            evidence=(evidence,),
        )