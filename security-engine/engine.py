from typing import Any

from analyzers.basic import BasicAnalyzer
from detectors.rules import RuleBasedDetector
from exceptions import SecurityEngineError
from threat_intelligence.local import LocalThreatIntelligenceProvider
from models import (
    AnalysisResult,
    Finding,
    ImpactResult,
    ResponseDecision,
    RiskResult,
    SecurityResult,
    VerificationResult,
)
from utils.normalization import normalize_input
from utils.risk_scoring import calculate_risk_score
from utils.validation import validate_input
from utils.verdict import generate_verdict


class SecurityEngine:
    """Core modular security detection pipeline."""

    def __init__(self) -> None:
        self.analyzer = BasicAnalyzer()
        self.detector = RuleBasedDetector()
        self.threat_intelligence = LocalThreatIntelligenceProvider()

    def _unknown_result(
        self,
        reason: str,
    ) -> SecurityResult:
        """Return a neutral result for missing or unusable telemetry."""

        risk = RiskResult(
            score=0,
            level="UNKNOWN",
            reasons=[reason],
        )

        return SecurityResult(
            verdict="UNKNOWN",
            risk_score=0,
            reasons=[reason],
            indicators=[],
            findings=[],
            risk=risk,
            impact=ImpactResult(
                level="UNKNOWN",
                reasons=[reason],
            ),
            response=ResponseDecision(
                action="NO_ACTION",
                reason="No response action is possible without valid telemetry.",
            ),
            verification=VerificationResult(
                verified=True,
                status="NOT_EXECUTED",
                details="No response action was executed.",
            ),
        )

    def _rejected_result(
        self,
        reason: str,
    ) -> SecurityResult:
        """Return a rejected result for malformed telemetry."""

        risk = RiskResult(
            score=0,
            level="UNKNOWN",
            reasons=[reason],
        )

        return SecurityResult(
            verdict="REJECTED",
            risk_score=0,
            reasons=[reason],
            indicators=[],
            findings=[],
            risk=risk,
            impact=ImpactResult(
                level="UNKNOWN",
                reasons=[reason],
            ),
            response=ResponseDecision(
                action="NO_ACTION",
                reason="Input was rejected before security analysis.",
            ),
            verification=VerificationResult(
                verified=True,
                status="NOT_EXECUTED",
                details="Input validation rejected the event.",
            ),
        )

    def _analyze_structured_event(
        self,
        event: dict[str, Any],
    ) -> SecurityResult | None:
        """Handle known structured telemetry event types.

        Returns a SecurityResult for events that have explicit telemetry
        semantics. Returns None when the event should continue through the
        normal content-analysis pipeline.
        """

        event_type = event.get("event_type")

        if not isinstance(event_type, str):
            return self._rejected_result(
                "Structured event must contain a valid event_type."
            )

        normalized_type = event_type.strip().lower()

        # ---------------------------------------------------------
        # Brute-force / failed-login detection
        # ---------------------------------------------------------
        if normalized_type in {
            "failed_login",
            "brute_force",
            "brute_force_attempt",
            "authentication_failure",
        }:
            attempts = event.get("attempts", 1)

            try:
                attempts_value = int(attempts)
            except (TypeError, ValueError):
                attempts_value = 1

            attempts_value = max(attempts_value, 1)

            if attempts_value >= 10:
                score = 100
                severity = "CRITICAL"
                reason = (
                    f"Brute-force authentication activity detected "
                    f"with {attempts_value} failed attempts."
                )
            elif attempts_value >= 5:
                score = 80
                severity = "HIGH"
                reason = (
                    f"Repeated authentication failures detected "
                    f"with {attempts_value} attempts."
                )
            else:
                score = 60
                severity = "MEDIUM"
                reason = (
                    f"Authentication failures detected "
                    f"with {attempts_value} attempt(s)."
                )

            finding = Finding(
                rule_id="BRUTE_FORCE",
                severity=severity,
                reason=reason,
                indicator=str(event.get("source_ip", "unknown")),
            )

            return self._build_result_from_findings(
                score=score,
                findings=[finding],
            )

        # ---------------------------------------------------------
        # Port-scan / network-scan detection
        # ---------------------------------------------------------
        if normalized_type in {
            "network_scan",
            "port_scan",
            "portscan",
            "network_probe",
        }:
            ports = event.get("ports_scanned", [])

            if isinstance(ports, (list, tuple, set)):
                port_count = len(ports)
            else:
                port_count = 0

            if port_count >= 5:
                score = 80
                severity = "HIGH"
                reason = (
                    f"Network port scanning detected across "
                    f"{port_count} ports."
                )
            elif port_count >= 2:
                score = 60
                severity = "MEDIUM"
                reason = (
                    f"Network probing detected across "
                    f"{port_count} ports."
                )
            else:
                score = 60
                severity = "MEDIUM"
                reason = "Potential network scanning activity detected."

            finding = Finding(
                rule_id="PORT_SCAN",
                severity=severity,
                reason=reason,
                indicator=str(event.get("source_ip", "unknown")),
            )

            return self._build_result_from_findings(
                score=score,
                findings=[finding],
            )

        return None

    def _build_result_from_findings(
        self,
        score: int,
        findings: list[Finding],
    ) -> SecurityResult:
        """Build a complete SecurityResult from explicit findings."""

        risk_score = max(0, min(int(score), 100))
        verdict = generate_verdict(risk_score)

        reasons = [
            finding.reason
            for finding in findings
        ]

        indicators = [
            finding.indicator
            for finding in findings
        ]

        risk = RiskResult(
            score=risk_score,
            level=verdict,
            reasons=reasons,
        )

        if risk_score >= 80:
            impact = ImpactResult(
                level="HIGH",
                reasons=[
                    "High-risk security findings were detected."
                ],
            )
        elif risk_score > 0:
            impact = ImpactResult(
                level="MEDIUM",
                reasons=[
                    "Security indicators require review."
                ],
            )
        else:
            impact = ImpactResult(
                level="LOW",
                reasons=[
                    "No security impact indicators were detected."
                ],
            )

        if verdict == "MALICIOUS":
            response = ResponseDecision(
                action="REVIEW",
                reason=(
                    "Potentially malicious activity requires review."
                ),
            )
        elif verdict == "SUSPICIOUS":
            response = ResponseDecision(
                action="MONITOR",
                reason=(
                    "Suspicious activity should be monitored."
                ),
            )
        else:
            response = ResponseDecision(
                action="NO_ACTION",
                reason="No response action is required.",
            )

        verification = VerificationResult(
            verified=True,
            status="NOT_EXECUTED",
            details=(
                "Response actions are simulated in the foundation."
            ),
        )

        return SecurityResult(
            verdict=verdict,
            risk_score=risk_score,
            reasons=reasons,
            indicators=indicators,
            findings=findings,
            risk=risk,
            impact=impact,
            response=response,
            verification=verification,
        )

    def analyze(
        self,
        content: str | dict[str, Any],
        source: str = "unknown",
        event_type: str = "text",
        metadata: dict[str, Any] | None = None,
    ) -> SecurityResult:
        """Run the complete security analysis pipeline."""

        # Empty structured input is not an engine crash condition.
        if isinstance(content, dict) and not content:
            return self._unknown_result(
                "No security telemetry was provided."
            )

        try:
            validate_input(content)

            if isinstance(content, dict):
                event = content

                # Handle explicitly structured security telemetry first.
                structured_result = self._analyze_structured_event(event)

                if structured_result is not None:
                    return structured_result

                event_type_from_event = event.get(
                    "event_type",
                    event_type,
                )

                source_from_event = event.get(
                    "source_ip",
                    source,
                )

                if not isinstance(event_type_from_event, str):
                    event_type_from_event = event_type

                if not isinstance(source_from_event, str):
                    source_from_event = source

                event_metadata = {
                    key: value
                    for key, value in event.items()
                    if key not in {
                        "event_type",
                        "source_ip",
                        "content",
                    }
                }

                if metadata:
                    event_metadata.update(metadata)

                content_parts: list[str] = []

                event_content = event.get("content")

                if (
                    isinstance(event_content, str)
                    and event_content.strip()
                ):
                    content_parts.append(event_content)

                if event_type_from_event:
                    content_parts.append(
                        f"event_type={event_type_from_event}"
                    )

                for key, value in event.items():
                    if key in {
                        "event_type",
                        "source_ip",
                        "content",
                    }:
                        continue

                    if value is not None:
                        content_parts.append(
                            f"{key}={value}"
                        )

                content = " ".join(content_parts)
                source = source_from_event
                event_type = event_type_from_event
                metadata = event_metadata

            normalized = normalize_input(
                content,
                source=source,
                event_type=event_type,
                metadata=metadata,
            )

            analysis = self.analyzer.analyze(normalized)

            findings = self.detector.detect(analysis)

            risk_score = calculate_risk_score(findings)

            risk = RiskResult(
                score=risk_score,
                level=generate_verdict(risk_score),
                reasons=[
                    finding.reason
                    for finding in findings
                ],
            )

            verdict = risk.level

            reasons = [
                finding.reason
                for finding in findings
            ]

            indicators = [
                finding.indicator
                for finding in findings
            ]

            if risk_score >= 80:
                impact = ImpactResult(
                    level="HIGH",
                    reasons=[
                        "High-risk security findings were detected."
                    ],
                )
            elif risk_score > 0:
                impact = ImpactResult(
                    level="MEDIUM",
                    reasons=[
                        "Security indicators require review."
                    ],
                )
            else:
                impact = ImpactResult(
                    level="LOW",
                    reasons=[
                        "No security impact indicators were detected."
                    ],
                )

            if verdict == "MALICIOUS":
                response = ResponseDecision(
                    action="REVIEW",
                    reason=(
                        "Potentially malicious activity requires review."
                    ),
                )
            elif verdict == "SUSPICIOUS":
                response = ResponseDecision(
                    action="MONITOR",
                    reason=(
                        "Suspicious activity should be monitored."
                    ),
                )
            else:
                response = ResponseDecision(
                    action="NO_ACTION",
                    reason="No response action is required.",
                )

            verification = VerificationResult(
                verified=True,
                status="NOT_EXECUTED",
                details=(
                    "Response actions are simulated in the foundation."
                ),
            )

            return SecurityResult(
                verdict=verdict,
                risk_score=risk_score,
                reasons=reasons,
                indicators=indicators,
                findings=findings,
                risk=risk,
                impact=impact,
                response=response,
                verification=verification,
            )

        except SecurityEngineError:
            raise

        except Exception as exc:
            raise SecurityEngineError(
                f"Security analysis failed: {exc}"
            ) from exc

    def analyze_event(
        self,
        event: dict[str, Any],
    ) -> SecurityResult:
        """Analyze a structured security telemetry event."""

        if not isinstance(event, dict):
            raise SecurityEngineError(
                "Security event must be a dictionary."
            )

        return self.analyze(event)

    def analyze_legacy(
        self,
        content: str,
        source: str = "unknown",
        metadata: dict[str, Any] | None = None,
    ) -> AnalysisResult:
        """Compatibility wrapper for the TASK-001 result format."""

        result = self.analyze(
            content,
            source=source,
            metadata=metadata,
        )

        return AnalysisResult(
            status=result.verdict,
            risk_score=result.risk_score,
            reasons=result.reasons,
            indicators=result.indicators,
        )
