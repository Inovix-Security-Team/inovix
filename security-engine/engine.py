from security_engine.analyzers.basic import BasicAnalyzer
from security_engine.detectors.rules import RuleBasedDetector
from security_engine.exceptions import SecurityEngineError
from security_engine.models import (
    AnalysisResult,
    ImpactResult,
    ResponseDecision,
    RiskResult,
    SecurityResult,
    VerificationResult,
)
from security_engine.threat_intelligence import (
    LocalThreatIntelligenceProvider,
)
from security_engine.utils.normalization import normalize_input
from security_engine.utils.risk_scoring import calculate_risk_score
from security_engine.utils.validation import validate_input
from security_engine.utils.verdict import generate_verdict

class SecurityEngine:
    """Core modular security detection pipeline."""

    def __init__(self) -> None:
        self.analyzer = BasicAnalyzer()
        self.detector = RuleBasedDetector()
        self.threat_intelligence = LocalThreatIntelligenceProvider()

    def analyze(
        self,
        content: str,
        source: str = "unknown",
        event_type: str = "text",
        metadata: dict[str, Any] | None = None,
    ) -> SecurityResult:
        """Run the complete security analysis pipeline.

        Pipeline:
            validation
            -> normalization
            -> analysis
            -> detection
            -> threat intelligence
            -> risk scoring
            -> verdict
            -> impact
            -> response decision
            -> verification
        """

        validate_input(content)

        try:
            normalized = normalize_input(
                content,
                source=source,
                event_type=event_type,
                metadata=metadata,
            )

            analysis = self.analyzer.analyze(normalized)

            findings = self.detector.detect(analysis)

            findings = [
                self.threat_intelligence.enrich(finding)
                for finding in findings
            ]

            risk_score = calculate_risk_score(findings)

            risk = RiskResult(
                score=risk_score,
                level=generate_verdict(risk_score),
                reasons=[finding.reason for finding in findings],
            )

            verdict = risk.level

            reasons = [finding.reason for finding in findings]
            indicators = [finding.indicator for finding in findings]

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
