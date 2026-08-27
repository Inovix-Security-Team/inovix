from analyzers.basic import BasicAnalyzer
from detectors.rules import RuleBasedDetector
from exceptions import SecurityEngineError
from models import AnalysisInput, AnalysisResult
from utils.validation import validate_input


class SecurityEngine:
    """Main orchestration layer for the Inovix Security Engine."""

    def __init__(self) -> None:
        self.analyzer = BasicAnalyzer()
        self.detector = RuleBasedDetector()

    def analyze(
        self,
        content: str,
        source: str = "unknown",
        metadata: dict | None = None,
    ) -> AnalysisResult:
        """Run the complete security analysis pipeline."""

        validate_input(content)

        normalized = AnalysisInput(
            content=content.strip(),
            source=source,
            metadata=metadata or {},
        )

        try:
            analysis = self.analyzer.analyze(normalized)
            detection = self.detector.detect(analysis)

            return AnalysisResult(
                status=detection["status"],
                risk_score=detection["risk_score"],
                reasons=detection["reasons"],
                indicators=detection["indicators"],
            )

        except Exception as exc:
            raise SecurityEngineError(
                f"Security analysis failed: {exc}"
            ) from exc