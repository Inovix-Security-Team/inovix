from datetime import datetime

from cli.models.dashboard_models import DashboardState, SecurityEvent
from cli.services.security_service import analyze


class EventService:
    """Process security events and maintain dashboard state."""

    def __init__(self) -> None:
        self.state = DashboardState()

    def process(self, text: str) -> dict:
        """Analyze input and update the dashboard state."""

        result = analyze(text)

        self.state.events_analyzed += 1
        self.state.threat_score = result.get("risk_score", 0)
        self.state.verdict = result.get("verdict", "UNKNOWN")

        for finding in result.get("findings", []):
            severity = str(
                finding.get("severity", "LOW")
            ).upper()

            if severity == "CRITICAL":
                self.state.critical += 1
            elif severity == "HIGH":
                self.state.high += 1
            elif severity == "MEDIUM":
                self.state.medium += 1
            else:
                self.state.low += 1

            self.state.findings += 1

            event = SecurityEvent(
                timestamp=datetime.now().strftime("%H:%M:%S"),
                severity=severity,
                rule=finding.get("rule_id", "UNKNOWN"),
                message=finding.get(
                    "reason",
                    "Finding detected.",
                ),
                score=result.get("risk_score", 0),
            )

            self.state.recent_events.insert(0, event)

        self.state.recent_events = self.state.recent_events[:12]

        return result