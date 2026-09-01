from dataclasses import dataclass, field


@dataclass
class SecurityEvent:
    """A security finding displayed in the dashboard."""

    timestamp: str
    severity: str
    rule: str
    message: str
    score: int = 0


@dataclass
class DashboardState:
    """Current state displayed by the Inovix security dashboard."""

    threat_score: int = 0
    events_analyzed: int = 0
    findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    recent_events: list[SecurityEvent] = field(default_factory=list)
    intelligence: str = "LOCAL"
    verdict: str = "UNKNOWN"