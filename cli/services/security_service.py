import sys
from pathlib import Path


ENGINE_DIR = Path(__file__).resolve().parents[2] / "security-engine"

if str(ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ENGINE_DIR))


try:
    from engine import SecurityEngine

    _engine = SecurityEngine()
except Exception:
    _engine = None


def analyze(text: str) -> dict:
    """Analyze text using the existing Inovix Security Engine."""

    if _engine is None:
        return {
            "verdict": "UNKNOWN",
            "risk_score": 0,
            "findings": [],
            "indicators": [],
        }

    return _engine.analyze(text).to_dict()