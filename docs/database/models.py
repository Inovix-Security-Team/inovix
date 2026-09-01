from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, List
import json


@dataclass
class EventRecord:
    id: str
    timestamp: str
    event_type: str
    source: str
    content_hash: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    created_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if isinstance(d.get("metadata"), dict):
            d["metadata"] = json.dumps(d["metadata"])
        return d


@dataclass
class FindingRecord:
    event_id: str
    rule_id: str
    severity: str
    reason: str
    indicator: str
    id: Optional[int] = None
    created_at: Optional[str] = None


@dataclass
class RiskAssessmentRecord:
    event_id: str
    score: int
    risk_level: str
    verdict: str
    id: Optional[int] = None
    created_at: Optional[str] = None