from dataclasses import dataclass
from enum import Enum


class DiagnosticStatus(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass
class DiagnosticResult:
    name: str
    status: DiagnosticStatus
    message: str
    details: str | None = None