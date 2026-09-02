from dataclasses import dataclass
from enum import Enum
from typing import Any


class DiagnosticStatus(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass
class DiagnosticResult:
    name: str
    status: DiagnosticStatus
    message: str
    details: Any = None