import sys
from pathlib import Path


SECURITY_ENGINE_DIR = Path(__file__).resolve().parents[1] / "security-engine"

if str(SECURITY_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(SECURITY_ENGINE_DIR))
