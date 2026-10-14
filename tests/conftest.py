import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for path in (ROOT / "src" / "collector", ROOT / "src" / "dashboard"):
    sys.path.insert(0, str(path))
