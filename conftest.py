"""Pytest bootstrap.

Ensures the project root is importable (``backend``, ``scripts``) no matter
which directory pytest is invoked from.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))