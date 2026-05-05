"""pytest config for netmon tests — adds the netmon package dir to sys.path.

netmon's modules import each other as top-level (e.g. `from rules import ...`),
not as a package. Tests need the same import root.
"""
from __future__ import annotations

import sys
from pathlib import Path

_NETMON_DIR = Path(__file__).resolve().parent.parent
if str(_NETMON_DIR) not in sys.path:
    sys.path.insert(0, str(_NETMON_DIR))
