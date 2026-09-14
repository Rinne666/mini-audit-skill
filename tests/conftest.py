"""Pytest configuration: add the runtime package to sys.path so tests can
import `runtime.<module>` directly without an editable install.

Usage from the skill root:

    python -m pytest tests/unit -q

This works because:

* The runtime package is at <skill>/runtime/
* tests/ lives at <skill>/tests/
* We insert the parent of `tests/` (= skill root) onto sys.path.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

# Make sure tests don't accidentally write outside tmp dirs
os.environ.setdefault("MINI_AUDIT_NO_NET", "1")
os.environ.setdefault("MINI_AUDIT_SANITIZED", "1")