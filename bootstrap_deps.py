from __future__ import annotations

import sys
from pathlib import Path


def ensure_local_deps(start: str | Path) -> None:
    current = Path(start).resolve()

    for root in [current] + list(current.parents):
        deps_dir = root / ".pydeps"
        if deps_dir.is_dir():
            deps_path = str(deps_dir)
            if deps_path not in sys.path:
                sys.path.insert(0, deps_path)
            return

