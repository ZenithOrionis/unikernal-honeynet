from __future__ import annotations

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from bootstrap_deps import ensure_local_deps

ensure_local_deps(__file__)

import uvicorn


def main() -> int:
    uvicorn.run("ingest_api.main:app", host="0.0.0.0", port=5000, reload=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

