from __future__ import annotations

import time

from ingest_api.database import session_scope
from ingest_api.services import materialize_detections, reconcile_expected_fleet, refresh_fleet_health


def main() -> int:
    while True:
        with session_scope() as db:
            reconcile_expected_fleet(db)
            refresh_fleet_health(db)
            processed = materialize_detections(db, limit=500)
        time.sleep(1 if processed else 5)


if __name__ == "__main__":
    raise SystemExit(main())
