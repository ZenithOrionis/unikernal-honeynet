# Operating Model

## Analyst workflow

1. Watch `Posture`
   - identify silent sensors
   - review severity load
   - review recommended blocks
2. Open `Detections`
   - validate severity and confidence
   - move detections into `triaging`, `confirmed`, `suppressed`, or `closed`
   - read recommended action and evidence summary
3. Pivot to `Investigations`
   - group activity by source IP or campaign fingerprint
   - determine whether activity looks opportunistic or targeted
4. Act from `Exports`
   - generate IOC/blocklist artifacts
   - generate evidence packages for IR
   - generate management summary for stakeholders

## Fleet operations

- `Fleet` is the source for sensor posture
- healthy, degraded, and silent states are heartbeat-driven
- silent sensors reduce coverage and surface as posture warnings
- relay backlog and runtime mismatches are surfaced as operator-visible issues

## Containment model

This version does not directly program firewalls or WAFs. Instead it creates auditable blocklist artifacts that can be handed off or imported into customer containment workflows.
