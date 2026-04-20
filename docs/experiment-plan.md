# Experiment Plan

## Objective

Demonstrate that a small unikernel-based honeynet can expose believable low-interaction HTTP bait, centralize telemetry, and be reset quickly for repeated demos.

## Scenarios

### Scenario 1: Benign browsing

- `GET /`
- `GET /login`

Expected outcome: normal hits appear in the collector with non-suspicious tags.

### Scenario 2: Credential guessing

- repeated `POST /login` requests with common username/password pairs

Expected outcome: login attempts are stored with credentials, source, and decoy identity.

### Scenario 3: Scanner-like behavior

- `GET /admin`
- `GET /config`
- `GET /.env`
- `GET /phpmyadmin`

Expected outcome: admin and config paths are logged, odd paths are marked suspicious.

### Scenario 4: Injection-like input

- `POST /login` with SQLi-like values
- `POST /login` with XSS-like values

Expected outcome: suspicious pattern matching toggles the `suspicious` flag and tags the event.

## Metrics to capture

- total requests
- requests by decoy
- top source IPs
- top attacked paths
- suspicious request count
- repeated login attempts
- startup time comparison against the Docker baseline

## Evidence to collect

- terminal output from `kraft --version`
- KVM check output
- screenshots of collector dashboard
- generated `dashboard/output/report.html`
- simple startup and reset timings from `scripts/benchmark.sh`

