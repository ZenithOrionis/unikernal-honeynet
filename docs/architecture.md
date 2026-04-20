# Architecture

## Final shape

```text
[attacker traffic / test scripts]
              |
        host port mappings
     8081    8082    8083
       |       |       |
     UK-1    UK-2    UK-3
       \       |       /
        \      |      /
         [collector API]
               |
        [SQLite + raw JSON]
               |
      [dashboard + reports]
```

## Components

### Module A: Host environment

Installs QEMU/KVM, KraftKit, Python, Docker, and helper tools. It also checks whether KVM is usable before you try to run the unikernel workloads.

### Module B: Unikernel decoy service

Implements a tiny HTTP service in C with these endpoints:

- `GET /`
- `GET /login`
- `POST /login`
- `GET /admin`
- `GET /config`
- `GET /status`

It always returns fake content, but logs attacker-like behavior and forwards structured JSON to the collector.

### Module C: Instance configuration

The same workload is launched three times with different runtime environment variables:

- `DECOY_PROFILE`
- `DECOY_ID`
- `DECOY_TITLE`
- `DECOY_HOSTNAME`
- `DECOY_LABEL`

This makes each instance present a different fake identity without needing three separate codebases.

### Module D: Launch/orchestration

The launch script uses `kraft run` with distinct instance names and host port mappings:

- `uk-router` on `8081:80`
- `uk-nvr` on `8082:80`
- `uk-admin` on `8083:80`

### Module E: Collector

The collector is a small Flask service with:

- `POST /event`
- `GET /health`
- `GET /stats`
- `GET /`

It writes normalized events to SQLite and keeps the raw JSON for later evidence and debugging.

### Module F: Dashboard/reporting

There are two ways to view results:

- a live Flask dashboard in the collector
- an offline HTML report generated from SQLite

### Module G: Attack simulator

The simulator drives benign requests, login attempts, path probes, and simple injection-like payloads so demos are reproducible.

### Module H: Container baseline

A small Flask app exposes the same bait endpoints in Docker on port `8090`, then sends the same JSON event shape to the collector.

## Data flow

1. A user or script sends HTTP traffic to one of the decoys.
2. The decoy serves believable fake content.
3. The decoy normalizes request metadata into a JSON event.
4. The decoy posts the event to the collector.
5. The collector stores the event in SQLite.
6. The dashboard and report generator query SQLite for summaries.

