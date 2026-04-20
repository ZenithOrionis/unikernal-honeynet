# Unikernel Honeynet

This repository implements a narrow, demo-friendly honeynet:

- 1 HTTP decoy app packaged as a Unikraft-compatible unikernel workload
- 3 local unikernel instances with different identities and bait pages
- 1 central Flask collector with SQLite storage
- 1 lightweight dashboard and offline HTML report generator
- 1 attack simulation script for reproducible demo traffic
- 1 Docker baseline that behaves similarly for comparison

## Architecture

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

## Project layout

```text
unikernel-honeynet/
├── README.md
├── docs/
├── unikernel-decoy/
├── collector/
├── dashboard/
├── scripts/
└── container-baseline/
```

## Implementation notes

The unikernel workload is implemented as a small C HTTP server and packaged on top of the Unikraft `base:latest` runtime using a `Kraftfile` `v0.6` plus a root filesystem `Dockerfile`. That keeps the application code small and portable while still letting `kraft run` manage multiple local KVM-backed instances with port publishing.

The launch script defaults each unikernel instance to sending events to `http://10.0.2.2:5000/event`, which is the usual host-side address from QEMU user-mode networking. If your setup differs, override `COLLECTOR_URL` before launching.

## Quick start

These steps are intended for Ubuntu on bare metal or WSL2 with nested virtualization enabled.

1. Prepare the host:

   ```bash
   bash scripts/setup_host.sh
   ```

2. Install Python dependencies:

   ```bash
   python3 -m venv .venv
   . .venv/bin/activate
   pip install -r collector/requirements.txt -r container-baseline/requirements.txt
   ```

3. Start the collector:

   ```bash
   python collector/app.py
   ```

4. Build the Unikraft workload:

   ```bash
   bash scripts/build_unikernel.sh
   ```

5. Launch the three unikernel instances:

   ```bash
   bash scripts/launch_instances.sh
   ```

6. Generate demo traffic:

   ```bash
   bash scripts/attack_sim.sh
   ```

7. Generate an offline report:

   ```bash
   python dashboard/report.py
   ```

8. Bring up the Docker baseline:

   ```bash
   docker compose -f container-baseline/docker-compose.yml up --build -d
   ```

## Demo flow

1. Start the collector and open `http://localhost:5000/`.
2. Launch the three unikernels on `8081`, `8082`, and `8083`.
3. Run `scripts/attack_sim.sh` to populate the collector.
4. Generate `dashboard/output/report.html`.
5. Start the Docker baseline on `8090` and compare startup, logging ease, and reset workflow.

## Current limitations

- The honeypots are deliberately low-interaction.
- The current unikernel packaging path depends on Docker/BuildKit to turn the root filesystem `Dockerfile` into an initramfs.
- The repository can be edited from Windows, but the actual Unikraft runtime flow needs Linux plus KVM support.

