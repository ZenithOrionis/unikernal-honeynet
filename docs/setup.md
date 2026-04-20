# Setup

## Target host

Use Ubuntu with KVM support. If you are on Windows, use WSL2 with nested virtualization enabled before attempting to run the unikernel instances.

## Required software

- `qemu-kvm`
- `qemu-system-x86`
- `cpu-checker`
- `python3`, `python3-venv`, `python3-pip`
- `git`
- `curl`
- `jq`
- `sqlite3`
- `docker.io`
- KraftKit (`kraft`)

## Recommended bootstrap

Run:

```bash
bash scripts/setup_host.sh
```

That script installs the packages above, installs KraftKit using the official installer, verifies `/dev/kvm`, checks `kraft --version`, and prints host information.

## Python environment

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r collector/requirements.txt -r container-baseline/requirements.txt
```

## BuildKit note

The unikernel workload uses a `Dockerfile` as its root filesystem source. KraftKit can turn that into an initramfs, but the smoothest path is to have a BuildKit daemon available. The build script will try to start a `buildkitd` container automatically if Docker is present.

## Launch order

1. Start the collector:

   ```bash
   python collector/app.py
   ```

2. Build the unikernel workload:

   ```bash
   bash scripts/build_unikernel.sh
   ```

3. Launch the three decoys:

   ```bash
   bash scripts/launch_instances.sh
   ```

4. Drive attack traffic:

   ```bash
   bash scripts/attack_sim.sh
   ```

5. Generate the offline report:

   ```bash
   python dashboard/report.py
   ```

## Collector reachability

The launch script defaults `COLLECTOR_URL` to `http://10.0.2.2:5000/event`. If your local networking uses a different host-side address, export a new value before running `scripts/launch_instances.sh`:

```bash
export COLLECTOR_URL=http://192.168.122.1:5000/event
```

