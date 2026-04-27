# Deployment Patterns

## Single-site

- one Kubernetes cluster for control plane
- one edge host for decoys and relay
- suitable for labs, pilots, and smaller production environments

## Branch office

- central control plane
- multiple branch edge hosts
- each branch contributes expected fleet members, sites, and coverage roles
- useful for showing coverage gaps by site

## DMZ / segmented edge

- decoys deployed into DMZ or internet-facing network segments
- control plane remains on private infrastructure
- relay handles store-and-forward during transient uplink issues

## Operational defaults

- use deployment inventory as expected fleet source of truth
- keep MinIO and PostgreSQL inside the same trusted environment as the control plane
- use heartbeat freshness plus deployment state to drive fleet health
