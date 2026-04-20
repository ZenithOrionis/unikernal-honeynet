# Unikernel decoy notes

## Packaging choice

This decoy is implemented as a small C HTTP server and packaged on top of the Unikraft `base:latest` runtime using a `Dockerfile` root filesystem. That keeps the application code simple while still letting `kraft` manage the workload as a local unikernel instance.

## Runtime configuration

Each instance can be varied with environment variables at `kraft run` time:

- `DECOY_PROFILE`
- `DECOY_ID`
- `DECOY_TITLE`
- `DECOY_HOSTNAME`
- `DECOY_LABEL`
- `COLLECTOR_URL`
- `HTTP_PORT`
- `ASSET_DIR`

## Supported endpoints

- `GET /`
- `GET /login`
- `POST /login`
- `GET /admin`
- `GET /config`
- `GET /status`

## Suspicious markers

The request parser flags the following markers:

- `union select`
- `<script>`
- `../`
- `wget`
- `curl`
- `cmd=`
- `.env`
- `phpmyadmin`

## Local networking assumption

The default collector URL is `http://10.0.2.2:5000/event`, which is commonly reachable from guests running behind QEMU user-mode networking. If your host uses a different reachable address, override `COLLECTOR_URL` before launch.

