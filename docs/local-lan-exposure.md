# Local LAN Exposure

This guide exposes the local WSL-hosted decoys to other devices on the same Wi-Fi/Ethernet network so they can be discovered with tools such as `nmap`.

Use this only on a trusted lab network. The goal is to expose the fake decoy services, not the control plane.

## What Gets Exposed

The script exposes only these decoy ports:

```text
8081 -> router decoy
8082 -> NVR decoy
8083 -> admin decoy
```

These stay private to the local machine unless you expose them separately:

```text
5000 -> FastAPI control plane
5173 -> analyst UI
5432 -> PostgreSQL
9000/9001 -> MinIO
5001 -> edge relay
```

## Start The Platform

From normal PowerShell:

```powershell
cd C:\Users\Saphiya\Downloads\Unikernel
docker compose -f deploy/dev/docker-compose.yml up -d --build
wsl.exe -d Ubuntu -u root -- sh -lc "systemctl restart honeynet-edge-relay honeynet-decoy@router honeynet-decoy@nvr honeynet-decoy@admin"
```

Wait for the decoys to boot:

```powershell
wsl.exe -d Ubuntu -u root -- bash -lc "sleep 75"
```

## Expose Decoys To The LAN

Open PowerShell as Administrator and run:

```powershell
cd C:\Users\Saphiya\Downloads\Unikernel
powershell -ExecutionPolicy Bypass -File scripts\expose_decoys_lan.ps1
```

The script creates Windows `netsh portproxy` entries that listen on `0.0.0.0:8081-8083` and forward to the current WSL IP. It also creates a Windows Firewall rule for TCP ports `8081-8083` on the Private network profile.

## Scan From Another Device

On another device connected to the same LAN, run:

```bash
nmap -sV -p 8081,8082,8083 <WINDOWS_LAN_IP>
```

You can also test with:

```bash
curl http://<WINDOWS_LAN_IP>:8081/
curl http://<WINDOWS_LAN_IP>:8082/
curl http://<WINDOWS_LAN_IP>:8083/
```

## Verify From Windows

```powershell
netsh interface portproxy show v4tov4
Get-NetFirewallRule -DisplayName "Enterprise Honeynet Decoys"
```

## Turn LAN Exposure Off

Open PowerShell as Administrator and run:

```powershell
cd C:\Users\Saphiya\Downloads\Unikernel
powershell -ExecutionPolicy Bypass -File scripts\hide_decoys_lan.ps1
```

## Notes

WSL IP addresses can change after a reboot or `wsl --shutdown`. Re-run `scripts\expose_decoys_lan.ps1` after WSL restarts.

If another device cannot scan the ports, make sure Windows is on a Private network profile and that the other device is on the same subnet.
