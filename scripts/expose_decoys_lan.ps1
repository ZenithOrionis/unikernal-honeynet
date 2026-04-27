param(
    [string]$Distro = "Ubuntu",
    [int[]]$Ports = @(8081, 8082, 8083),
    [string]$ListenAddress = "0.0.0.0",
    [string]$FirewallRuleName = "Enterprise Honeynet Decoys"
)

$ErrorActionPreference = "Stop"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an Administrator PowerShell window. Windows portproxy and firewall changes require elevation."
    }
}

function Get-WslIp {
    param(
        [string]$TargetDistro
    )

    $ip = (wsl.exe -d $TargetDistro -- sh -lc "hostname -I | cut -d ' ' -f1").Trim()
    if (-not $ip) {
        throw "Could not determine the WSL IP for distro '$TargetDistro'."
    }

    return $ip
}

function Get-LanIpCandidates {
    Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object {
            $_.IPAddress -notlike "127.*" -and
            $_.IPAddress -notlike "169.254.*" -and
            $_.IPAddress -ne "0.0.0.0" -and
            $_.PrefixOrigin -ne "WellKnown"
        } |
        Select-Object -ExpandProperty IPAddress -Unique
}

function Ensure-PortProxyRule {
    param(
        [string]$TargetIp,
        [int]$Port,
        [string]$TargetListenAddress
    )

    & netsh interface portproxy delete v4tov4 listenport=$Port listenaddress=$TargetListenAddress | Out-Null
    & netsh interface portproxy add v4tov4 listenport=$Port listenaddress=$TargetListenAddress connectport=$Port connectaddress=$TargetIp | Out-Null
}

function Ensure-FirewallRule {
    param(
        [string]$RuleName,
        [int[]]$TargetPorts
    )

    Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule `
        -DisplayName $RuleName `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort $TargetPorts `
        -Profile Private `
        -Description "Allows LAN devices to reach Enterprise Honeynet decoy ports." | Out-Null
}

Assert-Administrator

$wslIp = Get-WslIp -TargetDistro $Distro

foreach ($port in $Ports) {
    Ensure-PortProxyRule -TargetIp $wslIp -Port $port -TargetListenAddress $ListenAddress
}

Ensure-FirewallRule -RuleName $FirewallRuleName -TargetPorts $Ports

$lanIps = @(Get-LanIpCandidates)
$portList = ($Ports -join ",")

Write-Host "LAN exposure enabled for Enterprise Honeynet decoys."
Write-Host "WSL distro: $Distro"
Write-Host "WSL target IP: $wslIp"
Write-Host "Windows listen address: $ListenAddress"
foreach ($port in $Ports) {
    Write-Host ("  0.0.0.0:{0} -> {1}:{0}" -f $port, $wslIp)
}

Write-Host ""
Write-Host "Windows Firewall rule:"
Write-Host "  $FirewallRuleName, TCP ports $portList, Private profile"

if ($lanIps.Count -gt 0) {
    Write-Host ""
    Write-Host "From another device on the same LAN, test with:"
    foreach ($lanIp in $lanIps) {
        Write-Host "  nmap -sV -p $portList $lanIp"
        foreach ($port in $Ports) {
            Write-Host ("  curl http://{0}:{1}/" -f $lanIp, $port)
        }
    }
} else {
    Write-Host ""
    Write-Host "No LAN IPv4 address was detected. Check your active Wi-Fi/Ethernet adapter."
}

Write-Host ""
Write-Host "Keep the control plane private. This script exposes only the decoy ports, not the API/dashboard/database."
