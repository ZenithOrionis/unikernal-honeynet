param(
    [string]$Distro = "Ubuntu",
    [int[]]$Ports = @(8081, 8082, 8083),
    [string]$ListenAddress = "127.0.0.1"
)

$ErrorActionPreference = "Stop"

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

function Ensure-PortProxyRule {
    param(
        [string]$TargetIp,
        [int]$Port,
        [string]$TargetListenAddress
    )

    & netsh interface portproxy delete v4tov4 listenport=$Port listenaddress=$TargetListenAddress | Out-Null
    & netsh interface portproxy add v4tov4 listenport=$Port listenaddress=$TargetListenAddress connectport=$Port connectaddress=$TargetIp | Out-Null
}

$wslIp = Get-WslIp -TargetDistro $Distro

foreach ($port in $Ports) {
    Ensure-PortProxyRule -TargetIp $wslIp -Port $port -TargetListenAddress $ListenAddress
}

Write-Host "WSL port proxy updated for distro '$Distro' -> $wslIp"
foreach ($port in $Ports) {
    Write-Host ("  http://{0}:{1} -> http://{2}:{1}" -f $ListenAddress, $port, $wslIp)
}
