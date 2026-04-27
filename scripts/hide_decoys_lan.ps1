param(
    [int[]]$Ports = @(8081, 8082, 8083),
    [string[]]$ListenAddresses = @("0.0.0.0", "127.0.0.1"),
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

Assert-Administrator

foreach ($listenAddress in $ListenAddresses) {
    foreach ($port in $Ports) {
        & netsh interface portproxy delete v4tov4 listenport=$port listenaddress=$listenAddress | Out-Null
    }
}

Get-NetFirewallRule -DisplayName $FirewallRuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule

Write-Host "LAN exposure disabled for Enterprise Honeynet decoys."
Write-Host "Removed portproxy entries for ports: $($Ports -join ', ')"
Write-Host "Removed firewall rule: $FirewallRuleName"
