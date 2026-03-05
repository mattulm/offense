# --------------------------------------------------------------------------
# Script: Audit-ActiveGhostMachines.ps1
# Description: Correlates user-created computer accounts with their 
#              last authentication activity.
# --------------------------------------------------------------------------

Write-Host "Hunting for Active 'Ghost' Machines..." -ForegroundColor Cyan

# Define the threshold for "Stale" (e.g., 90 days)
$StaleThreshold = (Get-Date).AddDays(-90)

# Fetch computers created by users with logon and OS data
$GhostMachines = Get-ADComputer -Filter 'mS-DS-CreatorSID -like "*"' `
                 -Properties mS-DS-CreatorSID, LastLogonDate, OperatingSystem, IPv4Address

if (!$GhostMachines) {
    Write-Host "[+] No user-created computer accounts found." -ForegroundColor Green
    return
}

$Report = foreach ($Computer in $GhostMachines) {
    $SID = $Computer.'mS-DS-CreatorSID'
    
    # Resolve the Creator
    try {
        $Creator = ([System.Security.Principal.SecurityIdentifier]$SID).Translate([System.Security.Principal.NTAccount])
    } catch {
        $Creator = "Deleted/Unknown ($SID)"
    }

    # Determine Status
    $Status = "Inactive/Stale"
    if ($Computer.LastLogonDate -gt $StaleThreshold) { $Status = "ACTIVE / RECENT" }
    if ($null -eq $Computer.LastLogonDate) { $Status = "NEVER LOGGED ON" }

    [PSCustomObject]@{
        ComputerName   = $Computer.Name
        Status         = $Status
        LastLogon      = $Computer.LastLogonDate
        Creator        = $Creator
        OS             = $Computer.OperatingSystem
        IPAddress      = $Computer.IPv4Address
    }
}

# Output to an interactive window for sorting
$Report | Sort-Object LastLogon -Descending | Out-GridView -Title "Active Ghost Machine Audit"

Write-Host "[!] Review the 'ACTIVE / RECENT' machines. If a standard user created them, investigate immediately." -ForegroundColor Yellow
