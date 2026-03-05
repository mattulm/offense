# --------------------------------------------------------------------------
# Script: Find-GhostMachineCreators.ps1
# Description: Identifies computer accounts created by users via their 
#              ms-DS-MachineAccountQuota (the 'CreatorSID').
# --------------------------------------------------------------------------

Write-Host "Scanning for user-created 'Ghost' computer accounts..." -ForegroundColor Cyan

# Fetch all computers that have a CreatorSID populated
$Computers = Get-ADComputer -Filter 'mS-DS-CreatorSID -like "*"' -Properties mS-DS-CreatorSID, WhenCreated

if ($null -eq $Computers) {
    Write-Host "[+] No user-created computer accounts found. Excellent." -ForegroundColor Green
    return
}

$GhostReport = foreach ($Computer in $Computers) {
    $SID = $Computer.'mS-DS-CreatorSID'
    
    # Try to resolve the SID of the person who created the machine
    try {
        $Creator = (New-Object System.Security.Principal.SecurityIdentifier($SID)).Translate([System.Security.Principal.NTAccount])
    } catch {
        $Creator = "Unknown / Deleted Account ($SID)"
    }

    [PSCustomObject]@{
        ComputerName = $Computer.Name
        CreatedDate  = $Computer.WhenCreated
        CreatorName  = $Creator
        CreatorSID   = $SID
    }
}

# Filter out common false positives (like Domain Admins if they use their personal accounts)
# But honestly, in a tight environment, even those should be reviewed.
$GhostReport | Sort-Object CreatedDate -Descending | Out-GridView -Title "User-Created Ghost Machines"

Write-Host "`n[!] Review the 'CreatorName' column. If you see standard users owning computer accounts, those are your targets." -ForegroundColor Yellow
