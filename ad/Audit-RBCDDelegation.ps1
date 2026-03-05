# --------------------------------------------------------------------------
# Script: Audit-RBCDDelegation.ps1
# Description: Audits the domain for computer accounts with Resource-Based 
#              Constrained Delegation (RBCD) configured.
# Author: Python Security Coder
# --------------------------------------------------------------------------

# Ensure the AD Module is available
if (!(Get-Module -ListAvailable ActiveDirectory)) {
    Write-Error "The ActiveDirectory module is required. Please install RSAT."
    return
}

Write-Host "Starting Audit of msDS-AllowedToActOnBehalfOfOtherIdentity..." -ForegroundColor Cyan

# Fetch all computers where the attribute is NOT null
$TargetMachines = Get-ADComputer -Filter 'msDS-AllowedToActOnBehalfOfOtherIdentity -like "*"' `
                  -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

if ($null -eq $TargetMachines) {
    Write-Host "[+] No machines found with RBCD entries. Your domain looks clean for this specific vector." -ForegroundColor Green
    return
}

$Results = foreach ($Machine in $TargetMachines) {
    # The attribute is stored as a Security Descriptor (Binary)
    $SD = New-Object System.Security.AccessControl.RawSecurityDescriptor($Machine.'msDS-AllowedToActOnBehalfOfOtherIdentity', 0)
    
    # We are specifically looking for the SIDs in the Discretionary ACL
    foreach ($Ace in $SD.DiscretionaryAcl) {
        $DelegatedSid = $Ace.SecurityIdentifier.Value
        
        # Resolve the SID to a name if possible
        try {
            $Account = (New-Object System.Security.Principal.SecurityIdentifier($DelegatedSid)).Translate([System.Security.Principal.NTAccount])
        } catch {
            $Account = "Unknown / Deleted Account"
        }

        [PSCustomObject]@{
            TargetMachine  = $Machine.Name
            DelegatedSID   = $DelegatedSid
            DelegatedName  = $Account
            DistinguishedName = $Machine.DistinguishedName
        }
    }
}

# Output results to table and CSV for record keeping
$Results | Tool-Table
$Results | Export-Csv -Path "./RBCD_Audit_Results.csv" -NoTypeInformation

Write-Host "`n[!] Audit complete. Results saved to RBCD_Audit_Results.csv" -ForegroundColor Yellow
