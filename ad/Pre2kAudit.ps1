# Check for the Active Directory Module
if (!(Get-Module -ListAvailable ActiveDirectory)) {
    Write-Error "The Active Directory module is required. Please install RSAT."
    return
}

$GroupName = "Pre-Windows 2000 Compatible Access"
$TargetPrincipal = "Authenticated Users"

try {
    # Get the group and its members
    $group = Get-ADGroup -Identity $GroupName -Properties Members
    $members = Get-ADGroupMember -Identity $GroupName
    
    Write-Host "--- Audit Report: $GroupName ---" -ForegroundColor Cyan

    $isVulnerable = $false

    foreach ($member in $members) {
        if ($member.Name -eq $TargetPrincipal -or $member.distinguishedName -like "*S-1-5-11*") {
            $isVulnerable = $true
            Write-Host "[!] DANGER: '$TargetPrincipal' is a member of '$GroupName'." -ForegroundColor Red
            Write-Host "    Reason: This allows any domain user to bypass various read-access restrictions." -ForegroundColor Yellow
        }
    }

    if (-not $isVulnerable) {
        Write-Host "[+] Clean: '$TargetPrincipal' was not found in the group." -ForegroundColor Green
    }

} catch {
    Write-Error "Failed to query Active Directory. Ensure you have appropriate permissions. Error: $($_.Exception.Message)"
}
