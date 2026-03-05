# 1. Get the Domain Distinguished Name automatically
$DomainDN = ([ADSI]"LDAP://RootDSE").defaultNamingContext

# 2. Path to the Built-in 'Pre-Windows 2000' group
# Note: This group is always in the 'Builtin' container
$GroupPath = "LDAP://CN=Pre-Windows 2000 Compatible Access,CN=Builtin,$DomainDN"

try {
    $Group = [ADSI]$GroupPath
    
    # Check if the object actually exists (handles different language locales if needed)
    if ($null -eq $Group.Name) { 
        Write-Host "[-] Could not bind to the group. Check permissions or path." -ForegroundColor Red
        return
    }

    Write-Host "[*] Checking members of: $($Group.distinguishedName)" -ForegroundColor Cyan

    $isFound = $false
    # 'member' attribute contains the DNs of direct members
    foreach ($memberDN in $Group.member) {
        # S-1-5-11 is the Well-Known SID for Authenticated Users
        # We check for the string name or the SID-based DN if it's resolved
        if ($memberDN -like "*S-1-5-11*" -or $memberDN -like "*Authenticated Users*") {
            $isFound = $true
            Write-Host "[!] Found: Authenticated Users is a member!" -ForegroundColor Red
        } else {
            Write-Host "[.] Other Member: $memberDN" -ForegroundColor Gray
        }
    }

    if (-not $isFound) {
        Write-Host "[+] Authenticated Users not explicitly found in member list." -ForegroundColor Green
    }

} catch {
    Write-Host "[-] Error: $($_.Exception.Message)" -ForegroundColor Red
}
