# 1. Automatically bind to the Root of the Current Domain
$DomainDN = ([ADSI]"LDAP://RootDSE").defaultNamingContext
$DomainRoot = [ADSI]"LDAP://$DomainDN"

try {
    # 2. Refresh the cache for the specific attribute
    $DomainRoot.RefreshCache(@("ms-DS-MachineAccountQuota"))
    
    # 3. Extract the value
    $Quota = $DomainRoot."ms-DS-MachineAccountQuota".Value

    Write-Host "--- Domain Configuration Audit ---" -ForegroundColor Cyan
    Write-Host "Attribute: ms-DS-MachineAccountQuota"
    
    if ($null -eq $Quota) {
        # If the attribute is null, it defaults to 10 in most functional levels
        Write-Host "[!] Value is NULL (Defaulting to 10)" -ForegroundColor Yellow
        $Quota = 10
    }

    if ($Quota -gt 0) {
        Write-Host "[!] VULNERABLE: Quota is set to $Quota." -ForegroundColor Red
        Write-Host "    Impact: Any Authenticated User can create $Quota machine accounts." -ForegroundColor Gray
    } else {
        Write-Host "[+] SECURE: Quota is set to 0." -ForegroundColor Green
        Write-Host "    Impact: Standard users cannot join new machines to the domain." -ForegroundColor Gray
    }

} catch {
    Write-Host "[-] Error: Could not read domain attributes. $($_.Exception.Message)" -ForegroundColor Red
}
