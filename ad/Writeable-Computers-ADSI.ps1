# 1. Identify current compromised user SID
$Currentuser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$UserSID = $CurrentUser.User.Value
Write-Host "[*] Searching for victims accessible by SID: $UserSID" -ForegroundColor Cyan

# 2. Setup ADSI Searcher for Computers
$DomainDN = ([ADSI]"LDAP://RootDSE").defaultNamingContext
$Searcher = [ADSISearcher]"(&(objectCategory=computer)(objectClass=computer))"
$Searcher.PageSize = 1000

# GUID for the specific attribute msDS-AllowedToActOnBehalfOfOtherIdentity
$RBCDGUID = "3f78c3e5-fec4-41ad-a0af-2c1746c0e983"

try {
    $Computers = $Searcher.FindAll()
    Write-Host "[*] Auditing $($Computers.Count) computers..."

    foreach ($Entry in $Computers) {
        $Computer = $Entry.GetDirectoryEntry()
        $ComputerName = $Computer.name
        
        # Get the Security Descriptor
        $nTSecurityDescriptor = $Computer.ObjectSecurity
        $Rules = $nTSecurityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

        foreach ($Rule in $Rules) {
            # Check if the rule applies to our compromised user SID
            if ($Rule.IdentityReference.Value -eq $UserSID) {
                
                # We are looking for GenericAll, GenericWrite, or specific WriteProperty
                $IsWrite = ($Rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -or 
                           ($Rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)

                if ($IsWrite) {
                    # Check if the write permission is restricted to the RBCD GUID
                    if ($Rule.ObjectType.ToString() -eq $RBCDGUID -or $Rule.ObjectType.ToString() -eq "00000000-0000-0000-0000-000000000000") {
                        Write-Host "[!] TARGET FOUND: $ComputerName" -ForegroundColor Red
                        Write-Host "    Permission: $($Rule.ActiveDirectoryRights)" -ForegroundColor Yellow
                        Write-Host "    DN: $($Computer.distinguishedName)" -ForegroundColor Gray
                    }
                }
            }
        }
    }
} catch {
    Write-Host "[-] Error during scan: $($_.Exception.Message)" -ForegroundColor Red
}
