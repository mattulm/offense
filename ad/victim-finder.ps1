# 1. Get the current user's Token Groups (This handles nested group membership)
Write-Host "[*] Identifying all Group SIDs for current user..." -ForegroundColor Cyan
$CurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$TargetSIDs = @($CurrentIdentity.User.Value) # Start with the User's own SID

foreach ($GroupSid in $CurrentIdentity.Groups) {
    $TargetSIDs += $GroupSid.Value
}
Write-Host "[+] Found $($TargetSIDs.Count) unique SIDs (User + Groups)." -ForegroundColor Green

# 2. Setup ADSI Searcher for Computers
$DomainDN = ([ADSI]"LDAP://RootDSE").defaultNamingContext
$Searcher = [ADSISearcher]"(&(objectCategory=computer)(objectClass=computer))"
$Searcher.PageSize = 1000
$Searcher.PropertiesToLoad.Add("nTSecurityDescriptor")
$Searcher.PropertiesToLoad.Add("name")
$Searcher.PropertiesToLoad.Add("distinguishedName")

# GUID for msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD attribute)
$RBCDGUID = "3f78c3e5-fec4-41ad-a0af-2c1746c0e983"

try {
    $Computers = $Searcher.FindAll()
    Write-Host "[*] Auditing $($Computers.Count) computers for delegation write-access..." -ForegroundColor Cyan

    $FoundTargets = 0

    foreach ($Entry in $Computers) {
        $ComputerName = $Entry.Properties["name"][0]
        $DN = $Entry.Properties["distinguishedname"][0]
        
        # Get the Binary Security Descriptor and convert to usable object
        $sdBytes = $Entry.Properties["ntsecuritydescriptor"][0]
        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($sdBytes, 0)
        
        # Iterate through the Discretionary Access Control List (DACL)
        foreach ($Ace in $sd.DiscretionaryAcl) {
            # Check if any of our SIDs (User or Group) match the ACE
            if ($TargetSIDs -contains $Ace.SecurityIdentifier.Value) {
                
                # Check for WriteProperty (0x20) or GenericWrite (0x4) or GenericAll (0xf0000)
                $isWrite = ($Ace.AccessMask -band [int][System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -or 
                           ($Ace.AccessMask -band [int][System.DirectoryServices.ActiveDirectoryRights]::GenericWrite) -or
                           ($Ace.AccessMask -band [int][System.DirectoryServices.ActiveDirectoryRights]::GenericAll)

                if ($isWrite) {
                    # If it's an Object-Specific ACE, verify it targets the RBCD attribute GUID
                    $isRBCD = ($Ace.ObjectType -eq [guid]$RBCDGUID) -or ($Ace.ObjectFlags -eq "None")

                    if ($isRBCD) {
                        Write-Host "`n[!] POTENTIAL TARGET: $ComputerName" -ForegroundColor Red
                        Write-Host "    Reason: Your SID $($Ace.SecurityIdentifier.Value) has Write rights." -ForegroundColor Yellow
                        Write-Host "    Object: $DN" -ForegroundColor Gray
                        $FoundTargets++
                        break # Move to next computer once a hit is found
                    }
                }
            }
        }
    }

    Write-Host "`n[*] Scan Complete. Total Targets Found: $FoundTargets" -ForegroundColor Cyan

} catch {
    Write-Host "[-] Error: $($_.Exception.Message)" -ForegroundColor Red
}
