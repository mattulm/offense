# Define the bitmask for AES (128 + 256)
$AES_Mask = 24 

# Query all relevant security principals (Users, Computers, GSAs)
Write-Host "Starting AD Security Audit: Searching for objects missing AES bits..." -ForegroundColor Cyan

$Results = Get-ADObject -Filter 'ObjectClass -eq "user" -or ObjectClass -eq "computer" -or ObjectClass -eq "msDS-GroupManagedServiceAccount"' `
    -Properties msDS-SupportedEncryptionTypes, LastLogonDate, PasswordLastSet, DistinguishedName | ForEach-Object {
    
    $RawValue = $_."msDS-SupportedEncryptionTypes"
    
    # Check if the AES bits (8 or 16) are present
    # We use -band (Bitwise AND) to see if the 24 bitmask is satisfied
    $HasAES = if ($null -ne $RawValue) { ($RawValue -band $AES_Mask) -ne 0 } else { $false }

    if (-not $HasAES) {
        [PSCustomObject]@{
            Name           = $_.Name
            Category       = $_.ObjectClass
            EncryptionRaw  = if ($null -eq $RawValue) { 0 } else { $RawValue }
            LastLogon      = $_.LastLogonDate
            PasswordAge    = (Get-Date) - $_.PasswordLastSet
            DistinguishedName = $_.DistinguishedName
            SecurityRisk   = if ($null -eq $RawValue) { "CRITICAL: Default/Legacy (Null Value)" } else { "HIGH: RC4/DES Only" }
        }
    }
}

# Output to a sortable grid for immediate analysis
if ($Results) {
    $Results | Sort-Object Category | Out-GridView -Title "AD Objects Missing AES Encryption Bits"
    Write-Host "Audit Complete. Found $($Results.Count) objects missing AES." -ForegroundColor Yellow
} else {
    Write-Host "Audit Complete. No objects missing AES found. Your environment is looking solid." -ForegroundColor Green
}
