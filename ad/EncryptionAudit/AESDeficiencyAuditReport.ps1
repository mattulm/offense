# Parameters for the audit
$ExportPath = "$HOME\Desktop\AD_AES_Gaps_Report.csv"
$AES_Mask = 24 # Bitmask for AES128 (8) + AES256 (16)

Write-Host "Gathering AD objects missing AES support. This may take a moment..." -ForegroundColor Cyan

$Gaps = Get-ADObject -Filter 'ObjectClass -eq "user" -or ObjectClass -eq "computer" -or ObjectClass -eq "msDS-GroupManagedServiceAccount"' `
    -Properties msDS-SupportedEncryptionTypes, LastLogonDate, PasswordLastSet, Description, DistinguishedName, msDS-UserPasswordExpiryTimeComputed | ForEach-Object {
    
    $RawValue = $_."msDS-SupportedEncryptionTypes"
    
    # Bitwise check: Does it have 8 or 16 set?
    $HasAES = if ($null -ne $RawValue) { ($RawValue -band $AES_Mask) -ne 0 } else { $false }

    if (-not $HasAES) {
        # Determine the "Risk Level" for the report
        $Risk = if ($null -eq $RawValue) { "Critical: Legacy Defaults" } else { "High: No AES bits set" }
        
        # Calculate password age - crucial because AES keys aren't generated until a password reset
        $PassAgeDays = if ($_.PasswordLastSet) { ((Get-Date) - $_.PasswordLastSet).Days } else { "N/A" }

        [PSCustomObject]@{
            ObjectName      = $_.Name
            ObjectClass     = $_.ObjectClass
            RiskLevel       = $Risk
            RawBitmask      = if ($null -eq $RawValue) { 0 } else { $RawValue }
            PasswordAgeDays = $PassAgeDays
            LastLogon       = $_.LastLogonDate
            Description     = $_.Description
            DistinguishedName = $_.DistinguishedName
            ParentOU        = ($_.DistinguishedName -split ',', 2)[1]
        }
    }
}

if ($Gaps) {
    $Gaps | Export-Csv -Path $ExportPath -NoTypeInformation
    Write-Host "Success! Report generated at: $ExportPath" -ForegroundColor Green
    Write-Host "Total objects requiring investigation: $($Gaps.Count)" -ForegroundColor Yellow
} else {
    Write-Host "No AES gaps found. Everyone is modern!" -ForegroundColor Green
}
