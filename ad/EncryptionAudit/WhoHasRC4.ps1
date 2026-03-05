# Define the bitmask once to avoid constant function calls
$ETypeMap = @{
    1  = "DES_CBC_CRC"
    2  = "DES_CBC_MD5"
    4  = "RC4"
    8  = "AES128"
    16 = "AES256"
}

# Use -ResultSetSize if testing, or use a SearchBase to be more surgical
$Objects = Get-ADObject -Filter 'objectClass -eq "computer" -or objectClass -eq "user"' `
           -Properties msDS-SupportedEncryptionTypes, LastLogonDate

$Report = foreach ($Obj in $Objects) {
    $Value = $Obj.'msDS-SupportedEncryptionTypes'
    
    # Logic: If Null, it's actually at risk because it uses defaults
    if ($null -eq $Value) {
        $Status = "Legacy/Default (Potentially RC4)"
        $IsSecure = $false
    } else {
        # Bitwise comparison is faster and more accurate than string matching
        $HasRC4 = ($Value -band 4) -eq 4
        $HasAES = ($Value -band 24) -ne 0
        $Status = if ($HasRC4) { "Insecure (RC4 Enabled)" } else { "Modern (AES)" }
        $IsSecure = (-not $HasRC4 -and $HasAES)
    }

    [PSCustomObject]@{
        Name       = $Obj.Name
        Type       = $Obj.ObjectClass
        RawValue   = $Value
        Status     = $Status
        IsSecure   = $IsSecure
    }
}

$Report | Out-GridView
