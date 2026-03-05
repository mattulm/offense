# Enumerating DCs via the current Domain context (Zero Dependencies)
$Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$Domain.DomainControllers | Select-Object Name, IPAddress, SiteName
