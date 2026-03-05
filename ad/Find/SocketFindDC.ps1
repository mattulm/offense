# 1. Grab the domain from the current process environment
$CurrentDomain = $env:USERDNSDOMAIN
if (-not $CurrentDomain) { Write-Error "No domain found."; return }

$SrvQuery = "_ldap._tcp.dc._msdcs.$CurrentDomain"
$TimeoutMS = 1000  # 1 second timeout (adjust for network latency)

# 2. Resolve the SRV records
Resolve-DnsName -Name $SrvQuery -Type SRV -ErrorAction SilentlyContinue | ForEach-Object {
    $Target = $_.Target
    # Resolve the target to an IP (A record)
    $IP = (Resolve-DnsName $Target -Type A -ErrorAction SilentlyContinue).IPAddress | Select-Object -First 1
    
    if ($IP) {
        # 3. Create a .NET TCP Socket
        $TcpClient = New-Object System.Net.Sockets.TcpClient
        $Connect = $TcpClient.BeginConnect($IP, 389, $null, $null)
        
        # Wait for the connection or timeout
        $Wait = $Connect.AsyncWaitHandle.WaitOne($TimeoutMS, $false)
        
        if (-not $Wait) {
            $IsOpen = $false
        } else {
            # Check if the connection actually succeeded
            try {
                $TcpClient.EndConnect($Connect)
                $IsOpen = $true
            } catch {
                $IsOpen = $false
            }
        }
        
        # Cleanup
        $TcpClient.Close()
        $TcpClient.Dispose()

        # 4. Output the results as a clean object
        [PSCustomObject]@{
            DC        = $Target
            IP        = $IP
            LDAP_389  = $IsOpen
            Domain    = $CurrentDomain
        }
    }
} | Format-Table -AutoSize
