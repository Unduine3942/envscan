# ---------------------------------------------------------------------------
# 25-probes-network: port reservations, interfaces, routes, DNS, proxy,
# listening ports, netstat (deep), firewall, reachability (net).
# ---------------------------------------------------------------------------

$script:ES_MAX_REACH_TARGETS = 20

function probe_net_ports {
    $r = New-EsResult
    $d = $r.data
    $netsh = Get-EsSystemTool 'netsh.exe'
    $excluded = Invoke-EsTool $r 'excludedportrange tcp' $netsh @('int', 'ipv4', 'show', 'excludedportrange', 'protocol=tcp')
    $ranges = @()
    foreach ($line in @(([string]$excluded.stdout) -split "`n")) {
        if ($line -match '^\s*(\d+)\s+(\d+)(\s+\*)?\s*$') { $ranges += @{ start = [int]$matches[1]; end = [int]$matches[2]; administered = [bool]$matches[3] } }
    }
    $d.excluded_tcp = $ranges
    $dynamic = Invoke-EsTool $r 'dynamicport tcp' $netsh @('int', 'ipv4', 'show', 'dynamicport', 'tcp')
    $numbers = @([regex]::Matches([string]$dynamic.stdout, ':\s*(\d+)') | ForEach-Object { [int]$_.Groups[1].Value })
    $d.ephemeral = $null
    if ($numbers.Count -ge 2) { $d.ephemeral = @{ start = $numbers[0]; end = $numbers[0] + $numbers[1] - 1; count = $numbers[1] } }
    $urlacl = Invoke-EsTool $r 'http urlacl' $netsh @('http', 'show', 'urlacl')
    $urls = @([regex]::Matches([string]$urlacl.stdout, '(?i)\bhttps?://\S+') | ForEach-Object { $_.Value })
    $d.urlacl_count = $urls.Count
    $d.urlacl = @($urls | Select-Object -First 100)
    $d.unprivileged_port_start = $null
    $blocked = @()
    foreach ($port in @($script:ES_THRESHOLDS['common_ports'])) {
        foreach ($range in $ranges) { if ([int]$port -ge $range.start -and [int]$port -le $range.end) { $blocked += [int]$port; break } }
    }
    $d.common_ports_excluded = $blocked
    return $r
}

function probe_net_interfaces {
    $r = New-EsResult
    $configs = @(Add-EsCimItems $r 'Win32_NetworkAdapterConfiguration' 'root/cimv2' 'IPEnabled=TRUE')
    $adapters = @(Add-EsCimItems $r 'Win32_NetworkAdapter' 'root/cimv2' 'NetConnectionID IS NOT NULL')
    $byIndex = @{}
    foreach ($adapter in $adapters) { $byIndex[[string]$adapter.DeviceID] = $adapter }
    $mtu = @{}
    $ipif = Get-EsCimSafe -Class 'MSFT_NetIPInterface' -Namespace 'root/StandardCimv2'
    if ($ipif.status -eq 'ok') {
        $r.sources += 'CIM root/StandardCimv2:MSFT_NetIPInterface (MTU)'
        foreach ($item in $ipif.items) { if ([int]$item.AddressFamily -eq 2) { $mtu[[string]$item.InterfaceIndex] = $item.NlMtu } }
    }
    $r.data.interfaces = @($configs | ForEach-Object {
            $adapter = $byIndex[[string]$_.Index]
            @{
                name = $(if ($adapter) { [string]$adapter.NetConnectionID } else { $null }); description = [string]$_.Description
                addresses = @($_.IPAddress); subnets = @($_.IPSubnet); mac = [string]$_.MACAddress
                mtu = $mtu[[string]$_.InterfaceIndex]; gateways = @($_.DefaultIPGateway | Where-Object { $_ })
                dns = @($_.DNSServerSearchOrder | Where-Object { $_ }); dhcp = [bool]$_.DHCPEnabled
                dns_domain = [string]$_.DNSDomain; dns_suffixes = @($_.DNSDomainSuffixSearchOrder | Where-Object { $_ })
                speed_mbps = $(if ($adapter -and $adapter.Speed) { [long]([uint64]$adapter.Speed / 1000000) } else { $null })
                index = $_.InterfaceIndex
            }
        })
    if ($configs.Count -eq 0 -and $r.status -eq 'ok') { $r.status = 'not_found'; $r.notes += 'no IP-enabled adapter' }
    return $r
}

function probe_net_routes {
    $r = New-EsResult
    $d = $r.data
    $query = Get-EsCimSafe -Class 'MSFT_NetRoute' -Namespace 'root/StandardCimv2'
    $r.sources += 'CIM root/StandardCimv2:MSFT_NetRoute'
    $routes = @()
    $gateways = @()
    $defaults = 0
    # A default route whose next hop is 0.0.0.0 or :: is on-link (common for VPN adapters):
    # it is still a default route, just without a gateway address.
    if ($query.status -eq 'ok') {
        foreach ($route in $query.items) {
            $prefix = [string]$route.DestinationPrefix
            $hop = [string]$route.NextHop
            if ($prefix -eq '0.0.0.0/0' -or $prefix -eq '::/0') {
                $defaults++
                if ($hop -ne '0.0.0.0' -and $hop -ne '::') { $gateways += $hop }
            }
            $routes += ($prefix + ' via ' + $hop + ' if ' + $route.InterfaceIndex + ' metric ' + $route.RouteMetric)
        }
    } else {
        foreach ($route in @(Add-EsCimItems $r 'Win32_IP4RouteTable')) {
            if ([string]$route.Destination -eq '0.0.0.0' -and [string]$route.Mask -eq '0.0.0.0') {
                $defaults++
                if ([string]$route.NextHop -ne '0.0.0.0') { $gateways += [string]$route.NextHop }
            }
            $routes += ([string]$route.Destination + '/' + [string]$route.Mask + ' via ' + [string]$route.NextHop + ' if ' + $route.InterfaceIndex + ' metric ' + $route.Metric1)
        }
    }
    $d.default_route_count = $defaults
    $d.default_gateways = @($gateways | Sort-Object -Unique)
    $d.route_count = $routes.Count
    $d.routes = @($routes | Select-Object -First 200)
    return $r
}

function Get-EsHostsEntries([hashtable]$Result) {
    # The entries of the hosts file: no comments or blank lines, at most 200.
    $hostsPath = Join-Path ([string]$env:SystemRoot) 'System32\drivers\etc\hosts'
    $Result.sources += ('read ' + $hostsPath)
    $hosts = Read-EsTextFile $hostsPath 65536
    Add-EsReadNote $Result $hostsPath $hosts.error 'hosts file'
    return @(([string]$hosts.text) -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') } | Select-Object -First 200)
}

function probe_net_dns {
    $r = New-EsResult
    $d = $r.data
    $interfaces = @((Get-EsData 'net.interfaces')['interfaces'])
    if ($interfaces.Count -eq 0 -or $null -eq $interfaces[0]) {
        $interfaces = @(Add-EsCimItems $r 'Win32_NetworkAdapterConfiguration' 'root/cimv2' 'IPEnabled=TRUE' | ForEach-Object {
                @{ dns = @($_.DNSServerSearchOrder); dns_suffixes = @($_.DNSDomainSuffixSearchOrder) }
            })
    } else { $r.sources += 'net.interfaces (DNS servers and suffixes)' }
    $servers = @()
    $search = @()
    foreach ($item in $interfaces) {
        if (-not $item) { continue }
        $servers += @($item['dns'] | Where-Object { $_ })
        $search += @($item['dns_suffixes'] | Where-Object { $_ })
    }
    $tcpip = Get-EsRegValues 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    $policy = Get-EsRegValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    $r.sources += @('registry HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters (SearchList, Domain)', 'registry HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient')
    if ($tcpip -and $tcpip['SearchList']) { $search += @(([string]$tcpip['SearchList']) -split '[,\s]+' | Where-Object { $_ }) }
    if ($policy -and $policy['SearchList']) { $search += @(([string]$policy['SearchList']) -split '[,\s]+' | Where-Object { $_ }) }
    $d.servers = @($servers | Select-Object -Unique)
    $d.search = @($search | Select-Object -Unique)
    $d.domain = $(if ($tcpip) { [string]$tcpip['Domain'] } else { $null })
    $d.policy = $(if ($policy) { $policy } else { @{} })
    $d.llmnr_disabled = ($policy -and [string]$policy['EnableMulticast'] -eq '0')
    $d.nrpt_rules = @(Get-EsRegSubkeys 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig').Count
    $d.hosts_entries = @(Get-EsHostsEntries $r)
    $d.resolver_order = 'hosts file, DNS (NRPT, suffix search), LLMNR/NetBIOS'
    return $r
}

# ------------------------------------------------------------------ proxy

function Get-EsRegBytes([string]$Path, [string]$Name) {
    try {
        $value = (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name
        if ($value -is [byte[]]) { return , $value }
    } catch { }
    return $null
}

function ConvertFrom-EsProxyBlob($Bytes) {
    # WinHTTP/WinINET connection blob: flags at offset 8, then length-prefixed proxy, exclusion and PAC strings.
    $result = @{ flags = $null; proxy = $null; exclusions = $null; pac_url = $null }
    if ($null -eq $Bytes -or $Bytes.Length -lt 16) { return $result }
    $result.flags = [int]$Bytes[8]
    $offset = 12
    $strings = @()
    for ($n = 0; $n -lt 3; $n++) {
        if ($offset + 4 -gt $Bytes.Length) { break }
        $length = [int]$Bytes[$offset] + 256 * [int]$Bytes[$offset + 1] + 65536 * [int]$Bytes[$offset + 2]
        $offset += 4
        if ($offset + $length -gt $Bytes.Length) { break }
        $chars = @(for ($i = 0; $i -lt $length; $i++) { [char][int]$Bytes[$offset + $i] })
        $strings += (-join $chars)
        $offset += $length
    }
    if ($strings.Count -ge 1 -and $strings[0]) { $result.proxy = $strings[0] }
    if ($strings.Count -ge 2 -and $strings[1]) { $result.exclusions = $strings[1] }
    if ($strings.Count -ge 3 -and $strings[2]) { $result.pac_url = $strings[2] }
    return $result
}

function Get-EsProxyServers([string]$Value) {
    # "host:port" or "http=host:port;https=host:port" -> list of host:port strings.
    if (-not $Value) { return @() }
    return @($Value -split ';' | ForEach-Object { ($_ -replace '^[A-Za-z]+=', '').Trim() } | Where-Object { $_ })
}

function probe_net_proxy {
    $r = New-EsResult
    $d = $r.data
    $d.env = Get-EsEnvSubset $script:ES_PROXY_ENV
    $r.sources += 'environment proxy variables'
    $winhttpKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'
    $r.sources += 'registry HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections (WinHttpSettings)'
    $blob = ConvertFrom-EsProxyBlob (Get-EsRegBytes $winhttpKey 'WinHttpSettings')
    $d.winhttp = @{ proxy = $blob.proxy; exclusions = $blob.exclusions; direct = (-not $blob.proxy); configured = ($null -ne $blob.flags) }
    $userKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $r.sources += 'registry HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings (ProxyEnable, ProxyServer, ProxyOverride, AutoConfigURL, connection flags)'
    $user = Get-EsRegValues $userKey
    if ($null -eq $user) { $user = @{} }
    $connection = ConvertFrom-EsProxyBlob (Get-EsRegBytes ($userKey + '\Connections') 'DefaultConnectionSettings')
    $d.wininet = @{
        enabled = ([string]$user['ProxyEnable'] -eq '1'); server = $user['ProxyServer']; exclusions = $user['ProxyOverride']
        pac_url = $user['AutoConfigURL']
        auto_detect = $(if ($null -ne $connection.flags) { (($connection.flags -band 8) -ne 0) } else { $null })
    }
    $policy = @{}
    foreach ($hive in @('HKLM', 'HKCU')) {
        $r.sources += ('registry ' + $hive + '\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings')
        $values = Get-EsRegValues ($hive + ':\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings')
        if ($values) { $policy[$hive] = Protect-EsTable $values }
    }
    $d.policy = $policy
    $sources = Get-EsData 'pkg.sources'
    $null = Test-EsInputComplete $r 'pkg.sources'
    # The proxy settings pkg.sources found by their names (15-proxy): @{ tool; setting; value; file }.
    $d.package_managers = @()
    if ($sources.PSBase.Count -gt 0) { $d.package_managers = @($script:ES_PKG_PROXY_SETTINGS | Where-Object { $_ }) }
    # Endpoints from raw values (redaction would leave user:<redacted>@ in front of the host).
    $endpoints = @()
    foreach ($name in @($d.env.PSBase.Keys)) { if ($name -notmatch '(?i)\Ano_proxy\z') { $endpoints += ConvertTo-EsEndpoint ([string](Get-EsOrigEnv $name)) ('env ' + $name) } }
    foreach ($server in @(Get-EsProxyServers $d.winhttp.proxy)) { $endpoints += ConvertTo-EsEndpoint $server 'WinHTTP' }
    if ($d.wininet.enabled) { foreach ($server in @(Get-EsProxyServers ([string]$d.wininet.server))) { $endpoints += ConvertTo-EsEndpoint $server 'WinINET' } }
    if ($d.wininet.pac_url) { $endpoints += ConvertTo-EsEndpoint ([string]$d.wininet.pac_url) 'PAC URL' }
    foreach ($item in @($sources['proxy_urls'] | Where-Object { $_ })) { $endpoints += ConvertTo-EsEndpoint ([string]$item['url']) ('config ' + $item['tool']) }
    $d.proxy_endpoints = @($endpoints | Where-Object { $_ })
    # WPAD auto-detect is on by default in Windows, so it alone does not count as a configured proxy.
    $d.any_proxy = ($d.proxy_endpoints.Count -gt 0 -or [bool]$d.wininet.pac_url)
    return $r
}

# ------------------------------------------------------------------ ports, firewall, reachability

function Get-EsProcessNames {
    $names = @{}
    foreach ($process in @(Get-Process -ErrorAction SilentlyContinue)) { $names[[string]$process.Id] = [string]$process.ProcessName }
    return $names
}

function probe_net_listening {
    $r = New-EsResult
    $items = @(Add-EsCimItems $r 'MSFT_NetTCPConnection' 'root/StandardCimv2' 'State=2')
    $names = Get-EsProcessNames
    $r.sources += 'Get-Process (names only)'
    $seen = @{}
    $tcp = @()
    foreach ($item in @($items | Sort-Object { [int]$_.LocalPort })) {
        $key = [string]$item.LocalAddress + '|' + [string]$item.LocalPort
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $tcp += @{ address = [string]$item.LocalAddress; port = [int]$item.LocalPort; pid = [int]$item.OwningProcess; process = $names[[string]$item.OwningProcess] }
    }
    $r.data.tcp = $tcp
    $r.data.ports = @($tcp | ForEach-Object { $_.port } | Sort-Object -Unique)
    $used = @(@($script:ES_THRESHOLDS['common_ports']) | Where-Object { $r.data.ports -contains [int]$_ })
    $r.data.common_ports_in_use = $used
    if ($r.status -ne 'ok' -and $tcp.Count -eq 0) { Add-EsNote $r 'listening ports need Windows 8 / Server 2012 or later without --deep (netstat)' '' }
    return $r
}

function probe_net_netstat {
    $r = New-EsResult
    $run = Invoke-EsTool $r 'netstat -ano' (Get-EsSystemTool 'netstat.exe') @('-ano') 60
    $listening = @()
    foreach ($line in @(([string]$run.stdout) -split "`n")) {
        if ($line -match '^\s*TCP\s+(\S+):(\d+)\s+(0\.0\.0\.0:0|\[::\]:0)\s+\S+\s+(\d+)') {
            $listening += @{ address = $matches[1]; port = [int]$matches[2]; pid = [int]$matches[4] }
        }
    }
    $r.data.tcp_listening = $listening
    return $r
}

function ConvertTo-EsFirewallFlag($Value) {
    switch ([string]$Value) { '1' { return $true } '0' { return $false } 'True' { return $true } 'False' { return $false } }
    return $null
}

function probe_net_firewall {
    $r = New-EsResult
    $actions = @{ '0' = 'not_configured'; '2' = 'allow'; '4' = 'block' }
    $items = @(Add-EsCimItems $r 'MSFT_NetFirewallProfile' 'root/StandardCimv2')
    $r.data.profiles = @($items | ForEach-Object {
            @{ name = [string]$_.Name; enabled = (ConvertTo-EsFirewallFlag $_.Enabled); inbound = $actions[[string][int]$_.DefaultInboundAction]; outbound = $actions[[string][int]$_.DefaultOutboundAction] }
        })
    $policy = @{}
    foreach ($name in @('DomainProfile', 'StandardProfile', 'PublicProfile')) {
        $values = Get-EsRegValues ('HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\' + $name)
        if ($values) { $policy[$name] = @{ EnableFirewall = $values['EnableFirewall']; DefaultInboundAction = $values['DefaultInboundAction']; DefaultOutboundAction = $values['DefaultOutboundAction'] } }
    }
    $r.sources += 'registry HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall (profile values)'
    $r.data.policy = $policy
    return $r
}

$script:ES_IPV4_RE = '\A[0-9]{1,3}(\.[0-9]{1,3}){3}\z'
$script:ES_IPV6_TOKEN_RE = '\A[0-9A-Fa-f]{0,4}(:[0-9A-Fa-f]{0,4}){2,7}(%[0-9A-Za-z]+)?\z'
$script:ES_IPV6_WHY = 'IPv6 address outside the global and unique-local ranges; never contacted'
$script:ES_NO_RESOLVER_WHY = 'no resolver available; names are not contacted'
$script:ES_SINGLE_LABEL_WHY = 'single-label name; DNS search domains could expand it, so it is not looked up'
$script:ES_MALFORMED_WHY = 'malformed host name; not looked up'

$script:ES_PUBLIC_V4_WHY = 'public IPv4 address; never contacted'

function Test-EsIpv4Allowed([string]$Address) {
    # An IPv4 address that may be contacted: private (10/8, 172.16/12, 192.168/16) or shared
    # (100.64/10) only. Every other address (public, loopback, broadcast) fails, and so does any
    # text that is not four decimal octets 0-255 without leading zeros.
    if ($Address -notmatch '\A(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\z') { return $false }
    $o = @([int]$matches[1], [int]$matches[2], [int]$matches[3], [int]$matches[4])
    if (@($o | Where-Object { $_ -gt 255 }).Count -gt 0) { return $false }
    if ($o[0] -eq 10) { return $true }
    if ($o[0] -eq 172) { return ($o[1] -ge 16 -and $o[1] -le 31) }
    if ($o[0] -eq 192) { return ($o[1] -eq 168) }
    if ($o[0] -eq 100) { return ($o[1] -ge 64 -and $o[1] -le 127) }
    return $false
}

function Test-EsIpv6Allowed([string]$Address) {
    # An IPv6 address that may be contacted: first hextet (the text before the first ":", 0 for
    # "::...") 2000-3fff (global unicast) or fc00-fdff (unique local), not in fd00:ec2::/32 (second
    # hextet ec2, leading zeros ignored), no zone id. fe80::/10, ::ffff: mapped, 64:ff9b:: NAT64,
    # loopback and multicast all fail. The same rule as es_ip6_ok in src/sh/28-reach.sh.
    $a = $Address.ToLowerInvariant().TrimStart('[').TrimEnd(']')
    if ($a.Contains('%') -or $a -notmatch '\A[0-9a-f:.]+\z' -or $a.IndexOf(':') -lt 0) { return $false }
    $first = $a.Substring(0, $a.IndexOf(':'))
    if ($first -notmatch '\A[0-9a-f]{1,4}\z') { return $false }
    $value = [int]('0x' + $first)
    if ($value -ge 0x2000 -and $value -le 0x3fff) { return $true }
    if ($value -lt 0xfc00 -or $value -gt 0xfdff) { return $false }
    if ($value -ne 0xfd00) { return $true }
    $second = ([string](@($a.Substring($a.IndexOf(':') + 1) -split ':')[0])).TrimStart('0')
    return ($second -ne 'ec2')
}

function Resolve-EsHostName([string]$HostName) {
    # The addresses of a name as @{ status; addresses; error; method }: status ok (addresses
    # found; a literal address is its own), none (a definitive "no such name" or "no address"),
    # error (a timeout or a failure, error says which) or unavailable (no resolver to ask).
    # A name is looked up in its absolute form (one trailing "." removed, then "." added), so no
    # DNS search suffix or devolution applies; a single-label name is never looked up (skipped).
    # Malformed names and IPv4 literals written with a trailing dot are skipped too
    # (Get-EsNameRefusal): an IP literal never reaches a resolver.
    if ($HostName -match $script:ES_IPV4_RE -or $HostName.Contains(':')) {
        return @{ status = 'ok'; addresses = @($HostName); error = $null; method = 'literal' }
    }
    $refusal = Get-EsNameRefusal $HostName
    if ($refusal) { return @{ status = 'skipped'; addresses = @(); error = $refusal; method = 'none' } }
    $absolute = ($HostName -replace '\.\z', '') + '.'
    if ($script:ES_FULL_LANGUAGE) { return (Resolve-EsHostNameDns $absolute) }
    return (Resolve-EsHostNameNslookup $absolute)
}

function Get-EsNameRefusal([string]$HostName) {
    # Why a host name (not an IPv6 literal) is never looked up, after one trailing "." is
    # removed: an IPv4 literal written with that dot ("10.0.0.1.") is a public IPv4 address for
    # this rule; a name that is empty or starts with "." once that dot is gone, or that holds ".."
    # anywhere as written ("host.."), is malformed; a
    # single label is single-label (Test-EsSingleLabel). $null when the name may be looked up.
    if ($HostName.Contains(':')) { return $null }
    $name = $HostName -creplace '\.\z', ''
    if ($name.Length -lt $HostName.Length -and $name -match $script:ES_IPV4_RE) { return $script:ES_PUBLIC_V4_WHY }
    if ($name.Length -eq 0 -or $name.StartsWith('.') -or $HostName.Contains('..')) { return $script:ES_MALFORMED_WHY }
    if (Test-EsSingleLabel $HostName) { return $script:ES_SINGLE_LABEL_WHY }
    return $null
}

function Test-EsSingleLabel([string]$HostName) {
    # A host name (not an IP literal) without a "." once one trailing "." is removed: "proxy",
    # "proxy.", "localhost". DNS search domains could turn it into another host.
    if ($HostName -match $script:ES_IPV4_RE -or $HostName.Contains(':')) { return $false }
    return (($HostName -replace '\.\z', '').IndexOf('.') -lt 0)
}

function Resolve-EsHostNameDns([string]$HostName) {
    # FullLanguage: the system resolver, at most 3 s. HostNotFound and NoData are definitive.
    $result = @{ status = 'ok'; addresses = @(); error = $null; method = 'dns' }
    try {
        $async = [Net.Dns]::BeginGetHostAddresses($HostName, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(3000, $false)) { $result.status = 'error'; $result.error = 'name lookup timed out'; return $result }
        $result.addresses = @([Net.Dns]::EndGetHostAddresses($async) | ForEach-Object { [string]$_ })
        if ($result.addresses.Count -eq 0) { $result.status = 'none' }
    } catch {
        $inner = $_.Exception
        while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
        $code = ''
        try { $code = [string]$inner.SocketErrorCode } catch { }
        if (@('HostNotFound', 'NoData') -contains $code) { $result.status = 'none' }
        else { $result.status = 'error'; $result.error = 'name lookup failed: ' + $inner.Message }
    }
    return $result
}

function Get-EsNslookupAddresses([string]$Text) {
    # The answer addresses in nslookup output: the IPv4 and IPv6 addresses after the first blank
    # line (the server block, "Server:" and "Address:", comes before it; labels may be localized).
    $addresses = @()
    $answer = $false
    foreach ($line in @($Text -split "`r?`n")) {
        if (-not $answer) { $answer = ($line.Trim().Length -eq 0); continue }
        foreach ($token in @($line.Trim() -split '[\s,]+')) {
            if ($token -match $script:ES_IPV4_RE -or $token -match $script:ES_IPV6_TOKEN_RE) { $addresses += $token }
        }
    }
    return $addresses
}

function Resolve-EsHostNameNslookup([string]$HostName) {
    # ConstrainedLanguage: System32 nslookup (2 s, one retry). Unavailable when it cannot run.
    $result = @{ status = 'unavailable'; addresses = @(); error = $null; method = 'nslookup' }
    $tool = Get-EsSystemTool 'nslookup.exe'
    if (-not (Test-EsSafePath $tool 'Leaf')) { return $result }
    $run = Invoke-EsCommand -FilePath $tool -Arguments @('-timeout=2', '-retry=1', $HostName) -TimeoutSec 8
    if ($null -eq $run.exit_code -and -not $run.timed_out) { $result.error = $run.error; return $result }
    $result.addresses = @(Get-EsNslookupAddresses ([string]$run.stdout))
    $text = [string]$run.stdout + "`n" + [string]$run.stderr
    $result.status = 'error'
    if ($result.addresses.Count -gt 0) { $result.status = 'ok' }
    elseif ($text -match '(?i)Non-existent domain|records available') { $result.status = 'none' }
    elseif ($run.timed_out -or $text -match '(?i)timed[- ]?out') { $result.error = 'name lookup timed out' }
    else { $result.error = ('name lookup failed: ' + ((([string]$run.stderr).Trim() -split "`r?`n")[0])).TrimEnd(': ') }
    return $result
}

function Test-EsTcpPort([string]$Address, [int]$Port, [int]$TimeoutMs) {
    if (-not $script:ES_FULL_LANGUAGE) { return @{ tcp = $null; ms = $null; error = 'TCP checks need FullLanguage mode' } }
    $start = Get-EsUtc
    # The default client is IPv4 only: an IPv6 address needs an IPv6 socket.
    $family = 'InterNetwork'
    if ($Address.Contains(':')) { $family = 'InterNetworkV6' }
    $client = New-Object Net.Sockets.TcpClient ([Net.Sockets.AddressFamily]$family)  # lint-allow: new-object
    try {
        $async = $client.BeginConnect($Address, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return @{ tcp = 'timeout'; ms = $TimeoutMs; error = $null } }
        $client.EndConnect($async)
        return @{ tcp = 'ok'; ms = (Get-EsElapsedMs $start); error = $null }
    } catch {
        $message = $_.Exception.Message
        $state = 'error'
        if ($message -match '(?i)refused|actively') { $state = 'refused' }
        return @{ tcp = $state; ms = (Get-EsElapsedMs $start); error = $message }
    } finally { $client.Close() }
}

function Get-EsReachSkipReason([string]$HostName) {
    # Why a host is never resolved or contacted, or $null. registry.npmjs.org. is registry.npmjs.org.
    $written = $HostName
    $HostName = $HostName -creplace '\.\z', ''
    if (Test-EsNetNever $HostName) { return 'cloud metadata or link-local address; never contacted' }
    if ($HostName -match $script:ES_PUBLIC_REGISTRY_RE) { return 'public registry; only internal mirrors and proxies are checked' }
    $refusal = Get-EsNameRefusal $written
    if ($refusal) { return $refusal }
    if ($HostName.Contains(':') -and -not (Test-EsIpv6Allowed $HostName)) { return $script:ES_IPV6_WHY }
    if ($HostName -match $script:ES_IPV4_RE -and -not (Test-EsIpv4Allowed $HostName)) { return $script:ES_PUBLIC_V4_WHY }
    return $null
}

function New-EsSkippedTarget([hashtable]$Candidate, [string]$Reason) {
    # The shared shape of a target that is not contacted: host, port, source, tcp and reason only.
    return @{ host = $Candidate['host']; port = $Candidate['port']; source = $Candidate['source']; tcp = 'skipped'; reason = $Reason }
}

function Select-EsReachAddress([object[]]$Addresses) {
    # The address to connect to: the first IPv4 address that may be contacted
    # (Test-EsIpv4Allowed), else the first such IPv6 address (Test-EsIpv6Allowed); $null when
    # there is none.
    $v6 = $null
    foreach ($address in @($Addresses)) {
        $text = [string]$address
        if (-not $text.Contains(':')) { if (Test-EsIpv4Allowed $text) { return $text } }
        elseif ($null -eq $v6 -and (Test-EsIpv6Allowed $text)) { $v6 = $text }
    }
    return $v6
}

function Test-EsReachTarget([hashtable]$Candidate) {
    # One endpoint: DNS, then TCP to one vetted address (never to the name, so nothing resolves it
    # twice). Not contacted, and recorded with the shared skipped shape: a name that resolves to
    # a net-never address (DNS rebinding), one with only IPv6 addresses outside the global and
    # unique-local ranges, and any name when no resolver can be asked. A failed lookup gives
    # tcp "error"; only a definitive "no address" gives "unresolved".
    $resolved = Resolve-EsHostName ([string]$Candidate['host'])
    if ($resolved.status -eq 'unavailable') { return (New-EsSkippedTarget $Candidate $script:ES_NO_RESOLVER_WHY) }
    if ($resolved.status -eq 'skipped') { return (New-EsSkippedTarget $Candidate ([string]$resolved.error)) }
    if (@($resolved.addresses | Where-Object { Test-EsNetNever ([string]$_) }).Count -gt 0) {
        return (New-EsSkippedTarget $Candidate 'resolves to a cloud metadata or link-local address; never contacted')
    }
    $target = @{ host = $Candidate['host']; port = $Candidate['port']; source = $Candidate['source']; resolved = @($resolved.addresses)
        tcp = 'unresolved'; ms = $null; error = $resolved.error; reason = $null
    }
    if ($resolved.status -eq 'error') { $target.tcp = 'error'; return $target }
    if ($resolved.status -ne 'ok' -or @($resolved.addresses).Count -eq 0) { $target.error = 'the name has no address'; return $target }
    $address = Select-EsReachAddress @($resolved.addresses)
    if (-not $address) {
        $why = $(if (@($resolved.addresses | Where-Object { -not ([string]$_).Contains(':') }).Count -gt 0) { $script:ES_PUBLIC_V4_WHY } else { $script:ES_IPV6_WHY })
        return (New-EsSkippedTarget $Candidate $why)
    }
    $check = Test-EsTcpPort $address ([int]$Candidate['port']) 3000
    $target.tcp = $check.tcp
    $target.ms = $check.ms
    $target.error = $check.error
    return $target
}

function probe_net_reachability {
    $r = New-EsResult
    $candidates = @(@((Get-EsData 'net.proxy')['proxy_endpoints']) | Where-Object { $_ })
    foreach ($url in @((Get-EsData 'pkg.sources')['endpoints'])) {
        $endpoint = ConvertTo-EsEndpoint ([string]$url) 'package configuration'
        if ($endpoint) { $candidates += $endpoint }
    }
    $seen = @{}
    $targets = @()
    $looked = 0
    $over = 0
    foreach ($candidate in $candidates) {
        $key = ([string]$candidate['host']).ToLowerInvariant() + ':' + [string]$candidate['port']
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $reason = Get-EsReachSkipReason ([string]$candidate['host'])
        if ($reason) { $targets += (New-EsSkippedTarget $candidate $reason); continue }
        # The cap counts the endpoints that are looked up, not the skipped ones.
        if ($looked -ge $script:ES_MAX_REACH_TARGETS) { $over++; continue }
        $looked++
        $r.sources += ('dns + tcp ' + $key)
        $targets += (Test-EsReachTarget $candidate)
    }
    $r.data.targets = $targets
    if ($targets.Count -eq 0) { $r.status = 'not_found'; $r.notes += 'no proxy or mirror endpoint was found in local configuration' }
    foreach ($id in @('net.proxy', 'pkg.sources')) { $null = Test-EsInputComplete $r $id }
    Add-EsReachNotes $r $targets $looked $over
    return $r
}

function Add-EsReachNotes([hashtable]$Result, [object[]]$Targets, [int]$Looked, [int]$Over) {
    # Skips and caps are notes; a target that could not be checked (no resolver, a failed
    # lookup, no TCP test in ConstrainedLanguage) makes the probe partial.
    $skipped = @($Targets | Where-Object { $_.tcp -eq 'skipped' }).Count
    $noResolver = @($Targets | Where-Object { $_.reason -eq $script:ES_NO_RESOLVER_WHY }).Count
    $failed = @($Targets | Where-Object { $_.tcp -eq 'error' -and @($_.resolved).Count -eq 0 }).Count
    if ($skipped -gt 0) { $Result.notes += ([string]$skipped + ' endpoint(s) skipped and never contacted; each target says why') }
    if ($Over -gt 0) { $Result.notes += ([string]$Over + ' more endpoint(s) not checked (at most ' + $script:ES_MAX_REACH_TARGETS + ')') }
    if ($noResolver -gt 0) { Add-EsNote $Result 'no resolver (nslookup) is available: host names were not looked up or contacted' 'partial' }
    if ($failed -gt 0) { Add-EsNote $Result ('the name lookup failed for ' + $failed + ' host(s); they were not contacted') 'partial' }
    if (-not $script:ES_FULL_LANGUAGE -and $Looked -gt $noResolver) { Add-EsNote $Result 'ConstrainedLanguage: names resolved with nslookup, TCP not tested' 'partial' }
}
