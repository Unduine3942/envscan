# ---------------------------------------------------------------------------
# 30-findings: conclusions drawn from probe data. Severity, title and
# recommendation come from spec/findings.toml; each check writes the detail.
# A finding that depends on something being absent only fires when the probes
# that would have found it completed (status ok or not_found).
# ---------------------------------------------------------------------------

$script:ES_FINDING_CHECKS = @(
    'Get-EsExecFindings', 'Get-EsTlsFindings', 'Get-EsPackageFindings', 'Get-EsNetworkFindings',
    'Get-EsResourceFindings', 'Get-EsFsFindings', 'Get-EsUserFindings', 'Get-EsPlatformFindings', 'Get-EsScanFindings'
)
# Host suffixes from spec/configs.toml public_hosts (shared with the sh scanner).
$script:ES_PUBLIC_REGISTRY_RE = '(?i)(^|\.)(' + (ConvertTo-EsAlternation $script:ES_PUBLIC_HOSTS) + ')\z'

function New-EsFinding([string]$Id, [string]$Detail, [object[]]$Evidence) {
    $spec = $script:ES_FINDINGS[$Id]
    if (-not $spec) { Write-EsLog ('unknown finding id ' + $Id); return $null }
    return @{
        __order = @('id', 'severity', 'title', 'detail', 'recommendation', 'evidence')
        id = $Id; severity = [string]$spec.severity; title = [string]$spec.title; recommendation = [string]$spec.recommendation
        detail = (Protect-EsValue $Detail); evidence = @($Evidence)
    }
}

function Test-EsCompleted([string[]]$Ids) {
    # Completed: ok, not_found, or not_applicable (a probe that does not apply has nothing to find).
    foreach ($id in $Ids) { if (@('ok', 'not_found', 'not_applicable') -notcontains (Get-EsStatus $id)) { return $false } }
    return $true
}

function Test-EsHasFacts([string[]]$Ids) {
    # The probe ran and looked: ok or not_found. A not_applicable probe published no facts, so a
    # rule that concludes from a missing value (no default route, no writable folder) stays silent.
    foreach ($id in $Ids) { if (@('ok', 'not_found') -notcontains (Get-EsStatus $id)) { return $false } }
    return $true
}

function Join-EsShort([object[]]$Items, [int]$Max = 4) {
    $list = @($Items | Where-Object { $_ })
    $text = (@($list | Select-Object -First $Max) -join '; ')
    if ($list.Count -gt $Max) { $text += ('; +' + ($list.Count - $Max) + ' more') }
    return $text
}

function Get-EsPersistentPolicy([hashtable]$Policies) {
    # Execution policy without the process scope (the launcher may set that for this run only);
    # $null when no scope could be read. Defaults: PowerShell 6+ and Windows Server 2012 R2+
    # RemoteSigned, Windows clients Restricted.
    if ($null -eq $Policies) { return $null }
    $known = $false
    foreach ($scope in @('MachinePolicy', 'UserPolicy', 'CurrentUser', 'LocalMachine')) {
        if (-not $Policies.ContainsKey($scope)) { continue }
        $known = $true
        $value = [string]$Policies[$scope]
        if ($value -and $value -ne 'Undefined') { return $value }
    }
    if (-not $known) { return $null }
    if ($script:ES_PS_MAJOR -ge 6) { return 'RemoteSigned' }
    $productType = (Get-EsData 'os.identity')['product_type']
    if ($productType -and [int]$productType -ne 1 -and $script:ES_PS_MAJOR -ge 4) { return 'RemoteSigned' }
    return 'Restricted'
}

function Get-EsExecFindings {
    if (-not $script:ES_FULL_LANGUAGE) { New-EsFinding 'exec.ps_constrained' ('Language mode: ' + $script:ES_LANGUAGE_MODE) @('shell.info') }
    $enforced = @((Get-EsData 'sec.app_control')['enforced'] | Where-Object { $_ })
    if ($enforced.Count -gt 0) { New-EsFinding 'exec.app_control' (Join-EsShort $enforced) @('sec.app_control') }
    $shell = Get-EsData 'shell.info'
    if ($shell['execution_policy']) {
        $persistent = Get-EsPersistentPolicy $shell['execution_policy']
        if (@('Restricted', 'AllSigned') -contains $persistent) {
            $source = $(if ($shell['policy_from_gpo']) { 'set by Group Policy' } else { 'local setting or OS default' })
            New-EsFinding 'exec.policy_restricted' ('Execution policy ' + $persistent + ' (' + $source + ')') @('shell.info')
        }
    }
    if ($shell['cmd_disabled'] -and @(1, 2) -contains [int]$shell['cmd_disabled']) {
        New-EsFinding 'exec.cmd_disabled' ('DisableCMD = ' + $shell['cmd_disabled']) @('shell.info')
    }
}

function Test-EsVerifyOff([string]$Text) {
    return ($Text -match '(?i)(strict-ssl|sslverify|ssl_verify|ssl-verify|verify_ssl|http\.sslverify)\s*[=:]\s*"?(false|0|no)\b' -or $Text -match '(?i)\btrusted-host\b')
}

function Get-EsTlsFindings {
    $trust = Get-EsData 'tls.trust'
    $roots = @($trust['enterprise_roots'])
    if ($roots.Count -gt 0 -and $roots[0]) {
        $runtime = $trust['runtime_trust']
        $configured = @()
        if ($runtime) { $configured = @($runtime.PSBase.Keys | Where-Object { $_ -match '(?i)CA_CERTS|CA_BUNDLE|CERT_FILE|CERT_DIR|SSL_CAINFO' }) }
        $note = $(if ($configured.Count -gt 0) { 'runtime CA variables set: ' + ($configured -join ', ') } else { 'no runtime CA variable is set' })
        $backend = @((Get-EsData 'pkg.sources')['git_config'] | Where-Object { $_ -and [string]$_['key'] -eq 'http.sslbackend' } | ForEach-Object { [string]$_['value'] }) | Select-Object -Last 1
        if ($backend) { $note += ('; git http.sslbackend=' + $backend) }
        $names = @($roots | ForEach-Object { if ([string]$_ -match 'CN=([^,]+)') { $matches[1] } else { [string]$_ } })
        New-EsFinding 'tls.enterprise_ca' ([string]$roots.Count + ' added root(s): ' + (Join-EsShort $names 3) + '; ' + $note) @('tls.trust', 'pkg.sources')
    }
    if ($trust.ContainsKey('root_auto_update') -and $trust['root_auto_update'] -eq $false) {
        New-EsFinding 'tls.offline_pki' 'Root certificate auto-update is disabled by policy (DisableRootAutoUpdate=1)' @('tls.trust')
    }
    $evidence = @()
    $runtime = $trust['runtime_trust']
    if ($runtime) {
        if ([string]$runtime['NODE_TLS_REJECT_UNAUTHORIZED'] -eq '0') { $evidence += 'NODE_TLS_REJECT_UNAUTHORIZED=0' }
        if ($runtime.ContainsKey('GIT_SSL_NO_VERIFY')) { $evidence += 'GIT_SSL_NO_VERIFY is set' }
        if ([string]$runtime['PYTHONHTTPSVERIFY'] -eq '0') { $evidence += 'PYTHONHTTPSVERIFY=0' }
    }
    $sources = Get-EsData 'pkg.sources'
    foreach ($config in @($sources['configs'])) {
        if (-not $config) { continue }
        foreach ($line in @($config['lines'])) { if (Test-EsVerifyOff ([string]$line)) { $evidence += ([string]$config['tool'] + ': ' + ([string]$line).Trim()) } }
    }
    foreach ($item in @($sources['git_config'])) {
        if ($item -and (Test-EsVerifyOff ([string]$item['key'] + '=' + [string]$item['value']))) { $evidence += ('git: ' + $item['key'] + '=' + $item['value']) }
    }
    if ($evidence.Count -gt 0) { New-EsFinding 'tls.verification_disabled' (Join-EsShort $evidence) @('tls.trust', 'pkg.sources') }
}

function Get-EsInternalHosts {
    $hosts = @()
    foreach ($url in @((Get-EsData 'pkg.sources')['endpoints'])) {
        $endpoint = ConvertTo-EsEndpoint ([string]$url) ''
        if ($endpoint -and $endpoint.host -notmatch $script:ES_PUBLIC_REGISTRY_RE -and $hosts -notcontains $endpoint.host) { $hosts += $endpoint.host }
    }
    return $hosts
}

function Get-EsPackageFindings {
    $internal = @(Get-EsInternalHosts)
    if ($internal.Count -gt 0) { New-EsFinding 'pkg.mirror' (Join-EsShort $internal 5) @('pkg.sources') }
    $caches = @((Get-EsData 'pkg.caches')['caches'] | Where-Object { $_ })
    if ($caches.Count -gt 0) {
        New-EsFinding 'pkg.offline_cache' (Join-EsShort @($caches | ForEach-Object { [string]$_['tool'] + ' (' + [string]$_['entries'] + ' entries)' }) 6) @('pkg.caches')
    }
    $proxy = Get-EsData 'net.proxy'
    if ($internal.Count -eq 0 -and $caches.Count -eq 0 -and -not $proxy['any_proxy'] -and (Test-EsCompleted @('pkg.sources', 'pkg.caches', 'net.proxy'))) {
        New-EsFinding 'pkg.no_source' 'No proxy, internal registry or dependency cache is configured for this user; without direct internet access, package installs will fail' @('pkg.sources', 'pkg.caches', 'net.proxy')
    }
}

function Get-EsNetworkFindings {
    $proxy = Get-EsData 'net.proxy'
    if ($proxy['any_proxy']) {
        $parts = @($proxy['proxy_endpoints'] | Where-Object { $_ } | ForEach-Object { [string]$_['host'] + ':' + [string]$_['port'] + ' (' + [string]$_['source'] + ')' })
        if ($proxy['wininet'] -and $proxy['wininet']['pac_url']) { $parts += ('PAC ' + $proxy['wininet']['pac_url']) }
        New-EsFinding 'net.proxy_configured' (Join-EsShort $parts) @('net.proxy')
    }
    $wininet = $proxy['wininet']
    $winhttp = $proxy['winhttp']
    if ($wininet -and $winhttp -and ($wininet['enabled'] -or $wininet['pac_url']) -and $winhttp['direct']) {
        New-EsFinding 'net.proxy_user_only' 'WinINET/PAC proxy is set for this user; WinHTTP is direct' @('net.proxy')
    }
    $routes = Get-EsData 'net.routes'
    if ((Test-EsHasFacts @('net.routes')) -and [int]$routes['default_route_count'] -eq 0) {
        New-EsFinding 'net.no_route' 'No default route' @('net.routes')
    }
    $excluded = @((Get-EsData 'net.ports')['common_ports_excluded'] | Where-Object { $_ })
    if ($excluded.Count -gt 0) { New-EsFinding 'net.excluded_ports' ('Excluded: ' + ($excluded -join ', ')) @('net.ports') }
    $used = @((Get-EsData 'net.listening')['common_ports_in_use'] | Where-Object { $_ })
    if ($used.Count -gt 0) { New-EsFinding 'net.ports_in_use' ('In use: ' + ($used -join ', ')) @('net.listening') }
}

function Get-EsResourceFindings {
    $memory = Get-EsData 'hw.memory'
    if ($null -ne $memory['available_mb'] -and [long]$memory['available_mb'] -lt [long]$script:ES_THRESHOLDS['memory_min_mb']) {
        New-EsFinding 'limits.memory_low' ([string]$memory['available_mb'] + ' MB available of ' + [string]$memory['total_mb'] + ' MB') @('hw.memory')
    }
    $low = @()
    foreach ($volume in @((Get-EsData 'hw.storage')['volumes'])) {
        if (-not $volume -or $volume['kind'] -ne 'local' -or $null -eq $volume['free_mb']) { continue }
        if ([long]$volume['free_mb'] -lt [long]$script:ES_THRESHOLDS['disk_free_min_mb']) { $low += ([string]$volume['mount'] + ' ' + [string]$volume['free_mb'] + ' MB free') }
    }
    if ($low.Count -gt 0) { New-EsFinding 'fs.low_disk' (Join-EsShort $low) @('hw.storage') }
}

function Get-EsFsFindings {
    $semantics = Get-EsData 'fs.semantics'
    if ($semantics.ContainsKey('long_paths_enabled') -and $semantics['long_paths_enabled'] -eq $false) {
        New-EsFinding 'fs.long_paths_disabled' 'LongPathsEnabled is 0 or missing' @('fs.semantics')
    }
    if ($semantics['symlink'] -and $semantics['symlink'] -ne 'ok') {
        $mode = $(if ((Get-EsData 'user.identity')['developer_mode']) { 'Developer Mode on' } else { 'Developer Mode off' })
        New-EsFinding 'fs.symlinks_unavailable' ('Symbolic link test: ' + $semantics['symlink'] + ' (' + $mode + ')') @('fs.semantics', 'user.identity')
    }
    if ($semantics.ContainsKey('case_sensitive') -and $semantics['case_sensitive'] -eq $false) {
        New-EsFinding 'fs.case_insensitive' 'Temp directory is case-insensitive (Windows default)' @('fs.semantics')
    }
    $locations = Get-EsData 'fs.locations'
    if ((Test-EsHasFacts @('fs.locations')) -and @($locations['writable_install_locations'] | Where-Object { $_ }).Count -eq 0) {
        New-EsFinding 'fs.no_writable_install_dir' 'None of LOCALAPPDATA, LOCALAPPDATA\Programs, ProgramData, the profile or the system drive root accepts new files' @('fs.locations')
    }
}

function Get-EsUserFindings {
    $identity = Get-EsData 'user.identity'
    if ($identity['is_admin'] -eq $true) { New-EsFinding 'user.is_admin' 'The scanning process is elevated' @('user.identity') }
    $userProfile = Get-EsData 'user.profile'
    $reasons = @()
    if ($userProfile['profile_type'] -and $userProfile['profile_type'] -ne 'local') { $reasons += ('profile type ' + $userProfile['profile_type']) }
    $redirected = $userProfile['redirected_folders']
    if ($redirected -and $redirected.PSBase.Count -gt 0) { $reasons += ('redirected: ' + (@($redirected.PSBase.Keys | Sort-Object) -join ', ')) }
    if ($userProfile['fslogix'] -and $userProfile['fslogix']['enabled']) { $reasons += 'FSLogix profile container' }
    if ($reasons.Count -gt 0) { New-EsFinding 'user.profile_nonpersistent' (Join-EsShort $reasons) @('user.profile') }
    $network = @()
    if ($userProfile['home_network']) { $network += 'home or HOMESHARE is on a network share' }
    if ($userProfile['appdata_network']) { $network += 'APPDATA is on a network share' }
    $synced = @()
    if ($userProfile['onedrive']) { $synced = @($userProfile['onedrive']['folders_in_onedrive'] | Where-Object { $_ }) }
    if ($synced.Count -gt 0) { $network += ('in OneDrive: ' + ($synced -join ', ')) }
    if ($network.Count -gt 0) { New-EsFinding 'user.home_network' (Join-EsShort $network) @('user.profile') }
    $locale = Get-EsData 'os.time_locale'
    if ($locale['codepage_ansi'] -and $locale['codepage_ansi'] -ne '65001') {
        New-EsFinding 'locale.non_utf8' ('ANSI code page ' + $locale['codepage_ansi'] + ', OEM ' + $locale['codepage_oem'] + ', console ' + $locale['codepage_console']) @('os.time_locale')
    }
    if ($locale['decimal_separator'] -eq ',') { New-EsFinding 'locale.decimal_comma' ('Locale ' + $locale['locale'] + ' uses a decimal comma') @('os.time_locale') }
}

function Get-EsArchMismatches {
    $osArch = [string](Get-EsData 'os.identity')['arch']
    $items = @()
    $tools = (Get-EsData 'tools.inventory')['tools']
    if ($tools) {
        foreach ($id in @($tools.PSBase.Keys | Sort-Object)) {
            $tool = $tools[$id]
            # py.exe is a 32-bit launcher by design; it starts interpreters of any architecture.
            if (-not $tool['found'] -or $tool['cat'] -ne 'runtime' -or -not $tool['binary_arch'] -or $id -eq 'py') { continue }
            $arch = [string]$tool['binary_arch']
            if (($osArch -eq 'x86_64' -and $arch -eq 'x86') -or ($osArch -eq 'arm64' -and $arch -ne 'arm64')) { $items += ($id + ' is ' + $arch) }
        }
    }
    foreach ($jdk in @((Get-EsData 'runtime.java')['jdks'])) {
        if ($jdk -and $jdk['arch'] -and (($osArch -eq 'x86_64' -and $jdk['arch'] -eq 'x86') -or ($osArch -eq 'arm64' -and $jdk['arch'] -ne 'arm64'))) {
            $items += ('Java ' + $jdk['version'] + ' is ' + $jdk['arch'])
        }
    }
    if ((Get-EsData 'os.identity')['wow64_process']) { $items += 'the scanner itself ran as a 32-bit process' }
    return $items
}

function Get-EsPlatformFindings {
    $mismatch = @(Get-EsArchMismatches)
    if ($mismatch.Count -gt 0) { New-EsFinding 'arch.mismatch' ('OS is ' + (Get-EsData 'os.identity')['arch'] + '; ' + (Join-EsShort $mismatch)) @('tools.inventory', 'runtime.java', 'os.identity') }
    $health = Get-EsData 'os.health'
    if ($health['pending_reboot']) { New-EsFinding 'os.pending_reboot' ('Pending: ' + (@($health['pending_reasons']) -join ', ')) @('os.health') }
    $identity = Get-EsData 'os.identity'
    $legacy = @()
    if ([string]$identity['build'] -match '^(\d+)') {
        $build = [int]$matches[1]
        $server = ($identity['product_type'] -and [int]$identity['product_type'] -ne 1)
        if (($server -and $build -lt 17763) -or (-not $server -and $build -lt 19044)) { $legacy += ([string]$identity['name'] + ' build ' + $identity['build']) }
    }
    if ($script:ES_PS_MAJOR -lt 3) { $legacy += ('PowerShell ' + $PSVersionTable.PSVersion) }
    $updates = (Get-EsData 'os.updates')['legacy_updates']
    if ($updates) { foreach ($name in @($updates.PSBase.Keys)) { if (-not $updates[$name]) { $legacy += ('not listed as installed: ' + $name) } } }
    if ($legacy.Count -gt 0) { New-EsFinding 'os.legacy' (Join-EsShort $legacy) @('os.identity', 'os.updates') }
    $virt = Get-EsData 'virt.platform'
    if ($virt['container'] -and $virt['container']['detected']) { New-EsFinding 'container.detected' ('Engine: ' + $virt['container']['engine']) @('virt.platform') }
    $session = Get-EsData 'session.context'
    if (@('service', 'ssh') -contains [string]$session['type']) {
        New-EsFinding 'session.headless' ('Session type ' + $session['type']) @('session.context')
    }
    if ((Get-EsStatus 'runtime.python') -eq 'not_found') { New-EsFinding 'runtime.python_absent' 'No Python interpreter (Store aliases do not count)' @('runtime.python') }
    $shims = @()
    $tools = (Get-EsData 'tools.inventory')['tools']
    if ($tools) { $shims = @($tools.PSBase.Keys | Where-Object { [string]$tools[$_]['reason'] -match 'shim' } | Sort-Object) }
    if ($shims.Count -gt 0) { New-EsFinding 'runtime.shims_not_run' ('Not run: ' + (Join-EsShort $shims 8)) @('tools.inventory', 'runtime.version_managers') }
    $crypto = Get-EsData 'sec.crypto'
    if ($crypto['fips']) { New-EsFinding 'crypto.fips' 'FipsAlgorithmPolicy Enabled = 1' @('sec.crypto') }
    $weak = Get-EsWeakDotnetTls
    if ($weak) { New-EsFinding 'crypto.weak_dotnet_tls' $weak @('runtime.dotnet', 'sec.crypto') }
}

function Get-EsWeakDotnetTls {
    # Concludes from a missing SchUseStrongCrypto value, so sec.crypto must have completed.
    if (-not (Test-EsHasFacts @('sec.crypto'))) { return '' }
    $dotnet = Get-EsData 'runtime.dotnet'
    $strong = (Get-EsData 'sec.crypto')['dotnet_strong_crypto']
    if (-not $strong) { $strong = @{} }
    $issues = @()
    $release = $null
    if ($dotnet['framework']) { $release = $dotnet['framework']['release'] }
    $v4 = $strong['v4.0.30319']
    $v4Strong = ($v4 -and ([string]$v4['SchUseStrongCrypto'] -eq '1' -or [string]$v4['SystemDefaultTlsVersions'] -eq '1'))
    if ($null -ne $release -and [int]$release -lt 460798 -and -not $v4Strong) { $issues += ('.NET Framework ' + $dotnet['framework']['version'] + ' without SchUseStrongCrypto') }
    $v2 = $strong['v2.0.50727']
    $v2Strong = ($v2 -and ([string]$v2['SchUseStrongCrypto'] -eq '1' -or [string]$v2['SystemDefaultTlsVersions'] -eq '1'))
    if (@($dotnet['framework_legacy']) -contains 'v3.5' -and -not $v2Strong) { $issues += '.NET 3.5 apps without SchUseStrongCrypto' }
    return (Join-EsShort $issues)
}

function Get-EsScanFindings {
    $incomplete = @($script:ES_RESULTS.PSBase.Keys | Where-Object { @('partial', 'denied', 'timeout', 'error') -contains $script:ES_RESULTS[$_].status } | Sort-Object)
    if ($incomplete.Count -gt 0) { New-EsFinding 'scan.partial' ([string]$incomplete.Count + ' probe(s): ' + (Join-EsShort $incomplete 8)) $incomplete }
}

function Get-EsFindings {
    $all = @()
    foreach ($check in $script:ES_FINDING_CHECKS) {
        try { $all += @(& $check | Where-Object { $_ -is [hashtable] }) }
        catch { Write-EsLog ('finding check ' + $check + ' failed: ' + $_.Exception.Message) }
    }
    $ordered = @()
    foreach ($severity in @('blocker', 'warning', 'info')) { $ordered += @($all | Where-Object { $_.severity -eq $severity }) }
    return $ordered
}
