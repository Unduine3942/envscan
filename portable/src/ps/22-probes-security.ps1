# ---------------------------------------------------------------------------
# 22-probes-security: application control, crypto policy, antivirus and
# policy hive (deep), trusted roots, Java truststore (deep).
# ---------------------------------------------------------------------------

$script:ES_MITIGATION_EXES = @('node.exe', 'java.exe', 'javaw.exe', 'python.exe', 'pythonw.exe', 'dotnet.exe', 'powershell.exe',
    'pwsh.exe', 'cmd.exe', 'msbuild.exe', 'git.exe', 'code.exe', 'chrome.exe', 'msedge.exe', 'ruby.exe', 'perl.exe', 'go.exe')
$script:ES_BUILTIN_ROOT_RE = '(?i)Microsoft|MSFT|NO LIABILITY ACCEPTED|Thawte Timestamping CA|Symantec Enterprise Mobile Root'
# Policy keys never opened: any key named *Exclusion* (Defender path, process and extension
# exclusions, ASROnlyExclusions, ...), AllowedApplications (Controlled Folder Access), "Policy
# Manager" (the MDM mirror of the Defender policy), Installer, Winlogon and IPSec (stock Windows
# denies it to standard users). Value names never read: Exclu* and *Exclusion*
# (ASROnlyPerRuleExclusions, ...).
$script:ES_POLICY_SKIP_RE = '(?i)\\([^\\]*Exclusion[^\\]*|AllowedApplications|Installer|Winlogon|Policy Manager|IPSec)(\\|\z)'
$script:ES_POLICY_SKIP_VALUE_RE = '(?i)^Exclu|Exclusion'

function ConvertTo-EsEnforcement($Value) {
    if ($null -eq $Value) { return $null }
    switch ([int]$Value) { 0 { return 'off' } 1 { return 'audit' } 2 { return 'enforced' } }
    return [string]$Value
}

function Get-EsAppLocker([hashtable]$Result) {
    $base = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2'
    $Result.sources += 'registry HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2 (AppLocker)'
    $collections = @{}
    $counts = @{}
    foreach ($name in @(Get-EsRegSubkeys $base)) {
        $key = $base + '\' + $name
        $count = @(Get-EsRegSubkeys $key).Count
        $mode = Get-EsRegValue $key 'EnforcementMode'
        $state = 'NoRules'
        if ($count -gt 0) { if ($null -eq $mode -or [int]$mode -eq 1) { $state = 'Enforced' } else { $state = 'AuditOnly' } }
        $collections[$name] = $state
        $counts[$name] = $count
    }
    $enforced = @($collections.PSBase.Keys | Where-Object { $collections[$_] -eq 'Enforced' } | Sort-Object)
    $service = @(Add-EsCimItems $Result 'Win32_Service' 'root/cimv2' "Name='AppIDSvc'") | Select-Object -First 1
    return @{
        configured = ($collections.PSBase.Count -gt 0); collections = $collections; rule_counts = $counts
        enforced_collections = $enforced; identity_service = $(if ($service) { [string]$service.State } else { $null })
    }
}

function Get-EsSaferPolicy([hashtable]$Result) {
    $levels = @{ '0' = 'Disallowed'; '131072' = 'Basic User'; '262144' = 'Unrestricted' }
    $out = $null
    foreach ($hive in @('HKLM', 'HKCU')) {
        $key = $hive + ':\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
        $Result.sources += ('registry ' + $hive + '\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers (SRP)')
        $values = Get-EsRegValues $key
        if ($null -eq $values) { continue }
        $rules = 0
        foreach ($level in @(Get-EsRegSubkeys $key)) {
            foreach ($kind in @('Paths', 'Hashes', 'UrlZones')) { $rules += @(Get-EsRegSubkeys ($key + '\' + $level + '\' + $kind)).Count }
        }
        if ($null -eq $values['DefaultLevel'] -and $rules -eq 0) { continue }
        $default = [string]$values['DefaultLevel']
        $out = @{
            hive = $hive; default_level = $values['DefaultLevel']; default_level_name = $levels[$default]
            transparent_enabled = $values['TransparentEnabled']; policy_scope = $values['PolicyScope']
            executable_types = $values['ExecutableTypes']; rule_count = $rules
            enforced = ($default -eq '0' -or $default -eq '131072')
        }
        break
    }
    return $out
}

function probe_sec_app_control {
    $r = New-EsResult
    $d = $r.data
    $d.applocker = Get-EsAppLocker $r
    $d.srp = Get-EsSaferPolicy $r
    $guard = @(Add-EsCimItems $r 'Win32_DeviceGuard' 'root/Microsoft/Windows/DeviceGuard') | Select-Object -First 1
    $d.wdac = $null
    if ($guard) {
        $d.wdac = @{
            kmci = ConvertTo-EsEnforcement $guard.CodeIntegrityPolicyEnforcementStatus
            umci = ConvertTo-EsEnforcement $guard.UsermodeCodeIntegrityPolicyEnforcementStatus
            vbs = $guard.VirtualizationBasedSecurityStatus
            services_configured = @($guard.SecurityServicesConfigured)
            services_running = @($guard.SecurityServicesRunning)
        }
    }
    $r.sources += 'registry HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy (VerifiedAndReputablePolicyState)'
    $sac = Get-EsRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' 'VerifiedAndReputablePolicyState'
    $d.smart_app_control = $(switch ([string]$sac) { '0' { 'off' } '1' { 'on' } '2' { 'evaluation' } default { $null } })
    $r.sources += 'registry HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel (MitigationOptions)'
    $kernel = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
    $processes = @{}
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\'
    $r.sources += 'registry HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<runtime>.exe (MitigationOptions)'
    foreach ($exe in $script:ES_MITIGATION_EXES) {
        $value = Get-EsRegValue ($ifeo + $exe) 'MitigationOptions'
        if ($null -ne $value) { $processes[$exe] = $value }
    }
    $d.exploit_protection = @{
        system = Get-EsRegValue $kernel 'MitigationOptions'; system_audit = Get-EsRegValue $kernel 'MitigationAuditOptions'
        processes = $processes
    }
    $r.sources += @('registry HKLM\SOFTWARE\Policies\Microsoft\Windows\System (EnableSmartScreen)', 'registry HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments')
    $d.smartscreen = @{
        policy_enabled = Get-EsRegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
        policy_level = Get-EsRegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'ShellSmartScreenLevel'
    }
    $d.attachments_save_zone_information = Get-EsRegValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments' 'SaveZoneInformation'
    $enforced = @()
    if (@($d.applocker.enforced_collections).Count -gt 0) { $enforced += ('AppLocker (' + (@($d.applocker.enforced_collections) -join ', ') + ')') }
    if ($d.srp -and $d.srp.enforced) { $enforced += ('Software Restriction Policies (default ' + $d.srp.default_level_name + ')') }
    if ($d.wdac -and $d.wdac.umci -eq 'enforced') { $enforced += 'WDAC user-mode code integrity' }
    if ($d.smart_app_control -eq 'on') { $enforced += 'Smart App Control' }
    $d.enforced = $enforced
    return $r
}

function probe_sec_crypto {
    $r = New-EsResult
    $d = $r.data
    $r.sources += 'registry HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy (Enabled only)'
    $fips = Get-EsRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' 'Enabled'
    $d.fips = ([string]$fips -eq '1')
    $r.sources += 'registry HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    $d.schannel = Get-EsRegTree 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols' 60
    $strong = @{}
    foreach ($view in @(@('', ''), @('WOW6432Node\', ' (32-bit)'))) {
        foreach ($version in @('v2.0.50727', 'v4.0.30319')) {
            $key = 'HKLM:\SOFTWARE\' + $view[0] + 'Microsoft\.NETFramework\' + $version
            $r.sources += ('registry ' + ($key -replace '^HKLM:', 'HKLM'))
            $values = Get-EsRegValues $key
            if ($null -eq $values) { continue }
            $strong[$version + $view[1]] = @{ SchUseStrongCrypto = $values['SchUseStrongCrypto']; SystemDefaultTlsVersions = $values['SystemDefaultTlsVersions'] }
        }
    }
    $d.dotnet_strong_crypto = $strong
    $winhttp = @{}
    foreach ($view in @(@('', 'native'), @('WOW6432Node\', '32-bit'))) {
        $key = 'HKLM:\SOFTWARE\' + $view[0] + 'Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
        $r.sources += ('registry ' + ($key -replace '^HKLM:', 'HKLM') + ' (DefaultSecureProtocols)')
        $winhttp[$view[1]] = Get-EsRegValue $key 'DefaultSecureProtocols'
    }
    $d.winhttp_default_secure_protocols = $winhttp
    $d.crypto_policy = $null
    $d.openssl_dir = $null
    return $r
}

function Limit-EsTableValues([hashtable]$Table, [int]$MaxLength = 400) {
    $out = @{}
    foreach ($key in @($Table.PSBase.Keys)) {
        $value = $Table[$key]
        if ($value -is [string] -and $value.Length -gt $MaxLength) { $value = $value.Substring(0, $MaxLength) + '...' }
        $out[$key] = $value
    }
    return $out
}

function probe_sec_av {
    $r = New-EsResult
    $d = $r.data
    $query = Get-EsCimSafe -Class 'AntiVirusProduct' -Namespace 'root/SecurityCenter2'
    $r.sources += 'CIM root/SecurityCenter2:AntiVirusProduct'
    if ($query.status -eq 'ok') {
        $d.antivirus = @($query.items | ForEach-Object {
                @{ name = [string]$_.displayName; product_state = ('0x' + ([int]$_.productState).ToString('x6')); path = [string]$_.pathToSignedProductExe }
            })
    } else {
        $d.antivirus = $null
        $productType = (Get-EsData 'os.identity')['product_type']
        if ($productType -and [int]$productType -ne 1) { $r.notes += 'SecurityCenter2 does not exist on Windows Server; antivirus products are not listed' }
        else { Add-EsNote $r ('SecurityCenter2: ' + $query.error) 'partial' }
    }
    $r.sources += 'registry HKLM\SOFTWARE\Policies\Microsoft\Windows Defender (keys named *Exclusion*, AllowedApplications or Policy Manager and values named Exclu* or *Exclusion* are never read)'
    $d.defender_policy = Limit-EsTableValues (Protect-EsTable (Get-EsRegTree 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 200 $script:ES_POLICY_SKIP_RE $script:ES_POLICY_SKIP_VALUE_RE))
    $policies = @{}
    foreach ($hive in @('HKLM', 'HKCU')) {
        $r.sources += ('registry ' + $hive + '\SOFTWARE\Policies (capped; keys named *Exclusion*, AllowedApplications, Policy Manager, Installer, Winlogon or IPSec and values named Exclu* or *Exclusion* are never read)')
        $policies[$hive] = Limit-EsTableValues (Protect-EsTable (Get-EsRegTree ($hive + ':\SOFTWARE\Policies') 600 $script:ES_POLICY_SKIP_RE $script:ES_POLICY_SKIP_VALUE_RE))
    }
    $d.policies = $policies
    return $r
}

# ------------------------------------------------------------------ trusted roots

function Get-EsThumbprintSet([string]$Key) {
    $set = @{}
    foreach ($name in @(Get-EsRegSubkeys $Key)) { $set[$name.ToUpperInvariant()] = $true }
    return $set
}

function Get-EsCertOrigin([string]$Thumbprint, [string]$Subject, [hashtable]$Sets) {
    if ($Sets.group_policy.ContainsKey($Thumbprint)) { return 'group_policy' }
    if ($Sets.enterprise.ContainsKey($Thumbprint)) { return 'enterprise' }
    if ($Sets.authroot.ContainsKey($Thumbprint)) { return 'authroot' }
    if ($Sets.machine.ContainsKey($Thumbprint)) {
        if ($Subject -match $script:ES_BUILTIN_ROOT_RE) { return 'builtin' }
        return 'local'
    }
    return 'unknown'
}

function ConvertTo-EsCertEntry($Cert, [string]$Store, [string]$Origin) {
    return @{
        subject = [string]$Cert.Subject; issuer = [string]$Cert.Issuer; thumbprint = [string]$Cert.Thumbprint
        not_after = (Format-EsUtc ([datetime]$Cert.NotAfter).ToUniversalTime()); store = $Store; origin = $Origin
    }
}

function Get-EsJavaCacerts([string]$JavaHome) {
    if (-not (Test-EsLocalPath $JavaHome)) { return $null }
    foreach ($relative in @('lib\security\cacerts', 'jre\lib\security\cacerts')) {
        $path = Join-Path $JavaHome $relative
        # Below a folder link that is not followed: not tested here, noted by the caller.
        if (Get-EsRefusedFolder $path) { return @{ path = $path; size = $null; modified_utc = $null } }
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $item = Get-Item -LiteralPath $path -Force
            return @{ path = $path; size = [long]$item.Length; modified_utc = (Format-EsUtc $item.LastWriteTimeUtc) }
        }
    }
    return $null
}

function Get-EsRootEntries([hashtable]$Result, [hashtable]$Sets) {
    # Machine roots with their origin, plus the roots added for this user (directly or by policy).
    $roots = @()
    $Result.sources += 'Cert:\LocalMachine\Root'
    try {
        foreach ($cert in @(Get-ChildItem -Path 'Cert:\LocalMachine\Root' -ErrorAction Stop)) {
            $thumb = ([string]$cert.Thumbprint).ToUpperInvariant()
            $roots += ConvertTo-EsCertEntry $cert 'LocalMachine\Root' (Get-EsCertOrigin $thumb ([string]$cert.Subject) $Sets)
        }
    } catch { Add-EsNote $Result ('Cert:\LocalMachine\Root: ' + $_.Exception.Message) 'partial' }
    $Result.sources += 'Cert:\CurrentUser\Root (user-added entries)'
    try {
        foreach ($cert in @(Get-ChildItem -Path 'Cert:\CurrentUser\Root' -ErrorAction Stop)) {
            $thumb = ([string]$cert.Thumbprint).ToUpperInvariant()
            if ($Sets.user_policy.ContainsKey($thumb)) { $roots += ConvertTo-EsCertEntry $cert 'CurrentUser\Root' 'user_group_policy' }
            elseif ($Sets.user.ContainsKey($thumb)) { $roots += ConvertTo-EsCertEntry $cert 'CurrentUser\Root' 'user' }
        }
    } catch { Add-EsNote $Result ('Cert:\CurrentUser\Root: ' + $_.Exception.Message) 'partial' }
    return $roots
}

function probe_tls_trust {
    $r = New-EsResult
    $d = $r.data
    $sets = @{
        group_policy = Get-EsThumbprintSet 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates'
        enterprise = Get-EsThumbprintSet 'HKLM:\SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates'
        authroot = Get-EsThumbprintSet 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates'
        machine = Get-EsThumbprintSet 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates'
        user = Get-EsThumbprintSet 'HKCU:\Software\Microsoft\SystemCertificates\Root\Certificates'
        user_policy = Get-EsThumbprintSet 'HKCU:\Software\Policies\Microsoft\SystemCertificates\Root\Certificates'
    }
    $r.sources += @('registry HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates', 'registry HKLM\SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates',
        'registry HKLM\SOFTWARE\Microsoft\SystemCertificates\{AuthRoot,ROOT}\Certificates (names)', 'registry HKCU\Software\Microsoft\SystemCertificates\Root\Certificates (names)')
    $now = Get-Date
    $roots = @(Get-EsRootEntries $r $sets)
    $added = @('group_policy', 'enterprise', 'local', 'user', 'user_group_policy')
    $enterprise = @($roots | Where-Object { $added -contains $_.origin -and $_.subject -notmatch '^CN=localhost$' })
    $d.roots = $roots
    $d.enterprise_roots = @($enterprise | ForEach-Object { $_.subject } | Sort-Object -Unique)
    $d.enterprise_thumbprints = @($enterprise | ForEach-Object { $_.thumbprint } | Sort-Object -Unique)
    $d.root_count = @($roots | Where-Object { $_.store -eq 'LocalMachine\Root' }).Count
    $d.user_root_count = @($roots | Where-Object { $_.store -eq 'CurrentUser\Root' }).Count
    $d.authroot_count = $sets.authroot.Count
    $d.expired_roots = @($roots | Where-Object { $_.not_after -and $_.not_after -lt (Format-EsUtc $now.ToUniversalTime()) }).Count
    try { $d.intermediate_count = @(Get-ChildItem -Path 'Cert:\LocalMachine\CA' -ErrorAction Stop).Count; $r.sources += 'Cert:\LocalMachine\CA (count)' }
    catch { $d.intermediate_count = $null }
    $r.sources += 'registry HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot (DisableRootAutoUpdate)'
    $disable = Get-EsRegValue 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot' 'DisableRootAutoUpdate'
    $d.root_auto_update = -not ([string]$disable -eq '1')
    $d.runtime_trust = Get-EsEnvSubset $script:ES_TLS_ENV
    $r.sources += 'environment TLS variables'
    $javaHome = Get-EsOrigEnv 'JAVA_HOME'
    $d.java_home_cacerts = Get-EsJavaCacerts $javaHome
    if ($javaHome -and (Test-EsNetworkPath $javaHome)) { Add-EsNote $r 'JAVA_HOME is on a network path; its cacerts was not read' '' }
    elseif ($javaHome) { $r.sources += 'read %JAVA_HOME%\lib\security\cacerts (size and date)' }
    $d.bundles = @()
    $d.custom_anchors = @()
    return $r
}

function probe_tls_java_cacerts {
    $r = New-EsResult
    $d = $r.data
    if (-not (Test-EsDependency $r 'runtime.java')) { return $r }
    $java = Get-EsData 'runtime.java'
    $jdks = @($java['jdks'])
    $javaHome = $null
    foreach ($jdk in $jdks) { if ($jdk -and $jdk['source'] -eq 'JAVA_HOME') { $javaHome = $jdk['path']; break } }
    if (-not $javaHome -and $jdks.Count -gt 0 -and $jdks[0]) { $javaHome = $jdks[0]['path'] }
    if (-not $javaHome) { $r.status = 'not_found'; $r.notes += 'no Java installation found'; return $r }
    $keytool = Join-Path $javaHome 'bin\keytool.exe'
    $cacerts = Get-EsJavaCacerts $javaHome
    if (-not (Test-Path -LiteralPath $keytool -PathType Leaf) -or -not $cacerts) {
        $r.status = 'not_found'; $r.notes += ('keytool or cacerts missing under ' + $javaHome); return $r
    }
    # keytool opens the keystore: a cacerts that is a link off the local disk is not read.
    $link = Get-EsPathLinkReason $cacerts.path
    if ($link) { Add-EsReadNote $r $cacerts.path $link; return $r }
    $noRun = Get-EsNoRunReason @{ id = 'keytool'; mode = 'version' } $keytool
    if ($noRun) { Add-EsNote $r ('keytool not run: ' + $noRun) 'partial'; return $r }
    $run = Invoke-EsCommand -FilePath $keytool -Arguments @('-list', '-v', '-keystore', $cacerts.path, '-storepass', 'changeit') -MaxLines 40000
    $r.sources += ('run ' + $run.command)
    if ($run.timed_out) { $r.status = 'timeout'; return $r }
    $text = Get-EsCommandText $run
    $sha1 = @([regex]::Matches($text, '(?i)\bSHA-?1\s*:\s*((?:[0-9A-F]{2}:){19}[0-9A-F]{2})') | ForEach-Object { $_.Groups[1].Value.Replace(':', '').ToUpperInvariant() })
    $trust = Get-EsData 'tls.trust'
    if (@('ok', 'partial') -notcontains (Get-EsStatus 'tls.trust')) { Add-EsNote $r 'tls.trust did not complete: enterprise roots were not compared' 'partial' }
    $wanted = @(@($trust['enterprise_thumbprints']) | Where-Object { $_ })
    $subjects = @{}
    foreach ($root in @($trust['roots'])) { if ($root) { $subjects[[string]$root['thumbprint']] = [string]$root['subject'] } }
    $d.java_home = $javaHome
    $d.keytool = $keytool
    $d.cacerts = $cacerts
    $d.entries = $sha1.Count
    $d.enterprise_roots_present = @($wanted | Where-Object { $sha1 -contains $_ } | ForEach-Object { $subjects[$_] })
    $d.enterprise_roots_missing = @($wanted | Where-Object { $sha1 -notcontains $_ } | ForEach-Object { $subjects[$_] })
    if ($sha1.Count -eq 0) { Add-EsNote $r ('keytool listed no certificates (exit code ' + $run.exit_code + ')') 'partial'; $r.raw['keytool'] = $text }
    return $r
}
