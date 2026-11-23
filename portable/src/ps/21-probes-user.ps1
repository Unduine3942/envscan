# ---------------------------------------------------------------------------
# 21-probes-user: running user, profile, privileges (deep), environment,
# PATH analysis and shells.
# ---------------------------------------------------------------------------

$script:ES_SID_NAMES = @{
    'S-1-1-0' = 'Everyone'; 'S-1-2-0' = 'LOCAL'; 'S-1-2-1' = 'CONSOLE LOGON'; 'S-1-5-2' = 'NETWORK'
    'S-1-5-4' = 'INTERACTIVE'; 'S-1-5-6' = 'SERVICE'; 'S-1-5-11' = 'Authenticated Users'
    'S-1-5-14' = 'REMOTE INTERACTIVE LOGON'; 'S-1-5-15' = 'This Organization'; 'S-1-5-113' = 'Local account'
    'S-1-5-114' = 'Local account and member of Administrators'; 'S-1-5-32-544' = 'BUILTIN\Administrators'
    'S-1-5-32-545' = 'BUILTIN\Users'; 'S-1-5-32-546' = 'BUILTIN\Guests'; 'S-1-5-32-547' = 'BUILTIN\Power Users'
    'S-1-5-32-555' = 'BUILTIN\Remote Desktop Users'; 'S-1-5-32-559' = 'BUILTIN\Performance Log Users'
    'S-1-5-32-562' = 'BUILTIN\Distributed COM Users'; 'S-1-5-32-568' = 'BUILTIN\IIS_IUSRS'
    'S-1-5-32-573' = 'BUILTIN\Event Log Readers'; 'S-1-5-32-578' = 'BUILTIN\Hyper-V Administrators'
    'S-1-5-32-580' = 'BUILTIN\Remote Management Users'; 'S-1-5-64-10' = 'NTLM Authentication'
    'S-1-5-64-36' = 'Cloud Account Authentication'; 'S-1-18-1' = 'Authentication authority asserted identity'
}
$script:ES_DOMAIN_RIDS = @{ '512' = 'Domain Admins'; '513' = 'Domain Users (or local None)'; '514' = 'Domain Guests'; '519' = 'Enterprise Admins'; '525' = 'Protected Users' }
$script:ES_SHELL_FOLDERS = @{
    'Personal' = 'Documents'; 'Desktop' = 'Desktop'; 'AppData' = 'AppData'; 'Local AppData' = 'LocalAppData'
    '{374DE290-123F-4565-9164-39C4925E467B}' = 'Downloads'; 'My Pictures' = 'Pictures'; 'Favorites' = 'Favorites'
    'Start Menu' = 'StartMenu'; 'Templates' = 'Templates'; 'Cache' = 'InternetCache'
}

function ConvertTo-EsGroupName([string]$Sid) {
    if ($script:ES_SID_NAMES.ContainsKey($Sid)) { return $script:ES_SID_NAMES[$Sid] }
    if ($Sid -match '^S-1-5-21-\d+-\d+-\d+-(\d+)$') {
        $rid = $matches[1]
        if ($script:ES_DOMAIN_RIDS.ContainsKey($rid)) { return ($script:ES_DOMAIN_RIDS[$rid] + ' (' + $Sid + ')') }
    }
    return $Sid
}

function probe_user_identity {
    $r = New-EsResult
    $d = $r.data
    $r.sources += 'environment USERNAME, USERDOMAIN, USERDNSDOMAIN, USERPROFILE, LOGONSERVER'
    $info = Get-EsTokenInfo
    $r.sources += @('token groups (' + $info.groups_source + ')', 'Get-Process -Id $PID -IncludeUserName')
    $d.name = Get-EsOrigEnv 'USERNAME'
    $d.domain = Get-EsOrigEnv 'USERDOMAIN'
    $d.dns_domain = Get-EsOrigEnv 'USERDNSDOMAIN'
    $d.logon_server = Get-EsOrigEnv 'LOGONSERVER'
    $d.local_account = ($d.domain -and $d.domain -eq (Get-EsOrigEnv 'COMPUTERNAME'))
    $d.sid = $info.user_sid
    $d.uid = $null
    $d.gid = $null
    $d.groups_source = $info.groups_source
    $d.groups = @()
    $d.group_sids = @()
    if ($info.groups_source -eq 'token') {
        $d.group_sids = @($info.group_sids)
        $d.groups = @($info.group_sids | ForEach-Object { ConvertTo-EsGroupName $_ })
    } else {
        Add-EsNote $r 'group membership is only readable in FullLanguage mode (or with --deep: whoami /all)' ''
    }
    $d.is_admin = $info.is_admin
    $d.elevation_method = $info.elevation_method
    if ($null -eq $info.is_admin) { Add-EsNote $r 'elevation could not be determined' 'partial' }
    $d.integrity = $null
    $d.home = Get-EsOrigEnv 'USERPROFILE'
    $d.shell = Get-EsOrigEnv 'ComSpec'
    $d.passwd_entry = $null
    $uacKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $r.sources += 'registry HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System (UAC values)'
    $uac = @{}
    foreach ($name in @('EnableLUA', 'ConsentPromptBehaviorAdmin', 'ConsentPromptBehaviorUser', 'PromptOnSecureDesktop', 'FilterAdministratorToken')) {
        $uac[$name] = Get-EsRegValue $uacKey $name
    }
    $d.uac = $uac
    $unlock = Get-EsRegValues 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock'
    $r.sources += 'registry HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock'
    $d.developer_mode = $false
    if ($unlock -and $unlock['AllowDevelopmentWithoutDevLicense'] -eq 1) { $d.developer_mode = $true }
    return $r
}

function Get-EsShellFolders {
    $values = Get-EsRegValues 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
    if ($null -eq $values) { return @{} }
    return $values
}

function Get-EsProfileKind([hashtable]$Result, [string]$ProfilePath) {
    # Profile type from the own ProfileList entry, the profile folder name and NTUSER.MAN.
    $entry = Find-EsProfileEntry (Get-EsTokenInfo).user_sid
    $Result.sources += 'registry HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList (own entry)'
    $kind = @{ type = 'local'; state = $null; central = $null }
    if ($entry) {
        $state = $entry.values['State']
        $central = [string]$entry.values['CentralProfile']
        $kind.state = $state
        if ($central) { $kind.type = 'roaming'; $kind.central = $central }
        if ($null -ne $state -and ([long]$state -band 0x1) -ne 0) { $kind.type = 'mandatory' }
        if (($null -ne $state -and ([long]$state -band 0x800) -ne 0) -or $entry.key -like '*.bak') { $kind.type = 'temporary' }
    } else {
        Add-EsNote $Result 'own ProfileList entry not found' ''
    }
    $leaf = $ProfilePath.TrimEnd('\')
    $leaf = $leaf.Substring($leaf.LastIndexOf('\') + 1)
    if ($leaf -match '^TEMP(\.|$)') { $kind.type = 'temporary' }
    if ((Test-EsLocalPath $ProfilePath) -and (Test-EsSafePath (Join-Path $ProfilePath 'NTUSER.MAN'))) { $kind.type = 'mandatory' }
    return $kind
}

function Get-EsFolderRedirection([hashtable]$Result, [string]$ProfilePath) {
    # Known shell folders, those outside the local profile, and those inside OneDrive.
    $folders = Get-EsShellFolders
    $Result.sources += 'registry HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
    $redirected = @{}
    $known = @{}
    $oneDrive = @(@((Get-EsOrigEnv 'OneDrive'), (Get-EsOrigEnv 'OneDriveCommercial')) | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
    $profileLower = $ProfilePath.ToLowerInvariant()
    $inOneDrive = @()
    foreach ($name in @($folders.PSBase.Keys)) {
        $label = $name
        if ($script:ES_SHELL_FOLDERS.ContainsKey($name)) { $label = $script:ES_SHELL_FOLDERS[$name] }
        $path = [string]$folders[$name]
        $pathLower = $path.ToLowerInvariant()
        if ($script:ES_SHELL_FOLDERS.ContainsKey($name)) { $known[$label] = $path }
        $local = ($profileLower -and $pathLower.StartsWith($profileLower))
        if (-not $local -or (Test-EsNetworkPath $path)) { $redirected[$label] = $path }
        foreach ($root in $oneDrive) { if ($pathLower.StartsWith($root)) { $inOneDrive += $label } }
    }
    return @{ known = $known; redirected = $redirected; in_onedrive = @($inOneDrive | Sort-Object -Unique) }
}

function probe_user_profile {
    $r = New-EsResult
    $d = $r.data
    $profilePath = Get-EsOrigEnv 'USERPROFILE'
    $r.sources += 'environment USERPROFILE, HOMEDRIVE, HOMEPATH, HOMESHARE, OneDrive, OneDriveCommercial'
    $d.home = $profilePath
    $homeDrive = Get-EsOrigEnv 'HOMEDRIVE'
    $d.homeshare = Get-EsOrigEnv 'HOMESHARE'
    $d.homedrive = $homeDrive
    $d.homepath = Get-EsOrigEnv 'HOMEPATH'
    $d.home_network = ((Test-EsNetworkPath $profilePath) -or [bool]$d.homeshare -or (Test-EsNetworkPath ([string]$homeDrive)))
    $d.appdata_network = (Test-EsNetworkPath (Get-EsOrigEnv 'APPDATA'))
    $kind = Get-EsProfileKind $r ([string]$profilePath)
    $d.profile_type = $kind.type
    $d.profile_state = $kind.state
    $d.central_profile = $kind.central
    $folders = Get-EsFolderRedirection $r ([string]$profilePath)
    $d.known_folders = $folders.known
    $d.redirected_folders = $folders.redirected
    $d.onedrive = @{
        personal = Get-EsOrigEnv 'OneDrive'; commercial = Get-EsOrigEnv 'OneDriveCommercial'
        folders_in_onedrive = $folders.in_onedrive
    }
    $r.sources += 'registry HKLM\SOFTWARE\FSLogix\Profiles'
    $fslogix = Get-EsRegValues 'HKLM:\SOFTWARE\FSLogix\Profiles'
    $d.fslogix = $null
    if ($fslogix) {
        $d.fslogix = @{ enabled = ($fslogix['Enabled'] -eq 1); vhd_locations = $fslogix['VHDLocations']; volume_type = $fslogix['VolumeType'] }
    }
    return $r
}

function probe_user_privileges {
    $r = New-EsResult
    $d = $r.data
    $whoami = Invoke-EsTool $r 'whoami /all' (Get-EsSystemTool 'whoami.exe') @('/all')
    $text = Get-EsCommandText $whoami
    $d.privileges = @([regex]::Matches($text, '\bSe[A-Za-z]+Privilege\b') | ForEach-Object { $_.Value } | Sort-Object -Unique)
    $d.group_sids = @([regex]::Matches($text, '\bS-1-[0-9-]+\b') | ForEach-Object { $_.Value } | Sort-Object -Unique)
    $d.integrity = $null
    if ($text -match '\bS-1-16-(\d+)\b') {
        $levels = @{ '4096' = 'low'; '8192' = 'medium'; '8448' = 'medium-plus'; '12288' = 'high'; '16384' = 'system' }
        $d.integrity = $levels[$matches[1]]
    }
    $d.admin_capable = ($d.group_sids -contains 'S-1-5-32-544' -or $d.group_sids -contains 'S-1-5-114')
    $null = Invoke-EsTool $r 'gpresult /r /scope user' (Get-EsSystemTool 'gpresult.exe') @('/r', '/scope', 'user') 60
    return $r
}

function probe_env_vars {
    $r = New-EsResult
    $d = $r.data
    $r.sources += @('process environment (before the scanner changed anything)', 'registry HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'registry HKCU\Environment')
    $process = @{}
    $redacted = 0
    foreach ($name in @($script:ES_ENV_SNAPSHOT.PSBase.Keys | Sort-Object)) {
        $value = Protect-EsNamedValue $name $script:ES_ENV_SNAPSHOT[$name]
        if ($value -eq $script:ES_PLACEHOLDER) { $redacted++ }
        $process[$name] = $value
    }
    $d.process = $process
    $machine = Get-EsRegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    $user = Get-EsRegValues 'HKCU:\Environment'
    if ($null -eq $machine) { Add-EsNote $r 'machine environment key unreadable' 'partial'; $machine = @{} }
    if ($null -eq $user) { $user = @{} }
    $d.machine = Protect-EsTable $machine
    $d.user = Protect-EsTable $user
    $d.redacted = $redacted
    $d.count = $process.PSBase.Count
    return $r
}

function Get-EsPathList([string]$Value) {
    return @(([string]$Value) -split ';' | ForEach-Object { $_.Trim().Trim('"').TrimEnd('\').ToLowerInvariant() } | Where-Object { $_ })
}

function Get-EsPathIssues([object[]]$Entries, $SystemPosition) {
    # Distinct PATH entries per issue; writable_before_system32 lists entries searched first.
    return @{
        missing = @($Entries | Where-Object { $_.exists -eq $false } | ForEach-Object { $_.path } | Select-Object -Unique)
        duplicate = @($Entries | Where-Object { $_.duplicate } | ForEach-Object { $_.path } | Select-Object -Unique)
        relative = @($Entries | Where-Object { $_.relative } | ForEach-Object { $_.path } | Select-Object -Unique)
        network = @($Entries | Where-Object { $_.network } | ForEach-Object { $_.path } | Select-Object -Unique)
        writable = @($Entries | Where-Object { $_.writable } | ForEach-Object { $_.path } | Select-Object -Unique)
        writable_before_system32 = @($Entries | Where-Object { $_.writable -and $null -ne $SystemPosition -and $_.position -lt $SystemPosition } | ForEach-Object { $_.path } | Select-Object -Unique)
    }
}

function probe_env_path {
    $r = New-EsResult
    $d = $r.data
    $r.sources += @('process PATH', 'registry machine and user Path', 'directory ACLs of local PATH entries (read, no writes)')
    $raw = [string](Get-EsOrigEnv 'Path')
    $machineList = Get-EsPathList (Get-EsRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' 'Path')
    $userList = Get-EsPathList (Get-EsRegValue 'HKCU:\Environment' 'Path')
    $system32 = ([string]$env:SystemRoot + '\system32').ToLowerInvariant()
    $seen = @{}
    $entries = @()
    $empty = 0
    $position = 0
    $systemPosition = $null
    foreach ($part in @($raw -split ';')) {
        $path = $part.Trim()
        if (-not $path) { $empty++; continue }
        $position++
        $clean = $path.Trim('"').TrimEnd('\')
        $key = $clean.ToLowerInvariant()
        if ($key -eq $system32 -and $null -eq $systemPosition) { $systemPosition = $position }
        $scope = 'process'
        if ($machineList -contains $key) { $scope = 'machine' } elseif ($userList -contains $key) { $scope = 'user' }
        $network = Test-EsNetworkPath $clean
        $relative = ($clean -notmatch '^([A-Za-z]:\\|\\\\)')
        $entry = @{
            path = $path; scope = $scope; network = $network; relative = $relative; duplicate = $seen.ContainsKey($key)
            quoted = $path.Contains('"'); unexpanded = ($path -match '%[^%]+%'); exists = $null; writable = $null; position = $position
        }
        $seen[$key] = $true
        if (-not $network -and -not $relative) {
            $entry.exists = Test-EsSafePath $clean 'Container'
            if ($entry.exists) { $entry.writable = (Get-EsSddlAccess ($clean + '\')).create_files }
        }
        $entries += $entry
    }
    $d.separator = ';'
    $d.length = $raw.Length
    $d.count = $entries.Count
    $d.empty_entries = $empty
    $d.entries = $entries
    $d.issues = Get-EsPathIssues $entries $systemPosition
    if ((Get-EsTokenInfo).groups_source -ne 'token') { Add-EsNote $r 'writable is computed from ACLs with assumed standard-user groups (ConstrainedLanguage)' '' }
    return $r
}

function Get-EsPowerShellEngines([hashtable]$Result) {
    $engines = @()
    foreach ($major in @('1', '3')) {
        $key = 'HKLM:\SOFTWARE\Microsoft\PowerShell\' + $major + '\PowerShellEngine'
        $Result.sources += ('registry ' + ($key -replace '^HKLM:', 'HKLM'))
        $version = Get-EsRegValue $key 'PowerShellVersion'
        if ($version) { $engines += @{ name = 'Windows PowerShell'; version = [string]$version; path = [string](Get-EsRegValue $key 'ApplicationBase') } }
    }
    $root = Join-Path ([string]$env:ProgramFiles) 'PowerShell'
    $Result.sources += ('list ' + $root)
    foreach ($dir in @(Get-EsDirEntries $root 50)) {
        $exe = Join-Path $dir.FullName 'pwsh.exe'
        if (Test-EsSafePath $exe 'Leaf') {
            $version = $null
            try { $version = [string](Get-Item -LiteralPath $exe -ErrorAction Stop).VersionInfo.ProductVersion } catch { }
            $engines += @{ name = 'PowerShell'; version = $version; path = $exe }
        }
    }
    return $engines
}

function Get-EsExecutionPolicies([hashtable]$Result) {
    # Policy per scope (keys in Get-ExecutionPolicy -List order under __order) and the effective one.
    $scopes = @{ __order = @() }
    $effective = $null
    try {
        foreach ($item in @(Get-ExecutionPolicy -List -ErrorAction Stop)) {
            $scopes[[string]$item.Scope] = [string]$item.ExecutionPolicy
            $scopes.__order += [string]$item.Scope
        }
        $effective = [string](Get-ExecutionPolicy -ErrorAction Stop)
    } catch { Add-EsNote $Result ('execution policy: ' + $_.Exception.Message) 'partial' }
    return @{ scopes = $scopes; effective = $effective }
}

function Get-EsCmdSettings([hashtable]$Result) {
    # cmd.exe AutoRun (redacted) and DisableCMD, and whether Windows Script Host is enabled.
    $settings = @{ autorun = @{}; disabled = $null; wsh_enabled = $true }
    foreach ($hive in @('HKLM', 'HKCU')) {
        $Result.sources += ('registry ' + $hive + '\Software\Microsoft\Command Processor (AutoRun)')
        $value = Get-EsRegValue ($hive + ':\Software\Microsoft\Command Processor') 'AutoRun'
        if ($value) { $settings.autorun[$hive] = Protect-EsCommandLine ([string]$value) }
    }
    foreach ($hive in @('HKCU', 'HKLM')) {
        $Result.sources += ('registry ' + $hive + '\Software\Policies\Microsoft\Windows\System (DisableCMD)')
        $value = Get-EsRegValue ($hive + ':\Software\Policies\Microsoft\Windows\System') 'DisableCMD'
        if ($null -ne $value -and $null -eq $settings.disabled) { $settings.disabled = [int]$value }
    }
    foreach ($hive in @('HKLM', 'HKCU')) {
        $Result.sources += ('registry ' + $hive + '\Software\Microsoft\Windows Script Host\Settings (Enabled)')
        $value = Get-EsRegValue ($hive + ':\Software\Microsoft\Windows Script Host\Settings') 'Enabled'
        if ($null -ne $value -and [string]$value -eq '0') { $settings.wsh_enabled = $false }
    }
    return $settings
}

function probe_shell_info {
    $r = New-EsResult
    $d = $r.data
    $r.sources += @('$PSVersionTable, language mode', 'Get-ExecutionPolicy -List')
    $d.current_shell = 'powershell'
    $d.shell_version = [string]$PSVersionTable.PSVersion
    $d.edition = $(if ($PSVersionTable.PSEdition) { [string]$PSVersionTable.PSEdition } else { 'Desktop' })
    $d.clr_version = [string]$PSVersionTable.CLRVersion
    $d.host = [string]$Host.Name
    $d.language_mode = $script:ES_LANGUAGE_MODE
    $policy = Get-EsExecutionPolicies $r
    $policies = $policy.scopes
    $d.effective_policy = $policy.effective
    $d.execution_policy = $policies
    $d.policy_from_gpo = (@(@('MachinePolicy', 'UserPolicy') | Where-Object { $policies[$_] -and $policies[$_] -ne 'Undefined' }).Count -gt 0)
    $d.powershell_installed = @(Get-EsPowerShellEngines $r)
    $psPolicies = @{}
    foreach ($hive in @('HKLM', 'HKCU')) {
        $key = $hive + ':\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
        $r.sources += ('registry ' + $hive + '\SOFTWARE\Policies\Microsoft\Windows\PowerShell')
        $tree = Get-EsRegTree $key 50
        if ($tree.Count -gt 0) { $psPolicies[$hive] = Protect-EsTable $tree }
    }
    $d.powershell_policies = $psPolicies
    $cmd = Get-EsCmdSettings $r
    $d.cmd_autorun = $cmd.autorun
    $d.cmd_disabled = $cmd.disabled
    $d.wsh_enabled = $cmd.wsh_enabled
    $d.script_zone_id = $null
    if ($script:ES_SCRIPT_PATH -and $script:ES_PS_MAJOR -ge 3) {
        $r.sources += 'read envscan.ps1:Zone.Identifier'
        try {
            $zone = @(Get-Content -LiteralPath $script:ES_SCRIPT_PATH -Stream 'Zone.Identifier' -ErrorAction Stop) -join "`n"
            if ($zone -match 'ZoneId=(\d+)') { $d.script_zone_id = [int]$matches[1] }
        } catch { }
    }
    $d.comspec = Get-EsOrigEnv 'ComSpec'
    $d.pathext = Get-EsOrigEnv 'PATHEXT'
    return $r
}
