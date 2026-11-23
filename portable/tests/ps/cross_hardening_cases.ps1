# Cases for tests/test_ps_cross_hardening.py (cross-port hardening round 2026-11-15): the child
# environment allowlist and --net lookups of single-label and absolute names. Prints one JSON
# object (case name -> result). Runs in FullLanguage and in ConstrainedLanguage, so it may only
# use what the scanner itself may use. A case that throws reports {"case_error": message}.
param([string]$Lib, [string]$Scratch)

. $Lib
Initialize-EsRedaction
$script:ES_NETWORK_DRIVES = @()
$cases = @{}

function Get-Case([scriptblock]$Block) {
    try { return , (& $Block) } catch { return @{ case_error = ([string]$_.Exception.Message + ' at ' + [string]$_.InvocationInfo.PositionMessage) } }
}

# External commands run from a private temp folder, like a scan.
$script:ES_TMP = Join-Path $Scratch 'tmp'
$null = New-Item -ItemType Directory -Path $script:ES_TMP
$script:ES_EMPTY_IN = Join-Path $script:ES_TMP 'stdin.empty'
$null = New-Item -ItemType File -Path $script:ES_EMPTY_IN
$script:ES_CHILD_CWD = $env:SystemDrive + '\'

# Planted for the scan; only the allowlisted ones may reach a child.
$planted = @{
    ENVSCAN_TEST_CHILD_CANARY = 'canary-child-4d1e'; HTTP_PROXY = 'http://u:pw@p:1'; GITHUB_TOKEN = 'ghp_childcanary'
    NODE_OPTIONS = '--require x'; DOCKER_HOST = 'tcp://h:2375'; LC_ENVSCAN_T = 'lc-kept'; Xdg_Envscan_T = 'xdg-kept'
}

function Get-ChildEnvNames([hashtable]$Result) {
    # NAME=value lines of "cmd /d /c set" -> name -> value.
    $names = @{}
    foreach ($line in @(([string]$Result.stdout) -split "`r?`n")) {
        $at = $line.IndexOf('=')
        if ($at -gt 0) { $names[$line.Substring(0, $at)] = $line.Substring($at + 1) }
    }
    return $names
}

function Invoke-ChildSet([hashtable]$Extra) {
    $cmd = Get-EsSystemTool 'cmd.exe'
    if ($Extra) { return (Invoke-EsCommandWithEnv $Extra @{ FilePath = $cmd; Arguments = @('/d', '/c', 'set') }) }
    return (Invoke-EsCommand -FilePath $cmd -Arguments @('/d', '/c', 'set'))
}

function Get-EnvValues([string[]]$Names) {
    $out = @{}
    foreach ($name in $Names) { $out[$name] = Get-EsEnv $name }
    return $out
}

# ---- 1: a child sees only allowlisted scan-start variables, [child_env] and per-call extras
foreach ($name in @($planted.Keys)) { Set-Item -LiteralPath ('env:' + $name) -Value $planted[$name] }
$cases.child_env = Get-Case {
    Save-EsEnvSnapshot
    $before = Get-EnvValues @($planted.Keys)
    $plain = Get-ChildEnvNames (Invoke-ChildSet $null)
    $extra = Get-ChildEnvNames (Invoke-ChildSet @{ GIT_CEILING_DIRECTORIES = 'C:\x'; ENVSCAN_T_EXTRA = 'extra-1' })
    return @{
        plain = @($plain.Keys | Sort-Object); extra = @($extra.Keys | Sort-Object)
        no_color = $plain['NO_COLOR']; extra_value = $extra['ENVSCAN_T_EXTRA']; lc = $plain['LC_ENVSCAN_T']
        before = $before; after = (Get-EnvValues @($planted.Keys))
        after_extra = (Get-EsEnv 'ENVSCAN_T_EXTRA'); after_no_color = (Get-EsEnv 'NO_COLOR')
    }
}
# Without a snapshot (library use outside a scan) the live environment is the base.
$cases.child_env_live = Get-Case {
    $script:ES_ENV_SNAPSHOT = @{}
    $names = Get-ChildEnvNames (Invoke-ChildSet $null)
    return @(@($names.Keys) | Sort-Object)
}
foreach ($name in @($planted.Keys)) { Remove-Item -LiteralPath ('env:' + $name) -ErrorAction SilentlyContinue }
$script:ES_ENV_SNAPSHOT = @{}

$cases.child_env_keep = Get-Case {
    $out = @{}
    foreach ($name in @('path', 'ProgramFiles(x86)', 'COMMONPROGRAMFILES(X86)', 'lc_all', 'XDG_CONFIG_HOME', 'SystemRoot',
            'HTTP_PROXY', 'GITHUB_TOKEN', 'LD_PRELOAD', 'BASH_ENV', 'ENV', 'NODE_OPTIONS', 'PATHX', 'XPATH', 'LC')) {
        $out[$name] = [bool](Test-EsChildEnvKept $name)
    }
    return $out
}

# ---- 4: --net never looks up a single-label name, and looks up the absolute form of the others
$script:FakeAsked = @()
function Invoke-FakeLookup([object[]]$Hosts) {
    $script:ES_RESULTS = @{}
    $script:ES_OPT.net = $true
    $endpoints = @(foreach ($h in $Hosts) { @{ host = $h; port = 8080; source = 'env HTTP_PROXY' } })
    $script:ES_RESULTS['net.proxy'] = @{ status = 'ok'; data = @{ proxy_endpoints = $endpoints }; notes = @() }
    $script:ES_RESULTS['pkg.sources'] = @{ status = 'ok'; data = @{ endpoints = @() }; notes = @() }
    $script:FakeAsked = @()
    $result = & {
        function Resolve-EsHostNameDns([string]$HostName) {
            $script:FakeAsked += ('dns:' + $HostName); return @{ status = 'ok'; addresses = @('10.0.0.9'); error = $null; method = 'dns' } }
        function Resolve-EsHostNameNslookup([string]$HostName) {
            $script:FakeAsked += ('dns:' + $HostName); return @{ status = 'ok'; addresses = @('10.0.0.9'); error = $null; method = 'nslookup' } }
        function Test-EsTcpPort([string]$Address, [int]$Port, [int]$TimeoutMs) { return @{ tcp = 'ok'; ms = 1; error = $null } }
        probe_net_reachability
    }
    $script:ES_RESULTS = @{}
    $script:ES_OPT.net = $false
    return @{ asked = @($script:FakeAsked); targets = @($result.data.targets); status = $result.status; notes = @($result.notes) }
}
$cases.single_label = Get-Case { Invoke-FakeLookup @('proxy', 'proxy.', 'localhost', 'PROXY.CORP', 'proxy.corp.', 'nexus.corp.example', '10.0.0.5') }

# The nslookup path (ConstrainedLanguage) gets the absolute name as its last argument, and a
# single-label name never reaches it even when Resolve-EsHostName is called directly.
$cases.nslookup_absolute = Get-Case {
    $script:NsArgs = @()
    $full = $script:ES_FULL_LANGUAGE
    $script:ES_FULL_LANGUAGE = $false
    try {
        $answers = & {
            function Invoke-EsCommand { param([string]$FilePath, [string[]]$Arguments, [int]$TimeoutSec)
                $script:NsArgs += [string]::Join(' ', @($Arguments))
                return @{ exit_code = 0; timed_out = $false; error = $null; stdout = "Server: x`nAddress: 10.0.0.1`n`nName: p`nAddress: 10.0.0.9"; stderr = '' } }
            foreach ($name in @('proxy.corp', 'proxy.corp.', 'proxy', 'proxy.')) { $r = Resolve-EsHostName $name; $name + '=' + $r.status }
        }
    } finally { $script:ES_FULL_LANGUAGE = $full }
    return @{ args = @($script:NsArgs); answers = @($answers) }
}

# A scan-start environment with almost nothing in it still starts children.
$cases.child_env_minimal = Get-Case {
    $script:ES_ENV_SNAPSHOT = @{ Path = 'C:\envscan-nowhere'; PATHEXT = '.CMD;.EXE'; HOME = 'C:\h' }
    try {
        $run = Invoke-ChildSet @{ HOME = 'C:\y' }
        return @{ error = $run.error; exit_code = $run.exit_code; names = @((Get-ChildEnvNames $run).Keys | Sort-Object) }
    } finally { $script:ES_ENV_SNAPSHOT = @{} }
}

# ---- review fixes: Set-EsProcessEnv fails closed and always restores (HIGH)
function Get-EnvDump {
    # The whole process environment as sorted "name=value" lines (compared before and after).
    $table = Get-EsProcessEnv
    return @(@($table.PSBase.Keys) | Sort-Object | ForEach-Object { [string]$_ + '=' + [string]$table[$_] })
}
function Compare-EnvDump([object[]]$Before, [object[]]$After) {
    return @(Compare-Object -ReferenceObject @($Before) -DifferenceObject @($After) | ForEach-Object { [string]$_.SideIndicator + [string]$_.InputObject })
}
$cmdExe = Get-EsSystemTool 'cmd.exe'
$script:ES_ENV_SNAPSHOT = @{}
Set-Item -LiteralPath 'env:ENVSCAN_T_STICKY' -Value 'sticky-1'
Set-Item -LiteralPath 'env:ENVSCAN_T_KEEP' -Value 'keep-1'

# A variable that cannot be removed stays in the process environment: no child is started.
$cases.env_fail_closed = Get-Case {
    $before = Get-EnvDump
    $run = & {
        function Remove-Item { param([string[]]$LiteralPath, [switch]$Force, $ErrorAction)
            if (@($LiteralPath) -contains 'env:ENVSCAN_T_STICKY') { return }
            Microsoft.PowerShell.Management\Remove-Item @PSBoundParameters }
        Invoke-EsCommand -FilePath $cmdExe -Arguments @('/d', '/c', 'echo', 'child-ran')
    }
    return @{ error = $run.error; exit_code = $run.exit_code; stdout = [string]$run.stdout; diff = @(Compare-EnvDump $before (Get-EnvDump)) }
}
# Setting a variable fails half-way: the child is not started and everything is restored.
$cases.env_set_throws = Get-Case {
    $before = Get-EnvDump
    $run = & {
        function Set-Item { param([string[]]$LiteralPath, $Value, $ErrorAction)
            if (@($LiteralPath) -contains 'env:NO_COLOR') { throw 'refused by test' }
            Microsoft.PowerShell.Management\Set-Item @PSBoundParameters }
        Invoke-EsCommand -FilePath $cmdExe -Arguments @('/d', '/c', 'echo', 'child-ran')
    }
    return @{ error = $run.error; exit_code = $run.exit_code; stdout = [string]$run.stdout; diff = @(Compare-EnvDump $before (Get-EnvDump)) }
}
# The restore goes on past a variable it cannot set.
$cases.env_restore_tolerant = Get-Case {
    Set-Item -LiteralPath 'env:ENVSCAN_T_STICKY' -Value 'sticky-1'
    Set-Item -LiteralPath 'env:ENVSCAN_T_KEEP' -Value 'keep-1'
    $saved = Get-EsProcessEnv
    Remove-Item -LiteralPath 'env:ENVSCAN_T_STICKY', 'env:ENVSCAN_T_KEEP' -ErrorAction SilentlyContinue
    $threw = $false
    try {
        & {
            function Set-Item { param([string[]]$LiteralPath, $Value, $ErrorAction)
                if (@($LiteralPath) -contains 'env:ENVSCAN_T_STICKY') { throw 'refused by test' }
                Microsoft.PowerShell.Management\Set-Item @PSBoundParameters }
            $null = Restore-EsProcessEnv $saved
        }
    } catch { $threw = $true }
    $out = @{ threw = $threw; keep = (Get-EsEnv 'ENVSCAN_T_KEEP'); sticky = (Get-EsEnv 'ENVSCAN_T_STICKY') }
    Set-Item -LiteralPath 'env:ENVSCAN_T_STICKY' -Value 'sticky-1'
    return $out
}
# The PS 2.0 WMI job path restores the environment too, and fails closed the same way.
$cases.env_cim_job = Get-Case {
    $hasCim = $script:ES_HAS_CIM
    $script:ES_HAS_CIM = $false
    $script:JobStarted = 0
    try {
        $before = Get-EnvDump
        $failed = $null
        try { & { function Start-Job { $script:JobStarted++; throw 'job refused by test' }; Get-EsCim -Class 'Win32_Bios' -TimeoutSec 1 } }
        catch { $failed = $_.Exception.Message }
        $closed = $null
        try {
            & {
                function Start-Job { $script:JobStarted++; throw 'job refused by test' }
                function Remove-Item { param([string[]]$LiteralPath, [switch]$Force, $ErrorAction)
                    if (@($LiteralPath) -contains 'env:ENVSCAN_T_STICKY') { return }
                    Microsoft.PowerShell.Management\Remove-Item @PSBoundParameters }
                Get-EsCim -Class 'Win32_Bios' -TimeoutSec 1
            }
        } catch { $closed = $_.Exception.Message }
        return @{ failed = $failed; closed = $closed; started = $script:JobStarted; diff = @(Compare-EnvDump $before (Get-EnvDump)) }
    } finally { $script:ES_HAS_CIM = $hasCim }
}
Remove-Item -LiteralPath 'env:ENVSCAN_T_STICKY', 'env:ENVSCAN_T_KEEP' -ErrorAction SilentlyContinue

# ---- X2: kept variables that hold refused paths (network, UNC, mapped drive, credential store)
$cases.child_env_paths = Get-Case {
    $drives = $script:ES_NETWORK_DRIVES
    $script:ES_NETWORK_DRIVES = @('Z:')
    $script:ES_ENV_SNAPSHOT = @{
        Path = 'C:\Windows\System32;\\srv\share\bin;Z:\tools;C:\Users\u\.ssh\bin;;C:\Windows'
        PSModulePath = 'C:\m1;\\srv\mods'; LIBPATH = '\\srv\only;Z:\x'
        HOME = '\\srv\share\home'; APPDATA = '\\server\share\x'; USERPROFILE = 'C:\Users\u\.ssh'
        LOCALAPPDATA = 'C:\Users\u\AppData\Local'; TEMP = '\\srv\t'; TMP = 'Z:\tmp'; XDG_CACHE_HOME = '//srv/cache'
        JAVA_HOME = '\\srv\jdk'; GOROOT = 'Z:\go'; SSL_CERT_FILE = 'C:\certs\id_rsa'; COMSPEC = 'C:\Windows\system32\cmd.exe'
        LANG = 'en_US.UTF-8'; OS = 'Windows_NT'; GOPATH = 'C:\go-work'
    }
    try {
        $table = Get-EsChildEnvTable @{ GIT_CEILING_DIRECTORIES = '\\srv\ceiling' }
        $homeDir = [string]$table['HOME']
        # Only a folder inside the private temp folder is looked at (never a share).
        if (-not $homeDir.StartsWith($script:ES_TMP + '\')) { $homeDir = '' }
        return @{
            table = $table; tmp = $script:ES_TMP
            home_exists = [bool]($homeDir -and (Test-Path -LiteralPath $homeDir -PathType Container))
            home_empty = [bool]($homeDir -and @(Get-ChildItem -LiteralPath $homeDir -Force -ErrorAction SilentlyContinue).Count -eq 0)
            child = (Get-ChildEnvNames (Invoke-EsCommand -FilePath $cmdExe -Arguments @('/d', '/c', 'set')))
        }
    } finally { $script:ES_ENV_SNAPSHOT = @{}; $script:ES_NETWORK_DRIVES = $drives }
}

# ---- X4: malformed names and IPv4 literals with a trailing dot are never looked up
$cases.reach_malformed = Get-Case { Invoke-FakeLookup @('.proxy.corp', 'proxy..corp', '.', 'a.b..', '10.0.0.1.', '10.0.0.5', 'ok.corp') }
$cases.reach_reasons = Get-Case {
    $out = @{}
    foreach ($name in @('', '.', '..', '.x.corp', 'x..corp', 'x.corp..', 'host..', '10.0.0.1.', '192.168.1.1.', '8.8.8.8.', 'proxy.corp.', 'proxy.')) {
        $out['[' + $name + ']'] = Get-EsReachSkipReason $name
    }
    return $out
}
$cases.resolve_literal_dot = Get-Case {
    $script:FakeAsked = @()
    $answers = & {
        function Resolve-EsHostNameDns([string]$HostName) { $script:FakeAsked += $HostName; return @{ status = 'ok'; addresses = @('10.0.0.9'); error = $null; method = 'dns' } }
        function Resolve-EsHostNameNslookup([string]$HostName) { $script:FakeAsked += $HostName; return @{ status = 'ok'; addresses = @('10.0.0.9'); error = $null; method = 'nslookup' } }
        foreach ($name in @('10.0.0.1.', 'x..corp', '.x.corp')) { $r = Resolve-EsHostName $name; $name + '=' + $r.status + '=' + $r.error }
    }
    return @{ asked = @($script:FakeAsked); answers = @($answers) }
}

$cases.language_mode = $script:ES_LANGUAGE_MODE
Write-Output (ConvertTo-EsJson $cases)
