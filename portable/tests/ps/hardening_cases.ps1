# Cases for tests/test_ps_hardening.py (review findings of 2026-11-11). Prints one JSON object
# (case name -> result). Runs in FullLanguage and in ConstrainedLanguage, so it may only use what
# the scanner itself may use; cases that simulate PowerShell 2.0 run in FullLanguage only.
# Library functions are replaced inside a child scope (& { function X {...}; ... }): PowerShell
# resolves commands through the caller's scopes, so the library sees the fake only there.
param([string]$Lib, [string]$Scratch)

. $Lib
Initialize-EsRedaction
$script:ES_NETWORK_DRIVES = @()
$cases = @{}

function Get-Case([scriptblock]$Block) {
    # One case: its result, or the error that stopped it (the other cases still run). The comma
    # keeps an array result an array (a block returning a list uses "return , @(...)").
    try { return , (& $Block) } catch { return @{ case_error = ([string]$_.Exception.Message + ' at ' + [string]$_.InvocationInfo.PositionMessage) } }
}

function Reset-EsRun {
    $script:ES_RESULTS = @{}
    $script:ES_LINK_CACHE = @{}
    $script:ES_OPT.only = @(); $script:ES_OPT.skip = @(); $script:ES_OPT.out = $null
    $script:ES_OPT.deep = $false; $script:ES_OPT.net = $false; $script:ES_OPT.redact = $true
    $script:ES_OPT.list = $false; $script:ES_OPT.version = $false; $script:ES_OPT.help = $false
}

function Set-EsFakeResult([string]$Id, [string]$Status, [hashtable]$Data) {
    $script:ES_RESULTS[$Id] = @{ status = $Status; data = $Data; notes = @() }
}

function Reset-EsPathCache([hashtable]$Snapshot) {
    $script:ES_ENV_SNAPSHOT = $Snapshot
    $script:ES_PATH_DIRS = $null
    $script:ES_PATH_INDEX = $null
    $script:ES_PATHEXT = $null
}

# External commands run from a private temp folder, like a scan.
$script:ES_TMP = Join-Path $Scratch 'tmp'
$null = New-Item -ItemType Directory -Path $script:ES_TMP
$script:ES_EMPTY_IN = Join-Path $script:ES_TMP 'stdin.empty'
$null = New-Item -ItemType File -Path $script:ES_EMPTY_IN
$script:ES_CHILD_CWD = $env:SystemDrive + '\'
$noDrive = $Scratch.Substring(2)

# ---- 1: spec paths must be absolute and local (each relative form below exists from here)
$cases.paths = Get-Case {
    $local = Join-Path $Scratch 'loc'
    $null = New-Item -ItemType Directory -Path (Join-Path $local 'bin')
    Set-Content -LiteralPath (Join-Path $local 'bin\envscantool.exe') -Value 'x'
    $env:ENVSCAN_T_ROOTREL = $noDrive + '\loc'
    $env:ENVSCAN_T_DRIVEREL = $env:SystemDrive + 'loc'
    $env:ENVSCAN_T_LOCAL = $local
    $env:ENVSCAN_T_UNC = '\\envscan-test-server\share'
    $script:ES_NETWORK_DRIVES = @('Q:')
    $out = @{
        unix_absolute = @(Expand-EsPathPattern ($noDrive.Replace('\', '/') + '/loc/bin'))
        root_relative = @(Expand-EsPathPattern '{env:ENVSCAN_T_ROOTREL}/bin')
        drive_relative = @(Expand-EsPathPattern '{env:ENVSCAN_T_DRIVEREL}/bin')
        relative = @(Expand-EsPathPattern 'loc/bin')
        unc = @(Expand-EsPathPattern '{env:ENVSCAN_T_UNC}/bin')
        mapped = @(Expand-EsPathPattern 'Q:/loc/bin')
        local = @(Expand-EsPathPattern '{env:ENVSCAN_T_LOCAL}/bin')
        local_glob = @(Expand-EsPathPattern '{env:ENVSCAN_T_LOCAL}/b*')
    }
    $profilePath = $env:USERPROFILE
    $env:USERPROFILE = ''
    try { $out.home_unset = @(Expand-EsPathPattern ('~' + $noDrive.Replace('\', '/') + '/loc/bin')) }
    finally { $env:USERPROFILE = $profilePath }
    Reset-EsPathCache @{ Path = ''; PATHEXT = '.EXE' }
    $out.find_relative_tool = @(Find-EsExecutable @('envscantool') @('loc/bin') | ForEach-Object { $_.path })
    $out.writable_relative = Test-EsWritableDir 'loc'
    $out.sddl_relative = Get-EsSddlAccess 'loc'
    $script:ES_NETWORK_DRIVES = @()
    return $out
}

# ---- 2: strings ending in a newline
$cases.json_newline = ConvertTo-EsJson @{ s = "line`n"; crlf = "x`r`n"; arr = @("a`n", 'b'); "key`n" = 'v'; plain = 'ok' }
$cases.md_newline = @{ scalar = (Format-EsMdScalar "a`n"); inline = (Format-EsMdInline @{ k = "v`n" }); text = (Format-EsMdText "t`n") }

# ---- 4: absent data is not a finding, and the brief does not claim it
$cases.absent = Get-Case {
    Reset-EsRun
    Set-EsFakeResult 'runtime.dotnet' 'ok' @{ framework = @{ release = 378389; version = '4.5' }; framework_legacy = @('v3.5') }
    $findings = @(Get-EsExecFindings)
    $brief = @(Get-EsBriefPlatform) + @(Get-EsBriefRuntimes) + @(Get-EsBriefWrite) + @(Get-EsBriefNetwork) + @(Get-EsBriefLimits)
    return @{ finding_ids = @($findings | ForEach-Object { $_.id }); brief = ($brief -join "`n"); weak_tls = [string](Get-EsWeakDotnetTls) }
}
$cases.app_control_present = Get-Case {
    Reset-EsRun
    Set-EsFakeResult 'sec.app_control' 'ok' @{ enforced = @('AppLocker (Exe)') }
    $finding = @(Get-EsExecFindings | Where-Object { $_.id -eq 'exec.app_control' }) | Select-Object -First 1
    return @{ detail = $finding.detail; brief = (@(Get-EsBriefWrite) -join "`n") }
}

# ---- 5: progress never reaches stdout (stdout of this process is a pipe)
$cases.progress_stdout = Get-Case {
    $script:HostLines = @()
    if ($script:ES_FULL_LANGUAGE) { return , @() }  # FullLanguage writes to stderr (the scan tests check it)
    & {
        function Write-Host { $script:HostLines += [string]($args -join ' ') }
        Write-EsProgress 'envscan: progress line'
    }
    return , @($script:HostLines)
}

# ---- 6: PowerShell 2.0 has no -Encoding Oem
$cases.oem = Get-Case {
    if (-not $script:ES_FULL_LANGUAGE) { return @{ skipped = $true } }
    $file = Join-Path $Scratch 'oem.out'
    Set-Content -LiteralPath $file -Encoding Byte -Value ([byte[]]@(0x63, 0x61, 0x66, 0x82, 0x0D, 0x0A, 0x78, 0x0D, 0x0A))
    $ps3 = Read-EsCommandOutput $file 'Oem' 100
    $major = $script:ES_PS_MAJOR
    $script:ES_PS_MAJOR = 2
    $script:SpyEncodings = @()
    try {
        $ps2 = & {
            function Get-Content {
                param([string]$LiteralPath, [string]$Path, [string]$Encoding, [int]$TotalCount = -1, [int]$ReadCount = 1, $ErrorAction)
                $script:SpyEncodings += [string]$Encoding
                $forward = @{ ErrorAction = 'Stop'; TotalCount = $TotalCount; ReadCount = $ReadCount }
                if ($LiteralPath) { $forward.LiteralPath = $LiteralPath } else { $forward.Path = $Path }
                if ($Encoding) { $forward.Encoding = $Encoding }
                Microsoft.PowerShell.Management\Get-Content @forward
            }
            Read-EsCommandOutput $file 'Oem' 100
        }
    } finally { $script:ES_PS_MAJOR = $major }
    return @{ ps3 = $ps3; ps2 = $ps2; encodings = @($script:SpyEncodings) }
}

# ---- 7 and 17: arguments
function Get-ArgResult([object[]]$Arguments) {
    Reset-EsRun
    $errors = @(Read-EsArguments $Arguments)
    return @{ errors = $errors; net = $script:ES_OPT.net; deep = $script:ES_OPT.deep; redact = $script:ES_OPT.redact }
}
$cases.args = Get-Case {
    $out = @{
        net_false = Get-ArgResult @('--net=false'); deep_zero = Get-ArgResult @('--deep=0')
        no_redact_false = Get-ArgResult @('--no-redact=false'); version_value = Get-ArgResult @('-version=1')
        help_value = Get-ArgResult @('--help=yes'); list_value = Get-ArgResult @('--list-probes=1'); h_value = Get-ArgResult @('-h=1')
        out_value = Get-ArgResult @('--out=C:\x'); only_bad_char = Get-ArgResult @('--only', 'os.ident[ity')
        only_no_match = Get-ArgResult @('--only', 'nosuch.*'); skip_bad = Get-ArgResult @('--skip=os.identity,bad?')
        only_space = Get-ArgResult @('--only', 'os identity'); only_ok = Get-ArgResult @('--only', 'os.*,hw.cpu')
        skip_ok = Get-ArgResult @('--skip', 'net.*'); only_exact = Get-ArgResult @('--only=os.identity')
        only_empty = Get-ArgResult @('--only', ''); only_comma = Get-ArgResult @('--only=,')
        only_blank_list = Get-ArgResult @('--only', ' , '); skip_empty = Get-ArgResult @('--skip', '')
        skip_comma = Get-ArgResult @('--skip=,'); skip_blank_list = Get-ArgResult @('--skip', ' , ')
    }
    Reset-EsRun
    return $out
}

# ---- 8: endpoints from the raw text, never userinfo
$cases.endpoint_urls = Get-Case {
    return @{
        pip = @(Get-EsEndpointUrls ("[global]`nindex-url = https://pipuser:pip-pw-1@pypi.corp.example/simple"))
        proxy = @(Get-EsEndpointUrls 'proxy=http://alice:S3cret@proxy.corp:8080')
        separators = @(Get-EsEndpointUrls 'registry=https://u:p;a,ss(x)@npm.corp.example:8443/repo/')
        xmlns = @(Get-EsEndpointUrls '<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"><url>https://nexus.corp/repo</url>')
        comment = @(Get-EsEndpointUrls '# registry=https://old.corp.example/')
        ipv6 = @(Get-EsEndpointUrls 'proxy = http://[fd00::5]:3128/')
        upper = @(Get-EsEndpointUrls 'URL=HTTPS://Nexus.Corp.Example/Repo')
        inside_word = @(Get-EsEndpointUrls 'credential.https://dev.azure.com.username=x')
        two = @(Get-EsEndpointUrls ("a = https://a.corp/x https://a.corp/y`nb = 'https://b.corp:444'"))
        trailing_dot = @(Get-EsEndpointUrls 'registry=https://registry.npmjs.org./ x=https://nexus.corp.:8443/r')
        skip_trailing_dot = Get-EsReachSkipReason 'registry.npmjs.org.'
    }
}
$cases.config_entry = Get-Case {
    $file = Join-Path $Scratch 'npmrc'
    Set-Content -LiteralPath $file -Encoding Ascii -Value @('registry=https://npm.corp.example/repository/npm/',
        'https-proxy=http://alice:S3cretPw9@proxy.corp.example:8080', '//npm.corp.example/:_authToken=npm_tok_secret')
    $config = @{ id = 'npmrc.user'; tool = 'npm'; scope = 'user'; mode = 'content'; match = @(); max_bytes = 16384 }
    return (Read-EsConfigFile $config $file)
}
$cases.proxy_from_config = Get-Case {
    Reset-EsRun
    $script:ES_ENV_SNAPSHOT = @{}
    Set-EsFakeResult 'pkg.sources' 'ok' @{
        configs = @(@{ tool = 'npm'; path = 'C:\x\.npmrc'; lines = @('https-proxy=http://alice:<redacted>@proxy.corp.example:8080')
                urls = @('http://proxy.corp.example:8080'); proxy_urls = @('http://proxy.corp.example:8080') })
        git_config = @(); proxy_urls = @(@{ tool = 'npm'; url = 'http://proxy.corp.example:8080'; source = 'C:\x\.npmrc' })
    }
    $result = probe_net_proxy
    return , @($result.data.proxy_endpoints | Where-Object { [string]$_.source -like 'config*' })
}

# ---- 10: Java option banners
$cases.java_banner = @{
    tool_options = (Get-EsVersionToken ("Picked up JAVA_TOOL_OPTIONS: -Djdk.tls.client.protocols=TLSv1.2`nPicked up _JAVA_OPTIONS: -Xmx1g -Dv=1.5`nopenjdk version ""17.0.2"" 2022-01-18`nOpenJDK Runtime Environment (build 17.0.2+8-86)")).version
    jdk_options = (Get-EsVersionToken ("Picked up JDK_JAVA_OPTIONS: --add-opens=java.base/x=1.2`r`njava version ""1.8.0_381""")).version
    java_options_only = (Get-EsVersionToken 'Picked up _JAVA_OPTIONS: -Dhttps.protocols=TLSv1.2').version
}

# ---- 11: .cmd tools run through cmd.exe /d
$cases.cmd_tool = Get-Case {
    $dir = Join-Path $Scratch 'cmd tool (x86)'
    $null = New-Item -ItemType Directory -Path $dir
    $tool = Join-Path $dir 'tool.cmd'
    Set-Content -LiteralPath $tool -Encoding Ascii -Value '@echo [%CMDCMDLINE%] [%1]'
    $run = Invoke-EsCommand -FilePath $tool -Arguments @('--version') -TimeoutSec 30
    return @{ stdout = $run.stdout; command = $run.command; exit_code = $run.exit_code; error = $run.error; system_cmd = (Get-EsSystemTool 'cmd.exe') }
}

# ---- 12: the Defender policy read never opens an exclusion key or value (fake registry)
$script:FakeRegTree = @{
    'HKLM:\P\WD' = @('Exclusions', 'Policy Manager', 'Real-Time Protection', 'Windows Defender Exploit Guard')
    'HKLM:\P\WD\Exclusions' = @('Paths')
    'HKLM:\P\WD\Windows Defender Exploit Guard' = @('ASR', 'Controlled Folder Access')
    'HKLM:\P\WD\Windows Defender Exploit Guard\ASR' = @('ASROnlyExclusions', 'Rules')
    'HKLM:\P\WD\Windows Defender Exploit Guard\Controlled Folder Access' = @('AllowedApplications', 'ProtectedFolders')
}
$script:FakeRegValues = @{
    'HKLM:\P\WD' = @{ DisableAntiSpyware = 0; ExclusionsVisibleToLocalUsers = 1 }
    'HKLM:\P\WD\Exclusions\Paths' = @{ 'C:\secret\excluded' = 0 }
    'HKLM:\P\WD\Real-Time Protection' = @{ DisableRealtimeMonitoring = 0 }
    'HKLM:\P\WD\Windows Defender Exploit Guard\ASR' = @{ ExploitGuard_ASR_Rules = 1; ASROnlyPerRuleExclusions = 'x' }
    'HKLM:\P\WD\Windows Defender Exploit Guard\ASR\ASROnlyExclusions' = @{ 'C:\secret\asr-excluded.exe' = 0 }
    'HKLM:\P\WD\Windows Defender Exploit Guard\ASR\Rules' = @{ rule1 = '1' }
    'HKLM:\P\WD\Windows Defender Exploit Guard\Controlled Folder Access\AllowedApplications' = @{ 'C:\secret\allowed.exe' = 1 }
}
# The policy tree read: the IPSec policy key is denied to standard users (stock Windows).
$script:FakeRegTree['HKLM:\P\POL'] = @('Microsoft')
$script:FakeRegTree['HKLM:\P\POL\Microsoft'] = @('Windows')
$script:FakeRegTree['HKLM:\P\POL\Microsoft\Windows'] = @('IPSec', 'System')
$script:FakeRegTree['HKLM:\P\POL\Microsoft\Windows\IPSec'] = @('Policy')
$script:FakeRegValues['HKLM:\P\POL\Microsoft\Windows\IPSec\Policy'] = @{ ActivePolicy = 'x' }
$script:FakeRegValues['HKLM:\P\POL\Microsoft\Windows\System'] = @{ EnableSmartScreen = 1 }
function Invoke-FakeRegTree([string]$Root) {
    $script:FakeOpened = @()
    $tree = & {
        function Get-ChildItem { param([string]$LiteralPath, [switch]$Name, [switch]$Force, $ErrorAction, $ErrorVariable)
            $script:FakeOpened += ('list ' + $LiteralPath); return @($script:FakeRegTree[$LiteralPath]) }
        function Get-Item { param([string]$LiteralPath, [switch]$Force, $ErrorAction)
            $script:FakeOpened += ('open ' + $LiteralPath)
            $known = $script:FakeRegValues[$LiteralPath]
            if ($null -eq $known) { $known = @{} }
            return @{ Property = @($known.Keys) } }
        function Get-ItemProperty { param([string]$LiteralPath, [string[]]$Name, $ErrorAction)
            $script:FakeOpened += ('read ' + $LiteralPath + ' : ' + (@($Name) -join ', '))
            return $script:FakeRegValues[$LiteralPath] }
        Get-EsRegTree $Root 200 $script:ES_POLICY_SKIP_RE $script:ES_POLICY_SKIP_VALUE_RE
    }
    return @{ opened = @($script:FakeOpened); keys = @($tree.Keys | Sort-Object) }
}
$cases.defender = Get-Case { Invoke-FakeRegTree 'HKLM:\P\WD' }
$cases.policy_ipsec = Get-Case { Invoke-FakeRegTree 'HKLM:\P\POL' }
# The real policy tree, as sec.av reads it (--deep): no denied IPSec key on this machine.
$cases.policy_ipsec_real = Get-Case {
    $script:ES_DENIED_READS = @()
    $null = Get-EsRegTree 'HKLM:\SOFTWARE\Policies' 600 $script:ES_POLICY_SKIP_RE $script:ES_POLICY_SKIP_VALUE_RE
    $denied = @($script:ES_DENIED_READS)
    $script:ES_DENIED_READS = @()
    return , $denied
}

# ---- 13: one unreadable subkey does not hide the others; a denied read makes the probe partial
$cases.subkeys = Get-Case {
    $script:ES_DENIED_READS = @()
    $root = @(Get-EsRegSubkeys 'HKLM:\')
    $null = @(Get-EsRegSubkeys 'HKLM:\SOFTWARE\EnvscanNoSuchKey')
    $missing = @($script:ES_DENIED_READS)
    $null = @(Get-EsRegSubkeys 'HKLM:\SECURITY')
    return @{ root = $root; missing_issues = $missing; denied_issues = @($script:ES_DENIED_READS) }
}
function probe_test_denied { $r = New-EsResult; $r.data.names = @(Get-EsRegSubkeys 'HKLM:\SECURITY'); return $r }
function probe_test_clean { $r = New-EsResult; $r.data.names = @(Get-EsRegSubkeys 'HKLM:\SOFTWARE\EnvscanNoSuchKey'); return $r }
$cases.subkeys_probe = Get-Case {
    Reset-EsRun
    $envelope = Invoke-EsProbe @{ id = 'test.denied'; tier = 'default'; scope = 'machine'; title = 'denied' }
    return @{ status = $envelope.status; notes = @($envelope.notes) }
}
$cases.subkeys_probe_clean = Get-Case {
    Reset-EsRun
    $envelope = Invoke-EsProbe @{ id = 'test.clean'; tier = 'default'; scope = 'machine'; title = 'clean' }
    return @{ status = $envelope.status; notes = @($envelope.notes) }
}

# ---- 14: git and a home folder on the network
$cases.git_home = Get-Case {
    $script:ES_NETWORK_DRIVES = @('H:')
    $script:ES_ENV_SNAPSHOT = @{ HOMEDRIVE = 'H:'; HOMEPATH = '\'; USERPROFILE = 'C:\Users\u' }
    $network = Get-EsGitHome
    $script:ES_ENV_SNAPSHOT = @{ HOME = 'C:\Users\u'; HOMEDRIVE = 'H:'; HOMEPATH = '\' }
    $explicit = Get-EsGitHome
    $script:ES_ENV_SNAPSHOT = @{ USERPROFILE = 'C:\Users\u' }
    $profileOnly = Get-EsGitHome
    # Git for Windows takes HOMEDRIVE + HOMEPATH only when that folder exists.
    $script:ES_ENV_SNAPSHOT = @{ HOMEDRIVE = $env:SystemDrive; HOMEPATH = '\envscan-no-such-home'; USERPROFILE = 'C:\Users\u' }
    $missing = Get-EsGitHome
    $script:ES_ENV_SNAPSHOT = @{ HOMEDRIVE = $Scratch.Substring(0, 2); HOMEPATH = $noDrive; USERPROFILE = 'C:\Users\u' }
    $existing = Get-EsGitHome
    $script:ES_NETWORK_DRIVES = @()
    return @{ network = $network; explicit = $explicit; profile = $profileOnly; missing_local = $missing; existing_local = $existing }
}
$fakeGit = Join-Path $Scratch 'fakegit'
$null = New-Item -ItemType Directory -Path $fakeGit
Set-Content -LiteralPath (Join-Path $fakeGit 'git.cmd') -Encoding Ascii -Value @('@echo off',
    "echo file:x`tcore.home=%HOME%",
    "echo file:x`thttp.proxy=http://gp:GitPw9@gitproxy.corp:3128",
    "echo file:x`turl.https://gu:GitPw8@git.corp.example/.insteadof=https://github.com/")
function Invoke-FakeGit([hashtable]$Snapshot, [string[]]$NetworkDrives) {
    Reset-EsPathCache $Snapshot
    $script:ES_NETWORK_DRIVES = $NetworkDrives
    $before = $env:HOME
    $r = New-EsResult
    try { $git = Get-EsGitConfig $r } finally { $script:ES_NETWORK_DRIVES = @() }
    $homeItem = @($git.items | Where-Object { $_.key -eq 'core.home' }) | Select-Object -First 1
    return @{ home = [string]$homeItem.value; local_home = (Join-Path $script:ES_TMP 'githome'); status = $r.status
        notes = @($r.notes); caller_home = $env:HOME; caller_home_before = $before; git = $git }
}
$cases.git_network_home = Get-Case {
    $result = Invoke-FakeGit @{ Path = $fakeGit; PATHEXT = '.CMD;.EXE'; HOMEDRIVE = 'H:'; HOMEPATH = '\envscan-home'; USERPROFILE = [string]$env:USERPROFILE } @('H:')
    $result.Remove('git')
    return $result
}
$cases.git_local_home = Get-Case {
    $result = Invoke-FakeGit @{ Path = $fakeGit; PATHEXT = '.CMD;.EXE'; HOME = [string]$env:USERPROFILE; USERPROFILE = [string]$env:USERPROFILE } @('H:')
    $result.Remove('git')
    return $result
}
$cases.git_urls = Get-Case {
    $result = Invoke-FakeGit @{ Path = $fakeGit; PATHEXT = '.CMD;.EXE'; HOME = [string]$env:USERPROFILE; USERPROFILE = [string]$env:USERPROFILE } @()
    $git = $result.git
    return @{ endpoints = @($git.urls); proxy_urls = @($git.proxy_urls | ForEach-Object { @{ tool = $_.tool; url = $_.url } }) }
}
# Third review 2026-11-12: a git home, .gitconfig, XDG git folder or ProgramData behind a link
# (Get-EsPathLinkReason, faked here) is treated like one on the network.
$cases.git_link_locations = Get-Case {
    Reset-EsRun
    $out = @{ local = (Join-Path $script:ES_TMP 'githome') }
    $links = @(@('home', 'C:\Users\u'), @('gitconfig', 'C:\Users\u\.gitconfig'), @('xdg', 'C:\Users\u\.config\git'),
        @('programdata', 'C:\ProgramData\Git'), @('clean', 'C:\nothing'), @('unc_programdata', 'C:\nothing'))
    foreach ($pair in $links) {
        $pd = $(if ($pair[0] -eq 'unc_programdata') { '\\srv\pd' } else { 'C:\ProgramData' })
        $script:ES_ENV_SNAPSHOT = @{ HOME = 'C:\Users\u'; ProgramData = $pd }
        $script:LinkedPath = $pair[1]
        $r = New-EsResult
        $childEnv = & {
            function Get-EsPathLinkReason([string]$Path) {
                if ($Path.StartsWith($script:LinkedPath, [System.StringComparison]::OrdinalIgnoreCase)) { return 'link to a network path' }
                return $null
            }
            Get-EsGitChildEnv $r
        }
        $childEnv.Remove('GIT_CEILING_DIRECTORIES')
        $out[$pair[0]] = @{ env = $childEnv; status = $r.status; notes = @($r.notes) }
    }
    return $out
}
Reset-EsPathCache @{}

# ---- 20: git include files are read one level deep, local files only (git runs with
# --no-includes); a git without --no-includes or --show-origin runs again without it
$cases.git_unquote = Get-Case {
    return @{
        plain = ConvertFrom-EsGitQuoted 'C:/Users/u/.gitconfig'
        escapes = ConvertFrom-EsGitQuoted '"C:\\a\tb\"c\""'
        utf8 = ConvertFrom-EsGitQuoted '"q\303\266\360\237\230\200/x"'
        origin = Get-EsGitOriginFile 'file:"C:/Users/J\303\266rg/.gitconfig"'
        origin_plain = Get-EsGitOriginFile 'file:C:/Program Files/Git/etc/gitconfig'
        command_line = Get-EsGitOriginFile 'command line:'
        # Malformed: not UTF-8, no closing quote, an escaped closing quote, an escape git never writes.
        bad_utf8 = ConvertFrom-EsGitQuoted '"q\377x"'
        unterminated = ConvertFrom-EsGitQuoted '"abc'
        dangling = ConvertFrom-EsGitQuoted '"abc\"'
        unknown_escape = ConvertFrom-EsGitQuoted '"a\qb"'
        origin_bad = Get-EsGitOriginFile 'file:"C:/x/\377/.gitconfig"'
    }
}
# Credential stores are never opened or tested; reserved device names are never opened.
$cases.cred_names = Get-Case {
    $out = @{}
    foreach ($path in @('C:\Users\u\.ssh\config', 'C:\Users\u\.SSH', 'D:\x\.aws\credentials', 'C:/k/.kube/config',
            'C:\Users\u\.netrc', 'C:\Users\u\_NETRC', 'C:/Users/u/.git-credentials', 'C:\x\Auth.json',
            'C:\Users\u\.docker\config.json', 'C:\Users\u\.bash_history', 'C:\x\ConsoleHost_history.txt',
            'C:\Users\u\.history', 'C:/Users/u/.ZHISTORY', 'C:\Users\u\.histfile',
            'C:\Users\u\.npmrc', 'C:\x\config.json', 'C:\x\sshd\x', 'C:\x\my.netrc.bak', 'C:\x\auth.json.bak',
            'C:\x\history', 'C:\x\.history.bak', 'C:\x\my.histfile',
            'C:\Users\u\.ssh.\config', 'C:\Users\u\.ssh \config', 'C:\Users\u\.netrc. ', 'C:\Users\u\.netrc::$DATA',
            'C:\x\pip.ini:hidden', 'C:\Users\u\SSH~1\config', 'C:\Users\u\GIT-CR~1', 'C:\Users\u\BASH_H~1',
            '\\?\C:\Users\u\.ssh\config',
            'C:\PROGRA~1\Git\etc\gitconfig', '\\?\C:\x\pip.ini', 'C:\x\a.b.\pip.ini',
            'C:\Users\u\.gnupg\pubring.kbx', 'C:\Users\u\.gnupg', 'C:\Users\u\AppData\Roaming\postgresql\.pgpass', 'C:\Users\u\.pgpass', 'C:\Users\u\.azure\msal_token_cache.json', 'C:\Users\u\.config\gcloud\credentials.db', 'C:/Users/u/.config/gh/hosts.yml', 'C:\Users\u\.terraform.d\credentials.tfrc.json', 'C:\Users\u\.vault-token', 'C:\Users\u\.pypirc', 'C:\Users\u\.gem\credentials', 'C:\Users\u\.cargo\credentials.toml', 'C:\Users\u\.m2\settings-security.xml', 'C:\var\run\secrets\kubernetes.io\serviceaccount\token', 'C:\certs\client.pem', 'C:\certs\server.KEY', 'C:\certs\me.p12', 'C:\certs\me.pfx', 'C:\certs\store.jks', 'C:\certs\app.keystore', 'C:\Users\u\keys\id_rsa', 'C:\Users\u\keys\id_ecdsa', 'C:\Users\u\keys\ID_ED25519',
            'C:\jdk\lib\security\cacerts', 'C:\x\ca-bundle.pem', 'C:\x\cert.pem', 'C:\x\tls-ca-bundle.pem', 'C:\Users\u\.gem\specs', 'C:\Users\u\.cargo\config.toml', 'C:\Users\u\.m2\settings.xml', 'C:\Users\u\.config\gh\config.yml', 'C:\Users\u\keys\id_rsa.pub', 'C:\x\monkey.txt', 'C:\x\token', 'C:\x\keystore.txt')) {
        $out[$path] = [bool](Test-EsCredentialPath $path)
    }
    return $out
}
# Round 6: credential paths are normalised (separators, doubled separators, ".", "..", trailing
# separators) and any 8.3 short name that may stand for a store is a risk.
$cases.cred_names_normalised = Get-Case {
    $out = @{}
    foreach ($path in @('C:\Users\u\.config\.\gcloud\x', 'C:\Users\u\.docker\\config.json', 'C:/Users/u/.docker//config.json',
            'C:\var\run\secrets\kubernetes.io\serviceaccount\\token', 'C:\Users\u\x\..\.ssh\config',
            'C:\Users\u\.ssh\x\..\config', 'C:\certs\x.pem\', 'C:\certs\x.pem/', 'C:\Users\u\.config\gcloud\.',
            'C:\Users\u\.docker\.\config.json', 'C:\Users\u\.docker\config.json\\',
            'C:\Users\u\TERRAF~1.D\credentials.tfrc.json', 'C:\Users\u\CONFIG~1\gcloud', 'C:\Users\u\CARGO~1\credentials.toml',
            'C:\Users\u\GEM~1\credentials', 'C:\Users\u\M2~1\settings-security.xml', 'C:\Users\u\SERVIC~1\token',
            'C:\Users\u\.ssh\.. \config',
            'C:\Users\u\a\..\b\x.txt', 'C:\x\.\y\z.txt', 'C:\x\\y\z.txt', 'C:\PROGRA~1\Git\etc\gitconfig',
            'C:\x\ca-bundle.pem\', 'C:\Users\u\.docker\other.json', 'C:\Users\u\PROGRA~2\Tool\a.txt')) {
        $out[$path] = [bool](Test-EsCredentialPath $path)
    }
    return $out
}
$cases.link_target_normalised = Get-Case {
    $out = @{}
    if ($script:ES_PS_MAJOR -ge 5) {
        $out.dotdot = Get-EsLinkTarget @{ Target = '..\.\x' } 'C:\a\b\link'
        $out.doubled = Get-EsLinkTarget @{ Target = 'sub\\.\.ssh' } 'C:\a\b\link'
        $out.absolute_dots = Get-EsLinkTarget @{ Target = 'C:\a\.\b\..\c' } 'C:\a\b\link'
    }
    return $out
}
$cases.device_names = Get-Case {
    $out = @{}
    foreach ($path in @('C:\x\NUL', 'C:\x\nul.txt', 'C:\x\Con', 'C:/x/com1', 'C:\x\LPT9.log', 'C:\x\CONIN$', 'C:\x\conout$',
            'C:\x\aux.gitconfig', 'C:\x\PRN', 'C:\x\COM0', 'C:\x\console', 'C:\x\nul2', 'C:\x\icon.txt', 'C:\x\COM10')) {
        $out[$path] = [bool](Test-EsDeviceName $path)
    }
    return $out
}
# Get-Item, Get-ChildItem and Test-Path calls, recorded and passed on (a credential store must
# never appear). $script:SpyLists holds the folders listed.
function Invoke-WithPathSpy([scriptblock]$Block) {
    $script:SpyPaths = @()
    $script:SpyLists = @()
    $script:ES_LINK_CACHE = @{}
    return (& {
            function Get-Item { param([string]$Path, [string]$LiteralPath, [switch]$Force, $ErrorAction = 'Continue')
                $script:SpyPaths += ($LiteralPath + $Path)
                if ($LiteralPath) { Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force:$Force -ErrorAction $ErrorAction }
                else { Microsoft.PowerShell.Management\Get-Item -Path $Path -Force:$Force -ErrorAction $ErrorAction } }
            function Get-ChildItem { param([string]$LiteralPath, [switch]$Force, [switch]$Name, $ErrorAction = 'Continue', [string]$Path)
                # env: is listed by Get-EsProcessEnv (the child environment), never a folder.
                if ($Path -eq 'env:') { return (Microsoft.PowerShell.Management\Get-ChildItem -Path 'env:' -ErrorAction $ErrorAction) }
                $script:SpyLists += $LiteralPath.TrimEnd('\')
                Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $LiteralPath -Force:$Force -Name:$Name -ErrorAction $ErrorAction }
            function Test-Path { param([string]$LiteralPath, $PathType = 'Any')
                $script:SpyPaths += $LiteralPath
                Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath -PathType $PathType }
            & $Block
        })
}
$cases.cred_paths = Get-Case {
    $credHome = Join-Path $Scratch 'credhome'
    $null = New-Item -ItemType Directory -Path (Join-Path $credHome '.ssh')
    foreach ($name in @('.netrc', '.ssh\config', 'auth.json', 'ConsoleHost_history.txt', 'pip.ini')) {
        Set-Content -LiteralPath (Join-Path $credHome $name) -Encoding Ascii -Value 'x' }
    $env:ENVSCAN_T_NETRC = Join-Path $credHome '.netrc'
    $env:ENVSCAN_T_CRED = $credHome
    $env:ENVSCAN_T_GLOB = Join-Path $credHome '.ss?'
    $out = Invoke-WithPathSpy {
        @{
            netrc = @(Expand-EsPathPattern '{env:ENVSCAN_T_NETRC}')
            ssh = @(Expand-EsPathPattern '{env:ENVSCAN_T_CRED}/.ssh/config')
            ssh_glob = @(Expand-EsPathPattern '{env:ENVSCAN_T_CRED}/.ssh/*')
            auth = @(Expand-EsPathPattern '{env:ENVSCAN_T_CRED}/AUTH.JSON')
            history = @(Expand-EsPathPattern '{env:ENVSCAN_T_CRED}/ConsoleHost_history.txt')
            history_glob = @(Expand-EsPathPattern '{env:ENVSCAN_T_CRED}/*_history.txt')
            any_glob = @(Expand-EsPathPattern '{env:ENVSCAN_T_CRED}/*')
            control = @(Expand-EsPathPattern '{env:ENVSCAN_T_CRED}/pip.ini')
            # A "*" in a folder component, or a {env:} value holding one, could match .ssh.
            ssh_star_dir = @(Expand-EsPathPattern '{env:ENVSCAN_T_CRED}/.ss*/config')
            star_dir = @(Expand-EsPathPattern '{env:ENVSCAN_T_CRED}/*/config')
            env_glob_dir = @(Expand-EsPathPattern '{env:ENVSCAN_T_GLOB}/config')
        }
    }
    $out.touched = @($script:SpyPaths)
    $out.listed = @($script:SpyLists)
    $out.control_path = Join-Path $credHome 'pip.ini'
    return $out
}
$cases.device_paths = Get-Case {
    # A {env:X} path that names a reserved device (opening it opens the device) is never tested.
    $devHome = Join-Path $Scratch 'devhome'
    $null = New-Item -ItemType Directory -Path $devHome
    Set-Content -LiteralPath (Join-Path $devHome 'pip.ini') -Encoding Ascii -Value 'x'
    $env:ENVSCAN_T_DEVDIR = $devHome
    $env:ENVSCAN_T_CON = 'C:\envscan-none\CON'
    $out = Invoke-WithPathSpy {
        @{
            con = @(Expand-EsPathPattern '{env:ENVSCAN_T_CON}')
            nul_ext = @(Expand-EsPathPattern '{env:ENVSCAN_T_DEVDIR}/nul.txt')
            com = @(Expand-EsPathPattern '{env:ENVSCAN_T_DEVDIR}/COM1.cfg')
            conin = @(Expand-EsPathPattern '{env:ENVSCAN_T_DEVDIR}/conin$')
            lpt = @(Expand-EsPathPattern '{env:ENVSCAN_T_DEVDIR}/Lpt9')
            control = @(Expand-EsPathPattern '{env:ENVSCAN_T_DEVDIR}/pip.ini')
        }
    }
    $out.touched = @($script:SpyPaths)
    $out.control_path = Join-Path $devHome 'pip.ini'
    return $out
}
$cases.git_include_paths = Get-Case {
    $origin = 'C:\cfg\.gitconfig'
    return @{
        relative = Resolve-EsGitIncludePath 'sub/x.cfg' $origin 'C:\home'
        parent = Resolve-EsGitIncludePath '../x.cfg' $origin 'C:\home'
        tilde = Resolve-EsGitIncludePath '~/x.cfg' $origin 'C:/home/'
        tilde_unset = Resolve-EsGitIncludePath '~/x.cfg' $origin ''
        tilde_user = Resolve-EsGitIncludePath '~bob/x.cfg' $origin 'C:\home'
        absolute = Resolve-EsGitIncludePath 'D:/x.cfg' $origin 'C:\home'
        unc = Resolve-EsGitIncludePath '//srv/share/x.cfg' $origin 'C:\home'
        device = Resolve-EsGitIncludePath '//?/C:/x.cfg' $origin 'C:\home'
        root_relative = Resolve-EsGitIncludePath '/etc/x.cfg' $origin 'C:\home'
        drive_relative = Resolve-EsGitIncludePath 'C:x.cfg' $origin 'C:\home'
        prefix = Resolve-EsGitIncludePath '%(prefix)/etc/x.cfg' $origin 'C:\home'
        no_origin = Resolve-EsGitIncludePath 'x.cfg' '' 'C:\home'
    }
}
function New-GitStub([string]$Name, [string[]]$Lines) {
    $dir = Join-Path $Scratch $Name
    $null = New-Item -ItemType Directory -Path $dir
    Set-Content -LiteralPath (Join-Path $dir 'git.cmd') -Encoding Ascii -Value (@('@echo off') + $Lines)
    return $dir
}
$incCfg = Join-Path $Scratch 'gitcfg'
$incHome = Join-Path $Scratch 'githome-inc'
$incQuoted = Join-Path $incCfg ('q' + [char]0xF6)
foreach ($dir in @($incCfg, $incHome, $incQuoted)) { $null = New-Item -ItemType Directory -Path $dir }
foreach ($file in @('gitcfg\inc.gitconfig', 'gitcfg\locked.gitconfig', 'githome-inc\home.gitconfig')) {
    Set-Content -LiteralPath (Join-Path $Scratch $file) -Encoding Ascii -Value '' }
Set-Content -LiteralPath (Join-Path $incQuoted 'q.gitconfig') -Encoding Ascii -Value ''
$cfgOrigin = 'file:' + $incCfg.Replace('\', '/') + '/.gitconfig'
# git config --list --show-origin --no-includes (4 arguments) lists the main configuration;
# "... --file <path>" (6 arguments) lists one include file.
$incGit = New-GitStub 'gitinc' @('if "%5"=="--file" goto included',
    "echo $cfgOrigin`tuser.name=tester",
    "echo $cfgOrigin`tinclude.path=inc.gitconfig",
    "echo $cfgOrigin`tinclude.path=~/home.gitconfig",
    "echo $cfgOrigin`tinclude.path=//envscan-test-server/share/team.gitconfig",
    "echo $cfgOrigin`tinclude.path=/etc/gitconfig-extra",
    "echo $cfgOrigin`tinclude.path=locked.gitconfig",
    "echo $cfgOrigin`tinclude.path=absent.gitconfig",
    "echo $cfgOrigin`tinclude.path=inc.gitconfig",
    "echo $cfgOrigin`tincludeif.gitdir:~/work/.path=~/work.gitconfig",
    "echo $cfgOrigin`tincludeif.hasconfig:remote.*.url:https://ci:HasPw55@git.corp.example/**.path=~/hc.gitconfig",
    ('echo file:"' + $incCfg.Replace('\', '/') + '/q\303\266/.gitconfig"' + "`tinclude.path=q.gitconfig"),
    "echo command line:`tinclude.path=cl.gitconfig",
    'exit /b 0',
    ':included',
    'if /i "%~nx6"=="inc.gitconfig" goto inc',
    'if /i "%~nx6"=="home.gitconfig" goto home',
    'if /i "%~nx6"=="q.gitconfig" goto quoted',
    'echo fatal: unable to read config file %6 1>&2', 'exit /b 128',
    ':inc',
    "echo file:x`thttp.proxy=http://ip:IncPw7@incproxy.corp:3128",
    "echo file:x`tinclude.path=nested.gitconfig",
    "echo file:x`tincludeif.onbranch:main.path=nested2.gitconfig",
    'exit /b 0',
    ':home', "echo file:x`tcore.fromhome=yes", 'exit /b 0',
    ':quoted', "echo file:x`tcore.fromquoted=yes", 'exit /b 0')
$condGit = New-GitStub 'gitcond' @("echo $cfgOrigin`tincludeif.gitdir:~/work/.path=~/work.gitconfig")
# git 1.7.10 to 2.7 has no --show-origin, git before 1.7.10 has no --no-includes either (and no
# includes: its include.path is an ordinary entry, even when it names an existing file).
$oldGit = New-GitStub 'gitold' @('set "ARGS=%*"', 'if not "%ARGS:--no-includes=%"=="%ARGS%" goto reject',
    "echo file:x`tcore.editor=vim", "echo file:x`tinclude.path=$($incHome.Replace('\', '/'))/home.gitconfig",
    "echo file:x`tincludeif.gitdir:~/work/.path=~/work.gitconfig", 'exit /b 0',
    ':reject', 'echo error: unknown option `no-includes'' 1>&2', 'echo usage: git config [options] 1>&2', 'exit /b 129')
$ancientGit = New-GitStub 'gitancient' @('set "ARGS=%*"', 'if not "%ARGS:--show-origin=%"=="%ARGS%" goto origin',
    'if not "%ARGS:--no-includes=%"=="%ARGS%" goto includes', 'echo core.editor=vim', 'exit /b 0',
    ':origin', 'echo error: unknown option `show-origin'' 1>&2', 'exit /b 129',
    ':includes', 'echo error: unknown option `no-includes'' 1>&2', 'exit /b 129')
$failGit = New-GitStub 'gitfail' @('echo fatal: bad config line 1 in file C:/x/.gitconfig 1>&2', 'exit /b 128')
function probe_test_gitinc { $r = New-EsResult; $r.data.git = Get-EsGitConfig $r; return $r }
function Invoke-GitProbe([string]$StubDir, [hashtable]$HomeVars = @{ HOME = $incHome }, [string[]]$NetworkDrives = @()) {
    # pkg.sources' git part as a probe: the envelope is what reaches the report (redacted).
    Reset-EsRun
    $snapshot = @{ Path = $StubDir; PATHEXT = '.CMD;.EXE'; USERPROFILE = [string]$env:USERPROFILE }
    foreach ($name in @($HomeVars.Keys)) { $snapshot[$name] = $HomeVars[$name] }
    Reset-EsPathCache $snapshot
    $script:ES_NETWORK_DRIVES = $NetworkDrives
    try { $envelope = Invoke-EsProbe @{ id = 'test.gitinc'; tier = 'default'; scope = 'user'; title = 'git includes' } }
    finally { $script:ES_NETWORK_DRIVES = @() }
    Reset-EsPathCache @{}
    $git = $envelope.data.git
    if ($null -eq $git) { $git = @{ items = @(); urls = @(); proxy_urls = @() } }
    return @{ status = $envelope.status; notes = @($envelope.notes | Where-Object { $_ }); sources = @($envelope.sources); items = @($git.items)
        urls = @($git.urls); proxy_urls = @($git.proxy_urls); json = (ConvertTo-EsJson $envelope); cfg_dir = $incCfg; home_dir = $incHome }
}
$cases.git_includes = Get-Case { Invoke-GitProbe $incGit }
$cases.git_conditional = Get-Case { Invoke-GitProbe $condGit }
$cases.git_old = Get-Case { Invoke-GitProbe $oldGit }
$cases.git_ancient = Get-Case { Invoke-GitProbe $ancientGit }
$cases.git_failed = Get-Case { Invoke-GitProbe $failGit }
# Include targets never opened: credential stores (never tested either), device names, folders;
# an origin git quoted that does not decode; ~/ is the user's real home, also when git runs with
# a local stand-in for a home on the network.
$null = New-Item -ItemType Directory -Path (Join-Path $incHome '.ssh')
$null = New-Item -ItemType Directory -Path (Join-Path $incCfg 'subdir')
foreach ($name in @('.ssh\config', '.git-credentials', 'team.gitconfig')) {
    Set-Content -LiteralPath (Join-Path $incHome $name) -Encoding Ascii -Value '' }
$guardGit = New-GitStub 'gitguard' @('if "%5"=="--file" goto included',
    "echo $cfgOrigin`tinclude.path=~/.ssh/config",
    "echo $cfgOrigin`tinclude.path=~/.git-credentials",
    "echo $cfgOrigin`tinclude.path=NUL",
    "echo $cfgOrigin`tinclude.path=con.gitconfig",
    "echo $cfgOrigin`tinclude.path=subdir",
    "echo $cfgOrigin`tinclude.path=~/team.gitconfig",
    ('echo file:"' + $incCfg.Replace('\', '/') + '/\377/.gitconfig"' + "`tinclude.path=x.gitconfig"),
    'exit /b 0',
    ':included', "echo file:x`tcore.fromteam=yes", 'exit /b 0')
$cases.git_include_guards = Get-Case {
    $result = Invoke-WithPathSpy { Invoke-GitProbe $guardGit }
    $result.touched = @($script:SpyPaths)
    return $result
}
$cases.git_include_network_home = Get-Case {
    Invoke-GitProbe $guardGit @{ HOMEDRIVE = 'H:'; HOMEPATH = '\envscan-home' } @('H:')
}

# ---- 15: process trees and PID reuse
$cases.tree = Get-Case {
    $t0 = [datetime]'2026-11-11T10:00:00'
    $cim = @(
        @{ ProcessId = 100; ParentProcessId = 4; CreationDate = $t0 },
        @{ ProcessId = 101; ParentProcessId = 100; CreationDate = $t0.AddSeconds(1) },
        @{ ProcessId = 102; ParentProcessId = 101; CreationDate = $t0.AddSeconds(2) },
        @{ ProcessId = 103; ParentProcessId = 100; CreationDate = $t0 },
        @{ ProcessId = 200; ParentProcessId = 100; CreationDate = $t0.AddSeconds(-60) },
        @{ ProcessId = 201; ParentProcessId = 200; CreationDate = $t0.AddSeconds(-30) }
    )
    $wmi = @(
        @{ ProcessId = 500; ParentProcessId = 4; CreationDate = '20261111100000.000000+060' },
        @{ ProcessId = 501; ParentProcessId = 500; CreationDate = '20261111093000.000000+000' },
        @{ ProcessId = 502; ParentProcessId = 500; CreationDate = '20261111085959.000000+000' }
    )
    return @{ cim = @(Select-EsDescendants 100 $cim); wmi = @(Select-EsDescendants 500 $wmi); unknown_root = @(Select-EsDescendants 999 $cim) }
}

# ---- 16: --net targets (fake resolver and TCP check: no traffic)
$cases.reach = Get-Case {
    Reset-EsRun
    $script:ES_OPT.net = $true
    Set-EsFakeResult 'net.proxy' 'ok' @{ proxy_endpoints = @(
            @{ host = 'proxy.corp.example'; port = 8080; source = 'env HTTP_PROXY' },
            @{ host = 'registry.npmjs.org'; port = 443; source = 'config npm' },
            @{ host = 'metadata.google.internal'; port = 80; source = 'config x' },
            @{ host = '169.254.169.254'; port = 80; source = 'config y' }) }
    Set-EsFakeResult 'pkg.sources' 'ok' @{ endpoints = @('https://pypi.org', 'https://files.pythonhosted.org',
            'https://nexus.corp.example:8443', 'https://rebind.corp.example', 'https://mixed.corp.example') }
    $script:FakeResolved = @()
    $script:FakeTcp = @()
    $result = & {
        function Resolve-EsHostName([string]$HostName) {
            $script:FakeResolved += $HostName
            $addresses = @('10.0.0.9')
            if ($HostName -eq 'rebind.corp.example') { $addresses = @('169.254.169.254') }
            if ($HostName -eq 'mixed.corp.example') { $addresses = @('10.0.0.5', 'fe80::1%12') }
            return @{ status = 'ok'; addresses = $addresses; error = $null; method = 'dns' }
        }
        function Test-EsTcpPort([string]$Address, [int]$Port, [int]$TimeoutMs) {
            $script:FakeTcp += ($Address + ':' + $Port)
            return @{ tcp = 'ok'; ms = 1; error = $null }
        }
        probe_net_reachability
    }
    Reset-EsRun
    return @{ resolved = @($script:FakeResolved); tcp = @($script:FakeTcp); targets = @($result.data.targets); notes = @($result.notes); status = $result.status }
}
# ---- --net lookups (second review 2026-11-11): only a definitive "no address" is unresolved, a
# failed lookup is an error, no resolver means no name is contacted, and an IPv6 address outside
# the global and unique-local ranges is never contacted. The resolvers below the literal check
# are faked (Resolve-EsHostNameDns in FullLanguage, Resolve-EsHostNameNslookup otherwise).
function Get-FakeAnswer([string]$HostName) {
    $script:FakeResolved += $HostName
    if ($script:FakeAnswers.ContainsKey('unavailable')) { return @{ status = 'unavailable'; addresses = @(); error = $null; method = 'none' } }
    # Names arrive in their absolute form (x.corp.example.); the answers are keyed without the dot.
    return $script:FakeAnswers[($HostName -replace '\.\z', '')]
}
function Invoke-FakeReach([hashtable]$Answers, [object[]]$Endpoints) {
    Reset-EsRun
    $script:ES_OPT.net = $true
    Set-EsFakeResult 'net.proxy' 'ok' @{ proxy_endpoints = $Endpoints }
    Set-EsFakeResult 'pkg.sources' 'ok' @{ endpoints = @() }
    $script:FakeAnswers = $Answers
    $script:FakeResolved = @()
    $script:FakeTcp = @()
    $result = & {
        function Resolve-EsHostNameDns([string]$HostName) { Get-FakeAnswer $HostName }
        function Resolve-EsHostNameNslookup([string]$HostName) { Get-FakeAnswer $HostName }
        function Test-EsTcpPort([string]$Address, [int]$Port, [int]$TimeoutMs) {
            $script:FakeTcp += ($Address + '|' + $Port)
            return @{ tcp = 'ok'; ms = 1; error = $null }
        }
        probe_net_reachability
    }
    Reset-EsRun
    return @{ resolved = @($script:FakeResolved); tcp = @($script:FakeTcp); targets = @($result.data.targets); notes = @($result.notes); status = $result.status }
}
# Third review 2026-11-12: a probe that adds another probe's data is partial (noted) when that
# probe did not complete, instead of ok or not_found from the missing data.
$cases.missing_inputs = Get-Case {
    $out = @{}
    foreach ($status in @('', 'skipped', 'error', 'ok')) {
        Reset-EsRun
        $script:ES_ENV_SNAPSHOT = @{}
        $script:ES_OPT.net = $true
        if ($status) {
            Set-EsFakeResult 'pkg.sources' $status @{ endpoints = @(); proxy_urls = @() }
            Set-EsFakeResult 'net.proxy' $status @{ proxy_endpoints = @() }
        }
        $proxy = & { function Get-EsRegValues { return $null }; function Get-EsRegBytes { return $null }; probe_net_proxy }
        $reach = probe_net_reachability
        $name = $(if ($status) { $status } else { 'not_run' })
        $out[$name] = @{ proxy_status = $proxy.status; proxy_notes = @($proxy.notes); reach_status = $reach.status; reach_notes = @($reach.notes) }
    }
    Reset-EsRun
    return $out
}
# Third review 2026-11-12: a table keyed by names from the system (environment variables,
# registry values, folder names) may hold "Keys" or "Count": .Keys and .Count would return that
# entry's value, so the library uses .PSBase.Keys and .PSBase.Count.
$cases.system_keys = Get-Case {
    Reset-EsRun
    $script:ES_ENV_SNAPSHOT = @{ Keys = 'zzz'; Count = 'many'; Path = 'C:\x' }
    $vars = & {
        function Get-EsRegValues { return @{ Keys = 'k'; Count = 'c'; Plain = 'p' } }
        probe_env_vars
    }
    $tree = & {
        function Get-EsRegValues { return @{ Keys = 'k'; Count = 'c' } }
        function Get-EsRegSubkeys { return @() }
        Get-EsRegTree 'HKLM:\SOFTWARE\x'
    }
    $limited = Limit-EsTableValues @{ Keys = 'k'; Count = 'c'; Other = 'o' }
    Set-EsFakeResult 'user.identity' 'ok' @{ is_admin = $false }
    Set-EsFakeResult 'user.profile' 'ok' @{ profile_type = 'local'; redirected_folders = @{ Keys = '\\srv\k'; Count = '\\srv\c' } }

    $findings = @(Get-EsUserFindings)
    $out = @{
        vars_process = @($vars.data.process.PSBase.Keys | Sort-Object); vars_count = $vars.data.count
        vars_machine = @($vars.data.machine.PSBase.Keys | Sort-Object)
        tree = @($tree.PSBase.Keys | Sort-Object); limited = @($limited.PSBase.Keys | Sort-Object)
        findings = @($findings | Where-Object { $_ } | ForEach-Object { [string]$_.detail })
    }
    Reset-EsRun
    return $out
}
$cases.reach_lookup = Get-Case {
    $answers = @{
        'nxdomain.corp.example' = @{ status = 'none'; addresses = @(); error = $null; method = 'dns' }
        'slow.corp.example' = @{ status = 'error'; addresses = @(); error = 'name lookup timed out'; method = 'dns' }
        'v6bad.corp.example' = @{ status = 'ok'; addresses = @('64:ff9b::a00:1', 'FF02::1', '::1', 'fd00:0EC2::11'); error = $null; method = 'dns' }
        'v6good.corp.example' = @{ status = 'ok'; addresses = @('fd00:ec2::10', '2001:DB8::10'); error = $null; method = 'dns' }
        'dual.corp.example' = @{ status = 'ok'; addresses = @('fd12::7', '10.0.0.7'); error = $null; method = 'dns' }
        'ula.corp.example' = @{ status = 'ok'; addresses = @('fd12:3456::1'); error = $null; method = 'dns' }
    }
    $endpoints = @()
    foreach ($pair in @(@('nxdomain.corp.example', 8080), @('slow.corp.example', 8080), @('v6bad.corp.example', 443),
            @('v6good.corp.example', 443), @('dual.corp.example', 443), @('ula.corp.example', 443), @('2001:db8::5', 3128),
            @('::1', 3128), @('fd00:ec2::7', 80), @('fe80::1%4', 80), @('3fff::1', 80), @('4000::1', 80))) {
        $endpoints += @{ host = $pair[0]; port = $pair[1]; source = 'config' }
    }
    $lookup = Invoke-FakeReach $answers $endpoints
    $none = Invoke-FakeReach @{ unavailable = $true } @(@{ host = 'proxy.corp.example'; port = 8080; source = 'env' }, @{ host = '10.1.2.3'; port = 8080; source = 'env' })
    # Security review 2026-11-12: only private and shared IPv4 (10/8, 172.16/12, 192.168/16,
    # 100.64/10) is contacted; any other literal or resolved IPv4 is skipped.
    $v4answers = @{
        'public.corp.example' = @{ status = 'ok'; addresses = @('93.184.216.34'); error = $null; method = 'dns' }
        'mixedv4.corp.example' = @{ status = 'ok'; addresses = @('8.8.8.8', '192.168.1.5'); error = $null; method = 'dns' }
    }
    $v4 = @()
    foreach ($pair in @(@('public.corp.example', 443), @('mixedv4.corp.example', 443), @('8.8.8.8', 80), @('172.32.0.1', 80),
            @('172.31.255.1', 80), @('100.64.0.1', 80), @('100.128.0.1', 80), @('127.0.0.1', 80), @('192.0.0.192', 80),
            @('fd20:ce::254', 80), @('2002:c000:204::1', 80))) {
        $v4 += @{ host = $pair[0]; port = $pair[1]; source = 'config' }
    }
    $ipv4 = Invoke-FakeReach $v4answers $v4
    return @{ lookup = $lookup; no_resolver = $none; ipv4 = $ipv4 }
}
$cases.ipv4_allowed = Get-Case {
    $out = @{}
    foreach ($value in @('10.0.0.1', '10.255.255.255', '172.16.0.1', '172.31.255.255', '172.15.0.1', '172.32.0.1',
            '192.168.0.1', '192.169.0.1', '100.64.0.1', '100.127.255.255', '100.63.0.1', '100.128.0.1', '8.8.8.8',
            '127.0.0.1', '0.0.0.0', '255.255.255.255', '010.0.0.1', '10.0.0.256', '10.0.0', 'fd00::1')) {
        $out[$value] = [bool](Test-EsIpv4Allowed $value)
    }
    return $out
}
# ---- net.proxy lists the settings pkg.sources found by name, never lines holding "proxy"
$cases.proxy_list = Get-Case {
    Reset-EsRun
    Reset-EsPathCache @{}
    $script:ES_PKG_PROXY_SETTINGS = @(@{ tool = 'npm'; setting = 'https-proxy'; value = 'http://proxy.corp:8080'; file = 'C:\Users\u\.npmrc' })
    $without = @((probe_net_proxy).data.package_managers)
    Set-EsFakeResult 'pkg.sources' 'ok' @{ proxy_urls = @(); configs = @(@{ tool = 'npm'; path = 'C:\x\.npmrc'; lines = @('registry=https://nexus.corp/repository/npm-proxy/') }) }
    $with = @((probe_net_proxy).data.package_managers)
    Reset-EsRun
    $script:ES_PKG_PROXY_SETTINGS = @()
    return @{ without = $without; with = $with }
}
$cases.ipv6_allowed = Get-Case {
    $out = @{}
    foreach ($value in @('2001:db8::1', '2000::', '3fff:ffff::1', '1fff::1', '4000::1', 'fc00::1', 'FDFF::1', 'fe00::1', 'fe80::1',
            'fd00:ec2::254', 'fd00:0ec2::1', 'fd00:ec20::1', 'fd00::ec2', '::1', '::ffff:10.0.0.1', '64:ff9b::a00:1', 'ff02::1',
            '2001:db8::1%3', '[2001:db8::1]', '02001::1', 'g001::1', '10.0.0.1')) {
        $out[$value] = [bool](Test-EsIpv6Allowed $value)
    }
    return $out
}
$cases.nslookup = Get-Case {
    $server6 = "Server:  UnKnown`r`nAddress:  fe80::1`r`n`r`nNon-authoritative answer:`r`nName:    nexus.corp.example`r`nAddresses:  2001:db8::10`r`n          10.0.0.9`r`n"
    $aliases = "Server:  dns.corp`nAddress:  10.0.0.1`n`nName:    real.corp.example`nAddress:  10.0.0.8`nAliases:  alias.corp.example`n"
    $empty = "Server:  dns.corp`nAddress:  10.0.0.1`n`n"
    $runs = @{
        ok = @{ stdout = $server6; stderr = ''; exit_code = 0; timed_out = $false; error = $null }
        nxdomain = @{ stdout = $empty; stderr = "*** dns.corp can't find nosuch.corp.example: Non-existent domain"; exit_code = 1; timed_out = $false; error = $null }
        nodata = @{ stdout = $empty; stderr = '*** No internal type for both IPv4 and IPv6 Addresses (A+AAAA) records available for x.corp.example'; exit_code = 0; timed_out = $false; error = $null }
        request_timeout = @{ stdout = $empty; stderr = '*** Request to dns.corp timed-out'; exit_code = 1; timed_out = $false; error = $null }
        killed = @{ stdout = ''; stderr = ''; exit_code = $null; timed_out = $true; error = $null }
        no_server = @{ stdout = ''; stderr = '*** Default servers are not available'; exit_code = 1; timed_out = $false; error = $null }
        launch_failed = @{ stdout = ''; stderr = ''; exit_code = $null; timed_out = $false; error = 'The system cannot find the file specified' }
    }
    $out = @{ server6 = @(Get-EsNslookupAddresses $server6); aliases = @(Get-EsNslookupAddresses $aliases); empty = @(Get-EsNslookupAddresses $empty) }
    foreach ($name in @($runs.Keys)) {
        $script:FakeRun = $runs[$name]
        $answer = & {
            function Invoke-EsCommand { param([string]$FilePath, [string[]]$Arguments, [int]$TimeoutSec) return $script:FakeRun }
            Resolve-EsHostNameNslookup 'nexus.corp.example'
        }
        $out[$name] = @{ status = $answer.status; addresses = @($answer.addresses); error = $answer.error }
    }
    $missing = & {
        function Get-EsSystemTool([string]$Name) { return 'C:\envscan-none\nslookup.exe' }
        Resolve-EsHostNameNslookup 'nexus.corp.example'
    }
    $out.missing = @{ status = $missing.status; addresses = @($missing.addresses); error = $missing.error }
    return $out
}
$cases.net_never = Get-Case {
    $out = @{}
    foreach ($value in @('169.254.169.254', '::ffff:169.254.1.1', 'FE80::1%12', '[fe80::1]', 'fd00:ec2::254', '100.100.100.200',
            '168.63.129.16', 'Metadata', 'metadata.google.internal', 'instance-data', '10.0.0.1', 'metadata.corp.example',
            '169.25.1.1', 'fd00:ec2::2540', 'fd20:ce::254', '192.0.0.192', '2002:c000:204::1', '2002::', '2003::1')) {
        $out[$value] = [bool](Test-EsNetNever $value)
    }
    return $out
}

# ---- 18: PowerShell 2.0 has no Get-Acl -LiteralPath (and its -Path fails on escaped brackets)
$cases.acl_ps2 = Get-Case {
    if (-not $script:ES_FULL_LANGUAGE) { return @{ skipped = $true } }
    $dir = Join-Path $Scratch 'acl[1]'
    $null = New-Item -ItemType Directory -Path (Join-Path $Scratch 'acl1')
    Rename-Item -LiteralPath (Join-Path $Scratch 'acl1') -NewName 'acl[1]'
    $major = $script:ES_PS_MAJOR
    $script:ES_PS_MAJOR = 2
    $script:SpyAcl = @()
    try {
        $access = & {
            function Get-Acl { param([string]$Path, [string]$LiteralPath, $ErrorAction)
                if ($LiteralPath) { $script:SpyAcl += ('literal:' + $LiteralPath); throw 'Get-Acl has no -LiteralPath in PowerShell 2.0' }
                $script:SpyAcl += ('path:' + $Path)
                Microsoft.PowerShell.Security\Get-Acl -Path $Path -ErrorAction Stop }
            Get-EsSddlAccess $dir
        }
    } finally { $script:ES_PS_MAJOR = $major }
    return @{ create_files = $access.create_files; error = $access.error; calls = @($script:SpyAcl); exists = (Test-Path -LiteralPath $dir) }
}

# ---- 19: probes share one CIM query per class, namespace and filter
$cases.cim_cache = Get-Case {
    $script:ES_CIM_CACHE = @{}
    $script:CimCalls = @()
    & {
        function Get-EsCim { param([string]$Class, [string]$Namespace, [string]$Filter, [int]$TimeoutSec)
            $script:CimCalls += ($Class + '|' + $Filter); return @(@{ Name = 'cpu' }) }
        $null = Add-EsCimItems (New-EsResult) 'Win32_Processor'
        $null = Add-EsCimItems (New-EsResult) 'Win32_Processor'
        $null = Get-EsCimSafe -Class 'Win32_Processor' -Filter 'DeviceID=''CPU0'''
    }
    $script:ES_CIM_CACHE = @{}
    return , @($script:CimCalls)
}

# ---- found while testing: a table entry named "Keys" or "Count" hides the Hashtable property
$cases.json_shadow_keys = ConvertTo-EsJson @{ keys = 'k'; Count = 2; a = 1 }
$cases.data_shadow_keys = Protect-EsData @{ keys = 'password=abc123'; values = 'x'; b = 'plain' }

$cases.language_mode = $script:ES_LANGUAGE_MODE
Write-Output (ConvertTo-EsJson $cases)
