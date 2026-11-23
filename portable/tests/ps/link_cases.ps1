# Cases for tests/test_ps_links.py: a file the scanner reads (a configuration file, the hosts
# file, a Java release file, a package manifest, a git include, the cacerts keytool would open)
# or a folder it lists (a configs entry in list mode, a dependency cache) that is a link is read
# only when the link ends on a local path that is no credential store. Prints one JSON object
# (case name -> result). Runs in FullLanguage and in ConstrainedLanguage, so it may only use what
# the scanner itself may use.
# Creating a symbolic link needs a privilege a standard user lacks: Get-Item is replaced, in a
# child scope (the library resolves commands through its callers' scopes), by one that returns
# a fake link item for the paths in $script:FakeItems. A real junction (no privilege needed)
# covers a real reparse point.
param([string]$Lib, [string]$Scratch)

. $Lib
Initialize-EsRedaction
$script:ES_NETWORK_DRIVES = @('Z:')
$script:ES_TMP = Join-Path $Scratch 'tmp'
$null = New-Item -ItemType Directory -Path $script:ES_TMP
$cases = @{}

function Get-Case([scriptblock]$Block) {
    # One case: its result, or the error that stopped it (the other cases still run).
    try { return , (& $Block) } catch { return @{ case_error = ([string]$_.Exception.Message + ' at ' + [string]$_.InvocationInfo.PositionMessage) } }
}

function New-TestFile([string]$Path, [string]$Text) {
    $null = New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force
    Set-Content -LiteralPath $Path -Encoding Ascii -Value $Text
    return $Path
}

function New-FakeLink([string]$Path, [string]$LinkType, [object[]]$Target, [int]$Kind = 0x20) {
    # What Get-Item returns for a reparse point (0x400) that is a file (0x20, Archive) or a
    # folder (0x10, Directory), with LinkType and Target as PowerShell 5+ reports them.
    return @{ FullName = $Path; Name = (Split-Path -Leaf $Path); Attributes = (0x400 -bor $Kind); LinkType = $LinkType
        Target = $Target; PSIsContainer = (($Kind -band 0x10) -ne 0); Length = 0; LastWriteTimeUtc = [datetime]'2026-11-11T00:00:00'
    }
}

function Test-NeverReal([string]$Path) {
    # A path the fakes never pass to the real cmdlet (it could reach the network): a UNC or
    # device path, or the fake network drive Z:.
    return ($Path.StartsWith('\\') -or $Path -like 'Z:*')
}

function Invoke-WithFakeLinks([hashtable]$Items, [scriptblock]$Block) {
    # Get-Item returns the fake item of a path in $Items. Get-Item, Get-Content, Get-ChildItem
    # and Test-Path record each path in $script:Touched ("item|", "read|", "list|", "test|").
    # The link reasons a scan keeps (ES_LINK_CACHE) start empty: the fakes change them.
    $script:FakeItems = $Items
    $script:Touched = @()
    $script:ES_LINK_CACHE = @{}
    return (& {
            function Get-Item { param([string]$Path, [string]$LiteralPath, [switch]$Force, $ErrorAction = 'Continue')
                $script:Touched += ('item|' + $LiteralPath + $Path)
                if ($LiteralPath -and $script:FakeItems.ContainsKey($LiteralPath)) { return $script:FakeItems[$LiteralPath] }
                if (Test-NeverReal ($LiteralPath + $Path)) { return $null }
                if ($LiteralPath) { return (Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force:$Force -ErrorAction $ErrorAction) }
                Microsoft.PowerShell.Management\Get-Item -Path $Path -Force:$Force -ErrorAction $ErrorAction }
            function Get-Content { param([string]$LiteralPath, [int]$TotalCount = -1, $Encoding = $null, [switch]$AsByteStream, $ErrorAction = 'Continue')
                $script:Touched += ('read|' + $LiteralPath)
                $more = @{}
                if ($Encoding) { $more['Encoding'] = $Encoding }
                if ($AsByteStream) { $more['AsByteStream'] = $true }
                if (Test-NeverReal $LiteralPath) { return }
                Microsoft.PowerShell.Management\Get-Content -LiteralPath $LiteralPath -TotalCount $TotalCount -ErrorAction $ErrorAction @more }
            function Get-ChildItem { param([string]$LiteralPath, [switch]$Force, [switch]$Name, $ErrorAction = 'Continue')
                $script:Touched += ('list|' + $LiteralPath.TrimEnd('\'))
                if (Test-NeverReal $LiteralPath) { return }
                Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $LiteralPath -Force:$Force -Name:$Name -ErrorAction $ErrorAction }
            function Test-Path { param([string]$LiteralPath, $PathType = 'Any')
                $script:Touched += ('test|' + $LiteralPath)
                if (Test-NeverReal $LiteralPath) { return $false }
                Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath -PathType $PathType }
            & $Block
        })
}

function Invoke-AsPowerShell4([scriptblock]$Block) {
    # PowerShell before 5 has no LinkType and no Target: the library must not ask for them.
    $major = $script:ES_PS_MAJOR
    $script:ES_PS_MAJOR = 4
    $script:ES_LINK_CACHE = @{}
    try { return (& $Block) } finally { $script:ES_PS_MAJOR = $major; $script:ES_LINK_CACHE = @{} }
}

# ---- Read-EsTextFile on links (each file exists; Get-Item says what kind of link it is)
$dir = Join-Path $Scratch 'links'
$plain = New-TestFile (Join-Path $dir 'plain.ini') 'proxy=http://plain.corp:8080'
$target = New-TestFile (Join-Path $dir 'target.ini') 'proxy=http://target.corp:8080'
$names = @('unc', 'unc_device', 'unc_long', 'mapped', 'cred', 'relative_cred', 'volume', 'root_relative', 'no_target',
    'local', 'relative', 'chain', 'hop', 'loop', 'other_reparse', 'placeholder')
$paths = @{}
foreach ($name in $names) { $paths[$name] = New-TestFile (Join-Path $dir ($name + '.ini')) ('proxy=http://' + $name + '.corp:8080') }
$fake = @{}
$fake[$paths['unc']] = New-FakeLink $paths['unc'] 'SymbolicLink' @('\\srv\share\pip.ini')
$fake[$paths['unc_device']] = New-FakeLink $paths['unc_device'] 'SymbolicLink' @('\??\UNC\srv\share\pip.ini')
$fake[$paths['unc_long']] = New-FakeLink $paths['unc_long'] 'SymbolicLink' @('\\?\UNC\srv\share\pip.ini')
$fake[$paths['mapped']] = New-FakeLink $paths['mapped'] 'SymbolicLink' @('Z:\pip.ini')
$fake[$paths['cred']] = New-FakeLink $paths['cred'] 'SymbolicLink' @('C:\Users\u\.ssh\config')
$fake[$paths['relative_cred']] = New-FakeLink $paths['relative_cred'] 'SymbolicLink' @('..\.aws\credentials')
$fake[$paths['volume']] = New-FakeLink $paths['volume'] 'SymbolicLink' @('\??\Volume{01234567-89ab-cdef-0123-456789abcdef}\pip.ini')
$fake[$paths['root_relative']] = New-FakeLink $paths['root_relative'] 'SymbolicLink' @('\share\pip.ini')
$fake[$paths['no_target']] = New-FakeLink $paths['no_target'] 'SymbolicLink' @()
$fake[$paths['local']] = New-FakeLink $paths['local'] 'SymbolicLink' @('\??\' + $target)
$fake[$paths['relative']] = New-FakeLink $paths['relative'] 'SymbolicLink' @('target.ini')
$fake[$paths['chain']] = New-FakeLink $paths['chain'] 'SymbolicLink' @($paths['hop'])
$fake[$paths['hop']] = New-FakeLink $paths['hop'] 'SymbolicLink' @('\\srv\share\hop.ini')
$fake[$paths['loop']] = New-FakeLink $paths['loop'] 'SymbolicLink' @($paths['loop'])
$fake[$paths['other_reparse']] = New-FakeLink $paths['other_reparse'] $null $null
$fake[$paths['placeholder']] = New-FakeLink $paths['placeholder'] $null $null (0x20 -bor 0x400000)

$cases.reads = Get-Case {
    $out = @{ plain_path = $plain; target_path = $target }
    foreach ($name in @(@('plain') + $names)) {
        $path = $(if ($name -eq 'plain') { $plain } else { $paths[$name] })
        $file = Invoke-WithFakeLinks $fake { Read-EsTextFile $path }
        $out[$name] = @{ path = $path; error = $file.error; text = $file.text; touched = @($script:Touched) }
    }
    return $out
}
$cases.reads_ps4 = Get-Case {
    $out = @{}
    foreach ($name in @('local', 'other_reparse')) {
        $path = $paths[$name]
        $file = Invoke-AsPowerShell4 { Invoke-WithFakeLinks $fake { Read-EsTextFile $path } }
        $out[$name] = @{ path = $path; error = $file.error; touched = @($script:Touched) }
    }
    $file = Invoke-AsPowerShell4 { Invoke-WithFakeLinks $fake { Read-EsTextFile $plain } }
    $out.plain = @{ error = $file.error; text = $file.text }
    return $out
}

# ---- git include files: the same link rule, in the reasons of the include notes
$cases.git_includes = Get-Case {
    $out = @{}
    foreach ($name in @('plain', 'unc', 'chain', 'cred', 'volume', 'local')) {
        $path = $(if ($name -eq 'plain') { $plain } else { $paths[$name] })
        $out[$name] = Invoke-WithFakeLinks $fake { Get-EsGitIncludeFileReason $path }
    }
    # A real file below a folder that is a link (a junction to .ssh or to a share).
    $items = @{}
    foreach ($key in @($fake.Keys)) { $items[$key] = $fake[$key] }
    foreach ($pair in @(@('below_cred', 'C:\Users\u\.ssh'), @('below_unc', '\\srv\share\git'))) {
        $folder = Join-Path $dir ('j_' + $pair[0])
        $file = New-TestFile (Join-Path $folder 'inc.cfg') '[user]'
        $items[$folder] = New-FakeLink $folder 'Junction' @($pair[1]) 0x10
        $out[$pair[0]] = Invoke-WithFakeLinks $items { Get-EsGitIncludeFileReason $file }
        $out[$pair[0] + '_touched'] = @($script:Touched | Where-Object { $_ -like ('*' + $file) })
    }
    return $out
}

# ---- configs entries (a file and a folder in list mode)
$cases.configs = Get-Case {
    $listDir = Join-Path $dir 'confdir'
    $null = New-TestFile (Join-Path $listDir 'a.conf') 'x'
    $items = @{}
    foreach ($key in @($fake.Keys)) { $items[$key] = $fake[$key] }
    $items[$listDir] = New-FakeLink $listDir 'SymbolicLink' @('\\srv\share\conf') 0x10
    $configs = @(
        @{ id = 'pip.user'; tool = 'pip'; scope = 'user'; mode = 'content'; match = @(); max_bytes = 16384; paths = @($paths['unc'], $plain) },
        @{ id = 'conf.list'; tool = 'x'; scope = 'user'; mode = 'list'; match = @(); max_bytes = 16384; paths = @($listDir) }
    )
    $r = New-EsResult
    $entries = @(Invoke-WithFakeLinks $items { Get-EsConfigEntries $r $configs })
    return @{ status = $r.status; notes = @($r.notes); touched = @($script:Touched); unc = $paths['unc']; plain = $plain
        list_dir = $listDir; entries = @($entries | ForEach-Object { @{ path = $_.path; error = $_.error; lines = @($_.lines) } })
    }
}

# ---- dependency caches: a folder link to the network, and a real junction to a local folder
$cases.caches = Get-Case {
    $netCache = Join-Path $dir 'netcache'
    $realCache = Join-Path $dir 'realcache'
    $junction = Join-Path $dir 'junction'
    $null = New-Item -ItemType Directory -Path $netCache
    $null = New-TestFile (Join-Path $realCache 'a\x.txt') 'x'
    $null = New-TestFile (Join-Path $realCache 'b\y.txt') 'y'
    $null = New-Item -ItemType Junction -Path $junction -Target $realCache
    $items = @{}
    $items[$netCache] = New-FakeLink $netCache 'SymbolicLink' @('\\srv\share\cache') 0x10
    $saved = $script:ES_CACHES
    $script:ES_CACHES = @(@{ id = 'net'; tool = 'x'; paths = @($netCache) }, @{ id = 'junction'; tool = 'y'; paths = @($junction) })
    try {
        $now = Invoke-WithFakeLinks $items { probe_pkg_caches }
        $touched = @($script:Touched)
        $old = Invoke-AsPowerShell4 { Invoke-WithFakeLinks $items { probe_pkg_caches } }
    } finally { $script:ES_CACHES = $saved }
    return @{ status = $now.status; notes = @($now.notes); touched = $touched; net = $netCache; junction = $junction
        caches = @($now.data.caches | ForEach-Object { @{ id = $_.id; path = $_.path; entries = $_.entries } })
        old_status = $old.status; old_notes = @($old.notes); old_caches = @($old.data.caches)
    }
}

# ---- Java release file, package manifests and the hosts file
$cases.java = Get-Case {
    $jdkNet = Join-Path $dir 'jdk-net'
    $jdkOk = Join-Path $dir 'jdk-ok'
    $release = New-TestFile (Join-Path $jdkNet 'release') 'JAVA_VERSION="21.0.1"'
    $null = New-TestFile (Join-Path $jdkOk 'release') 'JAVA_VERSION="17.0.9"'
    $items = @{}
    $items[$release] = New-FakeLink $release 'SymbolicLink' @('\\srv\share\release')
    $r = New-EsResult
    $net = Invoke-WithFakeLinks $items { Read-EsJavaRelease $r $jdkNet }
    $touched = @($script:Touched)
    $ok = Invoke-WithFakeLinks $items { Read-EsJavaRelease $r $jdkOk }
    return @{ status = $r.status; notes = @($r.notes); net_version = $net.version; ok_version = $ok.version
        release = $release; touched = $touched
    }
}
$cases.manifests = Get-Case {
    $root = Join-Path $dir 'scoop\apps'
    $manifest = New-TestFile (Join-Path $root 'netapp\current\manifest.json') '{ "version": "9.9.9" }'
    $null = New-TestFile (Join-Path $root 'okapp\current\manifest.json') '{ "version": "1.2.3" }'
    $items = @{}
    $items[$manifest] = New-FakeLink $manifest 'SymbolicLink' @('\\srv\share\manifest.json')
    $r = New-EsResult
    $packages = @(Invoke-WithFakeLinks $items { Get-EsFolderPackages $r @($root) 'scoop' 'current\manifest.json' })
    return @{ status = $r.status; notes = @($r.notes); manifest = $manifest; touched = @($script:Touched)
        packages = @($packages | ForEach-Object { @{ name = $_.name; version = $_.version } })
    }
}
$cases.cacerts = Get-Case {
    # keytool would open the keystore through the link: it is not run.
    $jdk = Join-Path $dir 'jdk-cacerts'
    $null = New-TestFile (Join-Path $jdk 'bin\keytool.exe') ''
    $cacerts = New-TestFile (Join-Path $jdk 'lib\security\cacerts') 'x'
    $items = @{}
    $items[$cacerts] = New-FakeLink $cacerts 'SymbolicLink' @('\\srv\share\cacerts')
    $script:ES_RESULTS = @{ 'runtime.java' = @{ status = 'ok'; data = @{ jdks = @(@{ path = $jdk; source = 'JAVA_HOME' }) }; notes = @() } }
    $r = Invoke-WithFakeLinks $items { probe_tls_java_cacerts }
    $script:ES_RESULTS = @{}
    return @{ status = $r.status; notes = @($r.notes); sources = @($r.sources); cacerts = $cacerts; touched = @($script:Touched) }
}
$cases.hosts = Get-Case {
    $hostsPath = Join-Path ([string]$env:SystemRoot) 'System32\drivers\etc\hosts'
    $items = @{}
    $items[$hostsPath] = New-FakeLink $hostsPath 'SymbolicLink' @('\\srv\share\hosts')
    $r = New-EsResult
    $entries = @(Invoke-WithFakeLinks $items { Get-EsHostsEntries $r })
    return @{ status = $r.status; notes = @($r.notes); entries = $entries; path = $hostsPath; touched = @($script:Touched) }
}

# ---- folders above a path: nothing below a folder link that is not followed is tested, listed,
# read or run (Windows would follow the link); a folder link to a local folder is followed.
$netDir = Join-Path $dir 'netdir'
$okDir = Join-Path $dir 'okdir'
$okTarget = Join-Path $dir 'oktarget'
$inNet = New-TestFile (Join-Path $netDir 'sub\pip.ini') 'proxy=http://innet.corp:8080'
$inOk = New-TestFile (Join-Path $okDir 'pip.ini') 'proxy=http://inok.corp:8080'
$null = New-TestFile (Join-Path $okTarget 'pip.ini') 'x'
$netTool = New-TestFile (Join-Path $okDir 'nettool.exe') 'MZ'
$okTool = New-TestFile (Join-Path $okDir 'oktool.exe') 'MZ'
$hopLink = New-TestFile (Join-Path $dir 'hop2.ini') 'x'
$folders = @{}
$folders[$netDir] = New-FakeLink $netDir 'SymbolicLink' @('\\srv\share\dir') 0x10
$folders[$okDir] = New-FakeLink $okDir 'Junction' @($okTarget) 0x10
$folders[$netTool] = New-FakeLink $netTool 'SymbolicLink' @('\\srv\share\tool.exe')
$folders[$hopLink] = New-FakeLink $hopLink 'SymbolicLink' @($inNet)

$cases.folder_reads = Get-Case {
    $out = @{ net_dir = $netDir }
    $file = Invoke-WithFakeLinks $folders { Read-EsTextFile $inNet }
    $out.in_net = @{ error = $file.error; text = $file.text; touched = @($script:Touched) }
    $file = Invoke-WithFakeLinks $folders { Read-EsTextFile $inOk }
    $out.in_ok = @{ error = $file.error; text = $file.text }
    $file = Invoke-WithFakeLinks $folders { Read-EsTextFile $hopLink }
    $out.hop = @{ error = $file.error; touched = @($script:Touched) }
    return $out
}
$cases.folder_patterns = Get-Case {
    $r = New-EsResult
    $out = Invoke-WithFakeLinks $folders {
        @{
            literal = @(Expand-EsPathPattern ($netDir + '\sub\pip.ini') $r)
            glob = @(Expand-EsPathPattern ($netDir + '\*.ini') $r)
            star_folder = @(Expand-EsPathPattern ($dir + '\netd*\sub\pip.ini') $r)
            ok = @(Expand-EsPathPattern ($okDir + '\*.ini') $r)
        }
    }
    $out.touched = @($script:Touched)
    $out.notes = @($r.notes)
    $out.status = $r.status
    $out.net_dir = $netDir
    $out.ok_file = $inOk
    return $out
}
$cases.folder_tools = Get-Case {
    $saved = $script:ES_ENV_SNAPSHOT
    $script:ES_ENV_SNAPSHOT = @{ Path = (($netDir + '\sub') + ';' + $okDir); PATHEXT = '.EXE' }
    $script:ES_PATH_DIRS = $null; $script:ES_PATH_INDEX = $null; $script:ES_PATHEXT = $null
    try {
        $out = Invoke-WithFakeLinks $folders {
            @{
                dirs = @(Get-EsPathDirs)
                found = @(Find-EsExecutable @('nettool') @() | ForEach-Object { $_.path })
                reason = Get-EsNoRunReason @{ id = 'nettool'; mode = 'version' } $netTool
                arch = Get-EsBinaryArch $netTool
                ok_arch = Get-EsBinaryArch $okTool
                run = (Invoke-EsCommand -FilePath $netTool -Arguments @('--version')).error
            }
        }
        $out.touched = @($script:Touched)
    } finally {
        $script:ES_ENV_SNAPSHOT = $saved
        $script:ES_PATH_DIRS = $null; $script:ES_PATH_INDEX = $null; $script:ES_PATHEXT = $null
    }
    $out.ok_dir = $okDir; $out.net_dir = $netDir; $out.tool = $netTool; $out.ok_tool = $okTool
    return $out
}
$cases.folder_packages = Get-Case {
    $scoopRoot = Join-Path $dir 'scoop2\apps'
    $netApp = Join-Path $scoopRoot 'netapp'
    $null = New-TestFile (Join-Path $netApp 'current\manifest.json') '{ "version": "9.9.9" }'
    $null = New-TestFile (Join-Path $scoopRoot 'okapp\current\manifest.json') '{ "version": "1.2.3" }'
    $items = @{}
    foreach ($key in @($folders.Keys)) { $items[$key] = $folders[$key] }
    $items[$netApp] = New-FakeLink $netApp 'SymbolicLink' @('\\srv\share\netapp') 0x10
    $saved = $script:ES_ENV_SNAPSHOT
    $script:ES_ENV_SNAPSHOT = @{ PSModulePath = ($netDir + ';' + $okDir) }
    $r = New-EsResult
    try {
        $packages = @(Invoke-WithFakeLinks $items {
                Get-EsFolderPackages $r @($netDir, $scoopRoot) 'scoop' 'current\manifest.json'
                Get-EsModulePackages $r
            })
        $touched = @($script:Touched)
    } finally { $script:ES_ENV_SNAPSHOT = $saved }
    return @{ status = $r.status; notes = @($r.notes); touched = $touched; net_dir = $netDir; net_app = $netApp
        packages = @($packages | ForEach-Object { @{ name = $_.name; version = $_.version; source = $_.source } })
    }
}

# ---- a path that is not local is refused by the link guards before any Get-Item
$cases.nonlocal_guards = Get-Case {
    $out = @{}
    $pairs = @(@('unc', '\\srv\share\tools\x.exe'), @('mapped', 'Z:\tools\x.exe'), @('device', '\\?\C:\tools\x.exe'),
        @('relative', 'tools\x.exe'), @('rooted', '\tools\x.exe'), @('drive_relative', 'C:tools\x.exe'))
    foreach ($pair in $pairs) {
        $path = $pair[1]
        $r = New-EsResult
        $out[$pair[0]] = Invoke-WithFakeLinks @{} {
            @{
                link = Get-EsPathLinkReason $path
                cached = Get-EsCachedLinkReason $path
                safe = Test-EsSafePath $path 'Leaf'
                listable = Test-EsListableFolder $r $path
                read = (Read-EsTextFile $path).error
                run = (Get-EsLaunch $path '').error
            }
        }
        $out[$pair[0]].touched = @($script:Touched)
        $out[$pair[0]].notes = @($r.notes)
    }
    # A bare drive (the first component of a glob) is local: C:\Windo* still expands.
    $r = New-EsResult
    $out.drive = Get-EsPathLinkReason $env:SystemDrive
    $out.drive_glob = @(Invoke-WithFakeLinks @{} { Expand-EsPathPattern ($env:SystemDrive + '\Windo*') $r })
    $out.drive_notes = @($r.notes)
    return $out
}

$cases.language_mode = $script:ES_LANGUAGE_MODE
Write-Output (ConvertTo-EsJson $cases)
