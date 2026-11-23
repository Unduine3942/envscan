# ---------------------------------------------------------------------------
# 24-probes-tools: tool inventory, version managers, Java, .NET, Python,
# Visual Studio / Windows SDK, native runtime libraries.
# ---------------------------------------------------------------------------

$script:ES_JAVA_VENDOR_DIRS = @('Java', 'Eclipse Adoptium', 'Eclipse Foundation', 'Microsoft', 'Zulu', 'Amazon Corretto', 'BellSoft', 'Semeru', 'RedHat', 'OpenJDK')
$script:ES_FRAMEWORK_RELEASES = @(
    @(533320, '4.8.1'), @(528040, '4.8'), @(461808, '4.7.2'), @(461308, '4.7.1'), @(460798, '4.7'),
    @(394802, '4.6.2'), @(394254, '4.6.1'), @(393295, '4.6'), @(379893, '4.5.2'), @(378675, '4.5.1'), @(378389, '4.5')
)

function Get-EsFirstLines([string]$Text, [int]$Count) {
    $lines = @(([string]$Text) -split "`n" | ForEach-Object { $_.TrimEnd("`r") } | Where-Object { $_.Trim() })
    return (@($lines | Select-Object -First $Count) -join "`n")
}

function Get-EsVersionToken([string]$Text) {
    # The first version-like token, skipping the JVM's "Picked up JAVA_TOOL_OPTIONS: ..." banners
    # (printed before the version; their options often hold numbers such as TLSv1.2).
    foreach ($line in @(([string]$Text) -split "`n")) {
        if ($line -match '\A\s*Picked up (JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS):') { continue }
        if ($line -match '(\d+(\.\d+)+[-+._A-Za-z0-9]*)') {
            $token = $matches[1]
            if ($token.Length -gt 40) { $token = $token.Substring(0, 40) }
            $clean = $line.Trim()
            if ($clean.Length -gt 160) { $clean = $clean.Substring(0, 160) }
            return @{ version = $token; line = $clean }
        }
    }
    return @{ version = $null; line = $null }
}

function Get-EsBinaryArch([string]$Path) {
    # The PE machine of a program; not read through a link that is not followed.
    if ((Test-EsAppAlias $Path) -or @('.exe', '.com') -notcontains (Get-EsExtension $Path)) { return $null }
    if (Get-EsPathLinkReason $Path) { return $null }
    return (Get-EsPeMachine $Path)
}

function Get-EsToolRecord([hashtable]$Result, [hashtable]$Tool) {
    $matchList = @(Find-EsExecutable $Tool.exe $Tool.dirs)
    if ($matchList.Count -eq 0) { return @{ name = $Tool.name; cat = $Tool.cat; found = $false } }
    # Primary = first match that may be run (a real binary beats a Store alias or shim), else the first match.
    $primary = $matchList[0]
    foreach ($candidate in $matchList) { if (-not (Get-EsNoRunReason $Tool $candidate.path)) { $primary = $candidate; break } }
    $record = @{
        name = $Tool.name; cat = $Tool.cat; found = $true; path = $primary.path; on_path = $primary.on_path
        paths = @($matchList | ForEach-Object { $_.path }); version = $null; version_line = $null
        executed = $false; reason = (Get-EsNoRunReason $Tool $primary.path); exit_code = $null
        binary_arch = (Get-EsBinaryArch $primary.path)
    }
    if ($record.reason) { return $record }
    if (((Get-EsUtc) - $script:ES_STARTED).TotalSeconds -gt $script:ES_OPT.budget) {
        $record.reason = 'scan budget exhausted'
        Add-EsNote $Result 'scan budget exhausted before every tool version was read' 'partial'
        return $record
    }
    $run = Invoke-EsCommand -FilePath $primary.path -Arguments @($Tool.args) -MaxLines 80
    $Result.sources += ('run ' + $run.command)
    $record.executed = $true
    $record.exit_code = $run.exit_code
    $text = Get-EsCommandText $run
    if ($run.timed_out) { $record.reason = 'timed out'; Add-EsNote $Result ($Tool.id + ': timed out') 'partial' }
    elseif ($run.error) { $record.reason = $run.error }
    $token = Get-EsVersionToken $text
    $record.version = $token.version
    $record.version_line = $token.line
    if ($text) { $Result.raw[$Tool.id] = Get-EsFirstLines $text 6 }
    return $record
}

function probe_tools_inventory {
    $r = New-EsResult
    $r.sources += @('list PATH directories (' + @(Get-EsPathDirs).Count + ' local)', 'known install directories from spec/tools.toml')
    $tools = @{}
    $found = 0
    $executed = 0
    foreach ($tool in @($script:ES_TOOLS)) {
        $record = Get-EsToolRecord $r $tool
        $tools[$tool.id] = $record
        if ($record.found) { $found++ }
        if ($record.executed) { $executed++ }
    }
    $r.data.tools = $tools
    $r.data.found_count = $found
    $r.data.executed_count = $executed
    $r.data.searched_count = @($script:ES_TOOLS).Count
    return $r
}

function Get-EsTool([string]$Id) {
    $tools = (Get-EsData 'tools.inventory')['tools']
    if ($tools -and $tools.ContainsKey($Id)) { return $tools[$Id] }
    return $null
}

function probe_runtime_version_managers {
    $r = New-EsResult
    $managers = @()
    $dirs = @(Get-EsPathDirs)
    foreach ($manager in @($script:ES_VMANAGERS)) {
        $shims = @($dirs | Where-Object {
                $lower = $_.ToLowerInvariant().Replace('\', '/')
                @($manager.markers | Where-Object { $_ -and $lower.Contains([string]$_) }).Count -gt 0
            })
        $versions = @()
        foreach ($pattern in @($manager.versions)) {
            $r.sources += ('list ' + $pattern)
            $nested = ([string]$pattern).EndsWith('*/*')
            foreach ($path in @(Expand-EsPathPattern ([string]$pattern) $r)) {
                if (-not (Test-Path -LiteralPath $path -PathType Container)) { continue }
                $label = Split-Path -Leaf $path
                if ($nested) { $label = (Split-Path -Leaf (Split-Path -Parent $path)) + '/' + $label }
                if ($versions -notcontains $label) { $versions += $label }
            }
        }
        if ($shims.Count -gt 0 -or $versions.Count -gt 0) {
            $managers += @{ id = $manager.id; name = $manager.name; shim_dirs = $shims; versions = $versions }
        }
    }
    $active = Get-EsOrigEnv 'NVM_SYMLINK'
    $r.data.managers = $managers
    $r.data.nvm_symlink = $active
    if ($managers.Count -eq 0) { $r.status = 'not_found' }
    return $r
}

# ------------------------------------------------------------------ Java

function Read-EsJavaRelease([hashtable]$Result, [string]$JavaHome) {
    # The release file of a Java home (a missing one is common and not noted; one that is a
    # link off the local disk is noted and not read).
    $info = @{ version = $null; vendor = $null; arch = $null; image = $null }
    $path = Join-Path $JavaHome 'release'
    $release = Read-EsTextFile $path 8192
    Add-EsReadNote $Result $path $release.error
    if ($release.text) {
        foreach ($line in @($release.text -split "`n")) {
            if ($line -match '^\s*(JAVA_VERSION|IMPLEMENTOR|OS_ARCH|IMAGE_TYPE)\s*=\s*"?([^"]*)"?') {
                switch ($matches[1]) {
                    'JAVA_VERSION' { $info.version = $matches[2] }
                    'IMPLEMENTOR' { $info.vendor = $matches[2] }
                    'OS_ARCH' { $info.arch = $matches[2] }
                    'IMAGE_TYPE' { $info.image = $matches[2] }
                }
            }
        }
    }
    return $info
}

function Add-EsJavaHome([hashtable]$Homes, [string]$Path, [string]$Source) {
    if (-not $Path) { return }
    $clean = $Path.Trim().Trim('"').TrimEnd('\')
    if (-not (Test-EsLocalPath $clean)) { return }
    if (-not (Test-EsSafePath (Join-Path $clean 'bin\java.exe') 'Leaf')) { return }
    $key = $clean.ToLowerInvariant()
    if (-not $Homes.ContainsKey($key)) { $Homes[$key] = @{ path = $clean; source = $Source } }
}

function Add-EsJavaInstallDirs([hashtable]$Result, [hashtable]$Homes) {
    # Java homes in the vendor folders under Program Files and in ~\.jdks (IntelliJ downloads).
    $roots = @()
    foreach ($programs in @((Get-EsOrigEnv 'ProgramFiles'), (Get-EsOrigEnv 'ProgramFiles(x86)'))) {
        if (-not $programs) { continue }
        foreach ($vendor in $script:ES_JAVA_VENDOR_DIRS) { $roots += (Join-Path $programs $vendor) }
    }
    $profilePath = Get-EsOrigEnv 'USERPROFILE'
    if ($profilePath) { $roots += (Join-Path $profilePath '.jdks') }
    foreach ($root in $roots) {
        if (-not (Test-EsLocalPath $root) -or -not (Test-EsListableFolder $Result $root)) { continue }
        $Result.sources += ('list ' + $root)
        foreach ($dir in @(Get-EsDirEntries $root 200 | Where-Object { $_.PSIsContainer })) { Add-EsJavaHome $Homes $dir.FullName 'install directory' }
    }
}

function probe_runtime_java {
    $r = New-EsResult
    $homes = @{}
    $order = @()
    $javaHome = Get-EsOrigEnv 'JAVA_HOME'
    $r.sources += 'environment JAVA_HOME'
    Add-EsJavaHome $homes $javaHome 'JAVA_HOME'
    $pathJava = Get-EsTool 'java'
    if ($pathJava -and $pathJava['found'] -and ([string]$pathJava['path']) -match '\\bin\\java\.exe$') {
        Add-EsJavaHome $homes (Split-Path -Parent (Split-Path -Parent ([string]$pathJava['path']))) 'PATH'
    }
    foreach ($view in @('SOFTWARE', 'SOFTWARE\WOW6432Node')) {
        foreach ($kind in @('JDK', 'JRE', 'Java Development Kit', 'Java Runtime Environment')) {
            $base = 'HKLM:\' + $view + '\JavaSoft\' + $kind
            foreach ($version in @(Get-EsRegSubkeys $base)) {
                Add-EsJavaHome $homes (Get-EsRegValue ($base + '\' + $version) 'JavaHome') 'registry'
            }
        }
        $r.sources += ('registry HKLM\' + $view + '\JavaSoft')
    }
    Add-EsJavaInstallDirs $r $homes
    $jdks = @()
    foreach ($key in @($homes.PSBase.Keys | Sort-Object)) {
        $entry = $homes[$key]
        $release = Read-EsJavaRelease $r $entry.path
        $r.sources += ('read ' + (Join-Path $entry.path 'release'))
        $jdks += @{
            path = $entry.path; source = $entry.source; version = $release.version; vendor = $release.vendor
            arch = (Get-EsPeMachine (Join-Path $entry.path 'bin\java.exe')); release_arch = $release.arch
            is_jdk = (Test-Path -LiteralPath (Join-Path $entry.path 'bin\javac.exe') -PathType Leaf); image_type = $release.image
        }
    }
    $r.data.java_home = $javaHome
    $r.data.java_home_valid = $(if ($javaHome) { $homes.ContainsKey($javaHome.Trim().Trim('"').TrimEnd('\').ToLowerInvariant()) } else { $null })
    $r.data.path_java = $(if ($pathJava -and $pathJava['found']) { @{ path = $pathJava['path']; version = $pathJava['version'] } } else { $null })
    $r.data.jdks = $jdks
    if ($jdks.Count -eq 0) { $r.status = 'not_found' }
    if ($javaHome -and -not $r.data.java_home_valid) { Add-EsNote $r 'JAVA_HOME does not point to a Java installation' '' }
    return $r
}

# ------------------------------------------------------------------ .NET

function probe_runtime_dotnet {
    $r = New-EsResult
    $d = $r.data
    $ndp = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP'
    $r.sources += 'registry HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP'
    $release = Get-EsRegValue ($ndp + '\v4\Full') 'Release'
    $version = $null
    if ($null -ne $release) {
        foreach ($pair in $script:ES_FRAMEWORK_RELEASES) { if ([int]$release -ge $pair[0]) { $version = $pair[1]; break } }
    }
    $d.framework = @{ release = $release; version = $version }
    $legacy = @()
    foreach ($name in @('v2.0.50727', 'v3.0', 'v3.5')) {
        if ([string](Get-EsRegValue ($ndp + '\' + $name) 'Install') -eq '1') { $legacy += $name }
    }
    $d.framework_legacy = $legacy
    $d.sdks = @()
    $d.runtimes = @()
    $tool = Get-EsTool 'dotnet'
    $dotnet = $null
    if ($tool -and $tool['found'] -and -not $tool['reason']) { $dotnet = [string]$tool['path'] }
    if ($dotnet) {
        foreach ($pair in @(@('sdks', '--list-sdks'), @('runtimes', '--list-runtimes'))) {
            # An empty list is valid (runtime-only install); only a failed run is incomplete.
            $run = Invoke-EsTool $r ('dotnet ' + $pair[1]) $dotnet @($pair[1]) -AllowFailure
            if ($null -ne $run.exit_code -and $run.exit_code -ne 0) { Add-EsNote $r ('dotnet ' + $pair[1] + ': exit code ' + $run.exit_code) 'partial' }
            $d[$pair[0]] = @(([string]$run.stdout) -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\S+ (\d|\[)' })
        }
    } else {
        $programFiles = [string](Get-EsOrigEnv 'ProgramFiles')
        $pairs = $(if (Test-EsLocalPath $programFiles) { @(@('sdks', 'sdk'), @('runtimes', 'shared\Microsoft.NETCore.App')) } else { @() })
        foreach ($pair in $pairs) {
            $root = Join-Path $programFiles 'dotnet'
            $dir = Join-Path $root $pair[1]
            if (Test-EsSafePath $dir 'Container') {
                $r.sources += ('list ' + $dir)
                $d[$pair[0]] = @(Get-EsDirEntries $dir 200 | Where-Object { $_.PSIsContainer -and $_.Name -match '^\d' } | ForEach-Object { $_.Name })
            }
        }
    }
    if (-not $version -and $legacy.Count -eq 0 -and @($d.sdks).Count -eq 0 -and @($d.runtimes).Count -eq 0) { $r.status = 'not_found' }
    return $r
}

# ------------------------------------------------------------------ Python

function Get-EsStorePythons {
    $apps = Join-Path ([string](Get-EsOrigEnv 'LOCALAPPDATA')) 'Microsoft\WindowsApps'
    return @(Get-EsDirEntries $apps 500 | Where-Object { $_.PSIsContainer -and $_.Name -match '^PythonSoftwareFoundation\.Python\.(\d+\.\d+)_' } | ForEach-Object {
            $null = $_.Name -match '^PythonSoftwareFoundation\.Python\.(\d+\.\d+)_'
            $matches[1]
        })
}

function Add-EsPythonCandidate([hashtable]$Seen, [string]$Path, [string]$Source) {
    if (-not $Path) { return }
    $clean = $Path.Trim().Trim('"')
    if (-not (Test-EsLocalPath $clean) -or -not (Test-EsSafePath $clean 'Leaf')) { return }
    $key = $clean.ToLowerInvariant()
    if (-not $Seen.ContainsKey($key)) { $Seen[$key] = @{ path = $clean; source = $Source } }
}

function Find-EsPythonCandidates([hashtable]$Result) {
    # Interpreter candidates from PATH, known install folders and the PythonCore registry keys.
    $seen = @{}
    foreach ($match in @(Find-EsExecutable @('python', 'python3') @())) { Add-EsPythonCandidate $seen $match.path 'PATH' }
    foreach ($pattern in @('{env:LOCALAPPDATA}/Programs/Python/Python*/python.exe', '{env:ProgramFiles}/Python*/python.exe',
            '{env:ProgramFiles(x86)}/Python*/python.exe', '{env:SystemDrive}/Python*/python.exe', '~/miniconda3/python.exe',
            '~/anaconda3/python.exe', '{env:ProgramData}/miniconda3/python.exe', '{env:ProgramData}/anaconda3/python.exe',
            '~/.pyenv/pyenv-win/versions/*/python.exe')) {
        foreach ($path in @(Expand-EsPathPattern $pattern $Result)) { Add-EsPythonCandidate $seen $path 'install directory' }
    }
    $Result.sources += @('list PATH and known Python install directories', 'registry HKLM and HKCU \SOFTWARE\Python\PythonCore')
    foreach ($base in @('HKCU:\SOFTWARE\Python\PythonCore', 'HKLM:\SOFTWARE\Python\PythonCore', 'HKLM:\SOFTWARE\WOW6432Node\Python\PythonCore')) {
        foreach ($version in @(Get-EsRegSubkeys $base)) {
            $key = $base + '\' + $version + '\InstallPath'
            $exe = Get-EsRegValue $key 'ExecutablePath'
            if (-not $exe) {
                $dir = Get-EsRegValue $key '(default)'
                if ($dir) { $exe = Join-Path $dir 'python.exe' }
            }
            Add-EsPythonCandidate $seen $exe 'registry'
        }
    }
    return $seen
}

function Get-EsPyLauncherList([hashtable]$Result) {
    # Interpreters registered with the py launcher (py -0p), when a runnable launcher exists.
    $rule = @{ id = 'py'; mode = 'version' }
    $py = @(Find-EsExecutable @('py') @('{env:SystemRoot}', '{env:LOCALAPPDATA}/Programs/Python/Launcher')) | Where-Object { -not (Get-EsNoRunReason $rule $_.path) } | Select-Object -First 1
    if (-not $py) { return @() }
    $run = Invoke-EsTool $Result 'py -0p' $py.path @('-0p')
    return @(([string]$run.stdout) -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function probe_runtime_python {
    $r = New-EsResult
    $seen = Find-EsPythonCandidates $r
    $store = @(Get-EsStorePythons)
    $interpreters = @()
    $runs = 0
    $pythonTool = @{ id = 'python'; mode = 'version' }
    foreach ($key in @($seen.PSBase.Keys | Sort-Object)) {
        $candidate = $seen[$key]
        $alias = Test-EsAppAlias $candidate.path
        # Never run shims (pyenv-win .bat, .ps1), Store aliases or other non-executables.
        $noRun = Get-EsNoRunReason $pythonTool $candidate.path
        $entry = @{ path = $candidate.path; source = $candidate.source; store_alias = $alias; version = $null; arch = $null; not_run = $noRun }
        if (-not $noRun -and $runs -lt 10) {
            $runs++
            $run = Invoke-EsTool $r ('python ' + $runs) $candidate.path @('--version')
            $entry.version = (Get-EsVersionToken (Get-EsCommandText $run)).version
            $entry.arch = Get-EsPeMachine $candidate.path
        }
        $interpreters += $entry
    }
    $launcher = @(Get-EsPyLauncherList $r)
    $real = @($interpreters | Where-Object { -not $_.store_alias -and -not $_.not_run })
    $r.data.interpreters = $interpreters
    $r.data.launcher = $launcher
    $r.data.store_packages = $store
    $r.data.real_count = $real.Count + $store.Count
    if ($r.data.real_count -eq 0) {
        $r.status = 'not_found'
        if ($interpreters.Count -gt 0) { Add-EsNote $r 'only Microsoft Store aliases or shims that are never run were found; no runnable Python interpreter' '' }
    }
    return $r
}

# ------------------------------------------------------------------ Visual Studio and SDKs

function probe_toolchain_msvc {
    $r = New-EsResult
    $d = $r.data
    $d.instances = @()
    # ProgramFiles(x86) does not exist on 32-bit Windows.
    $programFiles = [string](Get-EsOrigEnv 'ProgramFiles(x86)')
    if (-not $programFiles) { $programFiles = [string](Get-EsOrigEnv 'ProgramFiles') }
    $vswhere = $null
    if (Test-EsLocalPath $programFiles) { $vswhere = Join-Path $programFiles 'Microsoft Visual Studio\Installer\vswhere.exe' }
    if ($vswhere -and (Test-EsSafePath $vswhere 'Leaf')) {
        $run = Invoke-EsTool $r 'vswhere' $vswhere @('-all', '-products', '*', '-format', 'text', '-nologo', '-utf8') -Encoding 'UTF8' -AllowFailure
        $current = $null
        $wanted = @('instanceId', 'installationName', 'installationPath', 'installationVersion', 'displayName', 'productId', 'isComplete', 'isPrerelease')
        foreach ($line in @(([string]$run.stdout) -split "`n")) {
            if ($line -notmatch '^([A-Za-z_]+):\s?(.*)$') { continue }
            if ($matches[1] -eq 'instanceId') { if ($current) { $d.instances += $current }; $current = @{} }
            if ($current -and $wanted -contains $matches[1]) { $current[$matches[1]] = $matches[2].TrimEnd("`r") }
        }
        if ($current) { $d.instances += $current }
    }
    $sdks = @()
    foreach ($view in @('SOFTWARE', 'SOFTWARE\WOW6432Node')) {
        $key = 'HKLM:\' + $view + '\Microsoft\Windows Kits\Installed Roots'
        $r.sources += ('registry HKLM\' + $view + '\Microsoft\Windows Kits\Installed Roots')
        $root = Get-EsRegValue $key 'KitsRoot10'
        if (-not $root) { continue }
        $include = Join-Path $root 'Include'
        if ((Test-EsLocalPath $include) -and (Test-EsSafePath $include 'Container')) {
            $r.sources += ('list ' + $include)
            foreach ($dir in @(Get-EsDirEntries $include 100 | Where-Object { $_.PSIsContainer -and $_.Name -match '^10\.' })) {
                if ($sdks -notcontains $dir.Name) { $sdks += $dir.Name }
            }
        }
    }
    $d.windows_sdks = @($sdks | Sort-Object)
    $msbuild = Get-EsTool 'msbuild'
    $d.msbuild = $(if ($msbuild -and $msbuild['found']) { @{ path = $msbuild['path']; version = $msbuild['version'] } } else { $null })
    $cl = Get-EsTool 'cl'
    $d.cl_on_path = [bool]($cl -and $cl['found'])
    if (@($d.instances).Count -eq 0 -and $sdks.Count -eq 0 -and -not $d.msbuild) { $r.status = 'not_found' }
    return $r
}

# ------------------------------------------------------------------ native libraries

function probe_native_deps {
    $r = New-EsResult
    $d = $r.data
    $vc = @()
    foreach ($view in @(@('SOFTWARE', ''), @('SOFTWARE\WOW6432Node', ' (32-bit view)'))) {
        $base = 'HKLM:\' + $view[0] + '\Microsoft\VisualStudio\14.0\VC\Runtimes'
        $r.sources += ('registry HKLM\' + $view[0] + '\Microsoft\VisualStudio\14.0\VC\Runtimes')
        foreach ($arch in @(Get-EsRegSubkeys $base)) {
            $values = Get-EsRegValues ($base + '\' + $arch)
            if ($values -and [string]$values['Installed'] -eq '1') { $vc += @{ arch = $arch.ToLowerInvariant(); version = [string]$values['Version']; view = $view[1].Trim() } }
        }
    }
    $d.vcredist = $vc
    $ucrt = $null
    $ucrtPath = Join-Path ([string]$env:SystemRoot) 'System32\ucrtbase.dll'
    $r.sources += ('read version of ' + $ucrtPath)
    try { $ucrt = [string](Get-Item -LiteralPath $ucrtPath -ErrorAction Stop).VersionInfo.FileVersion } catch { }
    $d.ucrt = $ucrt
    $d.libc = @{ kind = 'ucrt'; version = $ucrt }
    $d.webview2 = $null
    foreach ($key in @('HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
            'HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
            'HKCU:\Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}')) {
        $version = Get-EsRegValue $key 'pv'
        if ($version -and $version -ne '0.0.0.0') { $d.webview2 = [string]$version; break }
    }
    $r.sources += 'registry HKLM and HKCU EdgeUpdate\Clients (WebView2 runtime)'
    $odbc = @()
    foreach ($view in @(@('SOFTWARE', 64), @('SOFTWARE\WOW6432Node', 32))) {
        $r.sources += ('registry HKLM\' + $view[0] + '\ODBC\ODBCINST.INI\ODBC Drivers')
        $values = Get-EsRegValues ('HKLM:\' + $view[0] + '\ODBC\ODBCINST.INI\ODBC Drivers')
        if ($null -eq $values) { continue }
        foreach ($name in @($values.PSBase.Keys | Sort-Object)) { $odbc += @{ name = $name; bits = $view[1] } }
    }
    $d.odbc_drivers = $odbc
    $oracle = @()
    foreach ($view in @('SOFTWARE', 'SOFTWARE\WOW6432Node')) {
        $base = 'HKLM:\' + $view + '\ORACLE'
        $r.sources += ('registry HKLM\' + $view + '\ORACLE')
        foreach ($name in @(Get-EsRegSubkeys $base | Where-Object { $_ -like 'KEY_*' })) {
            $oracle += @{ name = $name; home = [string](Get-EsRegValue ($base + '\' + $name) 'ORACLE_HOME') }
        }
    }
    $d.oracle_homes = $oracle
    $d.glibcxx_max = $null
    $d.libssl = @()
    return $r
}
