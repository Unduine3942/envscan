# ---------------------------------------------------------------------------
# 23-probes-packages: package sources and mirrors, offline caches, installed
# software, optional Windows features.
# ---------------------------------------------------------------------------

$script:ES_MAX_CONFIG_FILES = 20
$script:ES_MAX_PACKAGES = 2000

function Test-EsLineMatch([string]$Line, [object[]]$Patterns) {
    $lower = $Line.ToLowerInvariant()
    foreach ($pattern in @($Patterns)) {
        if ($lower.Contains(([string]$pattern).ToLowerInvariant())) { return $true }
    }
    return $false
}

function Read-EsConfigFile([hashtable]$Config, [string]$Path) {
    $entry = @{ id = $Config.id; tool = $Config.tool; path = $Path; scope = $Config.scope; lines = @(); urls = @(); proxy_urls = @(); truncated = $false; error = $null }
    if ($Config.mode -eq 'list') {
        # A folder that is a link is listed only when it ends on a local path (Get-EsLinkReason).
        $entry.error = Get-EsPathLinkReason $Path
        if (-not $entry.error) { $entry.lines = @(Get-EsDirEntries $Path 200 | ForEach-Object { [string]$_.Name }) }
        return $entry
    }
    $file = Read-EsTextFile $Path ([int]$Config.max_bytes)
    if ($file.error) { $entry.error = $file.error; return $entry }
    # Endpoints (scheme://host[:port], never userinfo) and proxy settings (by their names,
    # 15-proxy) from the raw lines this entry keeps, as envscan.sh keeps them (es_config_raw):
    # no blank lines, no comment lines outside "lines" mode, no last line cut by the byte cap.
    $raw = @(([string]$file.text) -split "`n" | ForEach-Object { $_.TrimEnd("`r") })
    if ($file.truncated -and ([string]$file.text).Length -ge [int]$Config.max_bytes) { $raw = @($raw | Select-Object -First ($raw.Count - 1)) }
    if ($Config.mode -eq 'lines') { $raw = @($raw | Where-Object { Test-EsLineMatch $_ $Config.match }) }
    else { $raw = @($raw | Where-Object { $_ -cnotmatch '^[ \t]*[#;]' }) }
    $raw = @($raw | Where-Object { $_ -cnotmatch '^[ \t]*$' })
    $entry.urls = @(Get-EsEndpointUrls ($raw -join "`n"))
    $settings = @(Get-EsConfigProxySettings $raw)
    $entry.proxy_urls = @(ConvertTo-EsProxyUrls $settings)
    # For net.proxy (probe_pkg_sources moves them out of the entry).
    $entry.proxy_settings = @(ConvertTo-EsProxySettingItems $settings $Config.tool $Path)
    # Redact the whole text first: secret blocks (JSON/YAML) and private keys span lines.
    $text = Protect-EsText ([string]$file.text)
    $lines = @(([string]$text) -split "`n" | ForEach-Object { $_.TrimEnd("`r") })
    if ($Config.mode -eq 'lines') { $lines = @($lines | Where-Object { Test-EsLineMatch $_ $Config.match }) }
    $entry.lines = $lines
    $entry.truncated = [bool]$file.truncated
    return $entry
}

function Get-EsConfigEntries([hashtable]$Result, [object[]]$Configs) {
    $entries = @()
    foreach ($config in @($Configs)) {
        $paths = @()
        foreach ($pattern in @($config.paths)) {
            foreach ($path in @(Expand-EsPathPattern ([string]$pattern) $Result)) {
                if ($paths -notcontains $path) { $paths += $path }
            }
        }
        $isList = ($config.mode -eq 'list')
        $paths = @($paths | Where-Object { (Test-Path -LiteralPath $_ -PathType Container) -eq $isList } | Select-Object -First $script:ES_MAX_CONFIG_FILES)
        foreach ($path in $paths) {
            $Result.sources += ('read ' + $path)
            $entry = Read-EsConfigFile $config $path
            Add-EsReadNote $Result $path $entry.error ('read ' + $path)
            $entries += $entry
        }
    }
    return $entries
}

function probe_pkg_sources {
    $r = New-EsResult
    $d = $r.data
    $configs = @(Get-EsConfigEntries $r $script:ES_CONFIGS)
    $d.configs = $configs
    $d.env = Get-EsEnvSubset $script:ES_PACKAGE_ENV
    $r.sources += 'environment package variables'
    $git = Get-EsGitConfig $r
    $d.git_config = @()
    $urls = @()
    $proxies = @()
    if ($git) { $d.git_config = @($git.items); $urls += @($git.urls); $proxies += @($git.proxy_urls) }
    $settings = @()
    foreach ($entry in $configs) {
        $urls += @($entry.urls)
        foreach ($url in @($entry.proxy_urls)) { $proxies += @{ tool = $entry.tool; url = $url; source = $entry.path } }
        # The settings found by name, for net.proxy (as envscan.sh: the files, then git).
        $settings += @($entry.proxy_settings | Where-Object { $_ })
        $entry.Remove('proxy_settings')
    }
    if ($git) { $settings += @($git.proxy_settings | Where-Object { $_ }) }
    $script:ES_PKG_PROXY_SETTINGS = $settings
    # Endpoints from the raw variable values (the data keeps the redacted ones).
    foreach ($name in @($d.env.PSBase.Keys)) { $urls += @(Get-EsEndpointUrls ([string](Get-EsOrigEnv $name))) }
    $d.endpoints = @($urls | Where-Object { $_ } | Sort-Object -Unique)
    $d.proxy_urls = $proxies
    $d.config_count = $configs.Count
    return $r
}

function Get-EsDirSummary([string]$Path, [int]$Max = 10000) {
    $entries = @(Get-EsDirEntries $Path ($Max + 1))
    $modified = $null
    try { $modified = Format-EsUtc (Get-Item -LiteralPath $Path -Force -ErrorAction Stop).LastWriteTimeUtc } catch { }
    $count = $entries.Count
    $shown = $count
    if ($shown -gt $Max) { $shown = $Max }
    return @{ entries = $shown; truncated = ($count -gt $Max); modified_utc = $modified }
}

function probe_pkg_caches {
    $r = New-EsResult
    $caches = @()
    $seen = @{}
    foreach ($cache in @($script:ES_CACHES)) {
        foreach ($pattern in @($cache.paths)) {
            foreach ($path in @(Expand-EsPathPattern ([string]$pattern) $r)) {
                $key = $path.ToLowerInvariant()
                if ($seen.ContainsKey($key) -or -not (Test-Path -LiteralPath $path -PathType Container)) { continue }
                $seen[$key] = $true
                # A cache folder that is a link is listed only when it ends on a local path.
                $link = Get-EsPathLinkReason $path
                if ($link) { Add-EsReadNote $r $path $link; continue }
                $r.sources += ('list ' + $path)
                $summary = Get-EsDirSummary $path
                $caches += @{ id = $cache.id; tool = $cache.tool; path = $path; entries = $summary.entries; truncated = $summary.truncated; modified_utc = $summary.modified_utc }
            }
        }
    }
    $r.data.caches = $caches
    # Caches left out because they are links are not "not found": the probe is partial.
    if ($caches.Count -eq 0 -and $r.status -eq 'ok') { $r.status = 'not_found'; $r.notes += 'no known dependency cache directory exists for this user' }
    return $r
}

function Get-EsUninstallEntries([hashtable]$Result) {
    $views = @(
        @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'machine'),
        @('HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall', 'machine-32bit'),
        @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall', 'user')
    )
    $packages = @()
    foreach ($view in $views) {
        $Result.sources += ('registry ' + ($view[0] -replace '^(HK..):', '$1'))
        if (-not (Test-EsRegKey $view[0])) { continue }
        try { $items = @(Get-ItemProperty -Path ($view[0] + '\*') -ErrorAction Stop) }
        catch { Add-EsNote $Result ('uninstall key ' + $view[1] + ': ' + $_.Exception.Message) 'partial'; continue }
        foreach ($item in $items) {
            if (-not $item.DisplayName -or [string]$item.SystemComponent -eq '1' -or $item.ParentKeyName) { continue }
            if ([string]$item.ReleaseType -match '(?i)update|hotfix') { continue }
            $packages += @{ name = [string]$item.DisplayName; version = [string]$item.DisplayVersion; publisher = [string]$item.Publisher; source = $view[1] }
        }
    }
    return $packages
}

function Get-EsAppxEntries([hashtable]$Result) {
    # Store (Appx) packages of the current user; listed = $false when they could not be read.
    # PowerShell 6+ would load the Appx module through a Windows PowerShell compatibility
    # session: an extra powershell.exe outside the scanner's time limits. Skipped there.
    if ($script:ES_PS_MAJOR -ge 6) {
        Add-EsNote $Result 'Store (Appx) packages are listed only when the scan runs in Windows PowerShell' 'partial'
        return @{ items = @(); listed = $false }
    }
    $Result.sources += 'Get-AppxPackage (current user)'
    try {
        $items = @(Get-AppxPackage -ErrorAction Stop | Where-Object { -not $_.IsFramework } | ForEach-Object {
                @{ name = [string]$_.Name; version = [string]$_.Version; publisher = [string]$_.PublisherId; source = 'appx' }
            })
        return @{ items = $items; listed = $true }
    } catch {
        Add-EsNote $Result ('Get-AppxPackage: ' + $_.Exception.Message) ''
        return @{ items = @(); listed = $false }
    }
}

function Get-EsAppxGroup([hashtable]$Result) {
    $appx = Get-EsAppxEntries $Result
    return @{ name = 'appx'; items = @($appx.items); listed = $appx.listed }
}

function Get-EsFolderPackages([hashtable]$Result, [string[]]$Roots, [string]$Source, [string]$ManifestPattern) {
    $packages = @()
    foreach ($root in @($Roots | Where-Object { $_ })) {
        if (-not (Test-EsLocalPath $root) -or -not (Test-EsListableFolder $Result $root)) { continue }
        $Result.sources += ('list ' + $root)
        foreach ($dir in @(Get-EsDirEntries $root 1000 | Where-Object { $_.PSIsContainer })) {
            $version = $null
            if ($ManifestPattern) {
                # A package folder (or "current") that is a link not followed is noted, not entered.
                $manifest = Join-Path $dir.FullName ($ManifestPattern -replace '<name>', $dir.Name)
                $refused = Get-EsRefusedFolder $manifest
                if ($refused) { Add-EsReadNote $Result $refused.path $refused.reason }
                elseif (Test-Path -LiteralPath $manifest -PathType Leaf) {
                    $file = Read-EsTextFile $manifest 8192
                    Add-EsReadNote $Result $manifest $file.error
                    $text = [string]$file.text
                    if ($text -match '(?i)"?<?version"?>?\s*[:>]?\s*"?([0-9][^"<\s,]*)') { $version = $matches[1] }
                }
            }
            $packages += @{ name = [string]$dir.Name; version = $version; publisher = $null; source = $Source }
        }
    }
    return $packages
}

function Get-EsModulePackages([hashtable]$Result) {
    $packages = @()
    foreach ($root in @(([string](Get-EsOrigEnv 'PSModulePath')) -split ';' | Where-Object { $_ })) {
        if (-not (Test-EsLocalPath $root) -or -not (Test-EsListableFolder $Result $root)) { continue }
        $Result.sources += ('list ' + $root)
        foreach ($dir in @(Get-EsDirEntries $root 500 | Where-Object { $_.PSIsContainer })) {
            $versions = @(Get-EsDirEntries $dir.FullName 50 | Where-Object { $_.PSIsContainer -and $_.Name -match '^\d+(\.\d+)+$' } | ForEach-Object { $_.Name })
            $packages += @{ name = [string]$dir.Name; version = ($versions -join ', '); publisher = $null; source = 'psmodule' }
        }
    }
    return $packages
}

function probe_pkg_installed {
    $r = New-EsResult
    $profilePath = Get-EsOrigEnv 'USERPROFILE'
    $programData = Get-EsOrigEnv 'ProgramData'
    $choco = Get-EsOrigEnv 'ChocolateyInstall'
    if (-not $choco -and $programData) { $choco = Join-Path $programData 'chocolatey' }
    $scoopRoots = @()
    if (Get-EsOrigEnv 'SCOOP') { $scoopRoots += (Join-Path (Get-EsOrigEnv 'SCOOP') 'apps') }
    if ($profilePath) { $scoopRoots += (Join-Path $profilePath 'scoop\apps') }
    if ($programData) { $scoopRoots += (Join-Path $programData 'scoop\apps') }
    $groups = @(
        @{ name = 'uninstall-registry'; items = @(Get-EsUninstallEntries $r) },
        (Get-EsAppxGroup $r),
        @{ name = 'chocolatey'; items = @(Get-EsFolderPackages $r @((Join-Path ([string]$choco) 'lib')) 'chocolatey' '<name>.nuspec') },
        @{ name = 'scoop'; items = @(Get-EsFolderPackages $r $scoopRoots 'scoop' 'current\manifest.json') },
        @{ name = 'powershell-modules'; items = @(Get-EsModulePackages $r) }
    )
    $all = @()
    $managers = @()
    foreach ($group in $groups) {
        # A source that could not be read has an unknown count, never 0.
        $count = $(if ($group.ContainsKey('listed') -and -not $group.listed) { $null } else { @($group.items).Count })
        $managers += @{ name = $group.name; count = $count }
        $all += @($group.items)
    }
    $sorted = @($all | Sort-Object { $_.name })
    $r.data.managers = $managers
    $r.data.count = $sorted.Count
    $r.data.packages = @($sorted | Select-Object -First $script:ES_MAX_PACKAGES)
    $r.data.truncated = ($sorted.Count -gt $script:ES_MAX_PACKAGES)
    return $r
}

function probe_pkg_features {
    $r = New-EsResult
    $items = @(Add-EsCimItems $r 'Win32_OptionalFeature' 'root/cimv2' 'InstallState=1')
    $names = @($items | ForEach-Object { [string]$_.Name } | Sort-Object)
    $r.data.enabled = $names
    $r.data.count = $names.Count
    $r.data.powershell_v2_engine = ($names -contains 'MicrosoftWindowsPowerShellV2Root')
    if ($names.Count -eq 0 -and $r.status -eq 'ok') { Add-EsNote $r 'no enabled optional features were returned' 'partial' }
    return $r
}
