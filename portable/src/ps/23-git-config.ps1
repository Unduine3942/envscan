# ---------------------------------------------------------------------------
# 23-git-config: git's configuration for pkg.sources: git config --list run so that it reads
# no repository and nothing on the network, and the include files it names, read one level
# deep by the scanner itself (git runs with --no-includes).
# ---------------------------------------------------------------------------

function Get-EsGitHome {
    # The home folder Git for Windows uses: HOME, else HOMEDRIVE + HOMEPATH when that folder
    # exists, else USERPROFILE. Only an absolute local path is checked: a home on the network
    # (or a relative one) is kept as it is and never touched.
    $gitHome = Get-EsOrigEnv 'HOME'
    if (-not $gitHome -and (Get-EsOrigEnv 'HOMEDRIVE') -and (Get-EsOrigEnv 'HOMEPATH')) {
        $candidate = (Get-EsOrigEnv 'HOMEDRIVE') + (Get-EsOrigEnv 'HOMEPATH')
        if (-not (Test-EsLocalPath $candidate) -or (Get-EsPathLinkReason $candidate) -or (Test-Path -LiteralPath $candidate -PathType Container)) { $gitHome = $candidate }
    }
    if (-not $gitHome) { $gitHome = Get-EsOrigEnv 'USERPROFILE' }
    return $gitHome
}

function Join-EsGitPath([string]$Folder, [string]$Child) {
    # Folder\Child as text (Join-Path would look up the drive of a share or a missing drive).
    if (-not $Folder) { return $null }
    return ($Folder.Replace('/', '\').TrimEnd('\') + '\' + $Child)
}

function Get-EsGitLocations {
    # The configuration locations of the git child, in order: the variable that replaces a
    # location git must not read, the label and scope of its note and the paths to check. HOME
    # covers the home folder and its .gitconfig; XDG_CONFIG_HOME its git folder (default
    # <home>\.config\git, below_home); ProgramData the system-wide file of Git for Windows (strict: anything
    # but a local path is refused, and GIT_CONFIG_NOSYSTEM=1 switches the system scope off).
    $gitHome = [string](Get-EsGitHome)
    $xdg = [string](Get-EsOrigEnv 'XDG_CONFIG_HOME')
    $xdgPaths = $(if ($xdg) { @($xdg, (Join-EsGitPath $xdg 'git')) } else { @(Join-EsGitPath $gitHome '.config\git') })
    $programData = [string](Get-EsOrigEnv 'ProgramData')
    $global = [string](Get-EsOrigEnv 'GIT_CONFIG_GLOBAL')
    $system = [string](Get-EsOrigEnv 'GIT_CONFIG_SYSTEM')
    return @(
        @{ name = 'HOME'; label = 'git home folder'; scope = 'global'; paths = @($gitHome, (Join-EsGitPath $gitHome '.gitconfig')) },
        @{ name = 'XDG_CONFIG_HOME'; label = 'XDG_CONFIG_HOME'; scope = 'global'; paths = $xdgPaths; below_home = (-not $xdg) },
        @{ name = 'GIT_CONFIG_GLOBAL'; label = 'GIT_CONFIG_GLOBAL'; scope = 'global'; paths = @($global) },
        @{ name = 'GIT_CONFIG_SYSTEM'; label = 'GIT_CONFIG_SYSTEM'; scope = 'system'; paths = @($system) },
        @{ name = 'GIT_CONFIG_NOSYSTEM'; label = 'ProgramData'; scope = 'system'; strict = $true
            paths = @($(if ($programData) { @($programData, (Join-EsGitPath $programData 'Git'), (Join-EsGitPath $programData 'Git\config')) }))
        }
    )
}

function Get-EsGitLocationProblem([string]$Path, [bool]$Strict) {
    # Why git must not read a location: it is on a network path, or it (or a folder above it) is
    # a link that is not followed (Get-EsPathLinkReason). A relative path is git's own business,
    # unless $Strict. $null when git may read it.
    if (-not $Path) { return $null }
    $p = $Path.Replace('/', '\')
    if (Test-EsNetworkPath $p) { return 'is on a network path' }
    if (-not (Test-EsLocalPath $p)) { return $(if ($Strict) { 'is not a local path' } else { $null }) }
    $link = Get-EsPathLinkReason $p
    if ($link) { return ('is behind a link (' + $link + ')') }
    return $null
}

function Get-EsGitChildEnv([hashtable]$Result) {
    # Environment of the git child: the repository search stops at the scanner temp folder,
    # and a configuration location on a network path or behind a link (Get-EsGitLocations) is
    # replaced by an empty local folder, or the system scope is switched off (partial, noted).
    $local = Join-Path $script:ES_TMP 'githome'
    $overrides = @{ GIT_CEILING_DIRECTORIES = (Split-Path -Parent $script:ES_TMP) }
    foreach ($location in @(Get-EsGitLocations)) {
        # The default XDG folder lies in the home folder: a replaced home replaces it too.
        if ($location['below_home'] -and $overrides.ContainsKey('HOME')) { continue }
        foreach ($path in @($location.paths | Where-Object { $_ })) {
            $problem = Get-EsGitLocationProblem ([string]$path) ([bool]$location['strict'])
            if (-not $problem) { continue }
            $name = $location.name
            if ($name -eq 'GIT_CONFIG_NOSYSTEM') { $overrides[$name] = '1' }
            else {
                if (-not (Test-Path -LiteralPath $local)) { $null = New-Item -ItemType Directory -Path $local -ErrorAction Stop }
                $overrides[$name] = $(if ($name -like 'GIT_CONFIG_*') { Join-Path $local 'none' } else { $local })
            }
            Add-EsNote $Result ($location.label + ' ' + $path + ' ' + $problem + ': ' + $location.scope + ' git configuration from there is not read') 'partial'
            break
        }
    }
    return $overrides
}

function Invoke-EsCommandWithEnv([hashtable]$Overrides, [hashtable]$Parameters) {
    # Invoke-EsCommand with environment variables added for the child only (its -Environment
    # extras; this process environment is left as it is).
    $call = @{}
    foreach ($name in @($Parameters.PSBase.Keys)) { $call[$name] = $Parameters[$name] }
    $call['Environment'] = $Overrides
    return (Invoke-EsCommand @call)
}

function ConvertFrom-EsGitQuoted([string]$Text) {
    # A path as git prints it: an unusual one (a backslash, a quote, a non-ASCII character) is in
    # double quotes with C escapes, each byte of a non-ASCII character as \ooo (octal, UTF-8).
    # Text without a leading quote is returned unchanged; $null when the quoted form does not
    # decode (no closing quote, an escape git never writes, bytes that are not UTF-8).
    if (-not $Text.StartsWith('"')) { return $Text }
    if ($Text.Length -lt 2 -or -not $Text.EndsWith('"')) { return $null }
    $escapes = @{ a = 7; b = 8; t = 9; n = 10; v = 11; f = 12; r = 13; '"' = 34; '\' = 92 }
    $body = $Text.Substring(1, $Text.Length - 2)
    $out = ''
    $bytes = @()
    for ($i = 0; $i -lt $body.Length; $i++) {
        $ch = [string]$body[$i]
        if ($ch -eq '"') { return $null }
        if ($ch -eq '\') {
            if ($body.Substring($i + 1) -cmatch '\A[0-3][0-7][0-7]') {
                $digits = $matches[0]
                $bytes += ([int][string]$digits[0]) * 64 + ([int][string]$digits[1]) * 8 + [int][string]$digits[2]
                $i += 3
                continue
            }
            if ($i + 1 -ge $body.Length) { return $null }
            $next = [string]$body[$i + 1]
            if (-not $escapes.ContainsKey($next) -or $next -cne $next.ToLowerInvariant()) { return $null }
            $bytes += $escapes[$next]
            $i++
            continue
        }
        if ($bytes.Count -gt 0) { $out += ConvertFrom-EsUtf8Bytes $bytes; $bytes = @() }
        $out += $ch
    }
    if ($bytes.Count -gt 0) { $out += ConvertFrom-EsUtf8Bytes $bytes }
    if ($out.IndexOf([char]0xFFFD) -ge 0) { return $null }
    return $out
}

function Get-EsGitOriginFile([string]$Origin) {
    # The file of a --show-origin origin ("file:<path>") as a Windows path; $null for another
    # origin (command line, standard input, blob) or none.
    if (-not $Origin -or -not $Origin.StartsWith('file:')) { return $null }
    $path = ConvertFrom-EsGitQuoted $Origin.Substring(5)
    if (-not $path) { return $null }
    return $path.Replace('/', '\')
}

function Resolve-EsGitIncludePath([string]$Value, [string]$OriginFile, [string]$GitHome) {
    # The file an include.path names, as git resolves it: ~/ is the git home folder, a relative
    # path is relative to the folder of the file that has the include. $null where git would
    # use the current drive or location, another user's home, its install prefix (%(prefix)/)
    # or the folder of an origin that is not a file; also for device paths.
    $path = $Value.Replace('/', '\')
    if ($path.StartsWith('~\')) {
        if (-not $GitHome) { return $null }
        return ($GitHome.Replace('/', '\').TrimEnd('\') + $path.Substring(1))
    }
    if ($path -match '\A\\\\[.?]\\') { return $null }
    if ($path -match '\A[A-Za-z]:\\' -or $path.StartsWith('\\')) { return $path }
    if ($path -match '\A(\\|[A-Za-z]:|~|%\()' -or -not $OriginFile) { return $null }
    return ((Get-EsParentDir $OriginFile) + '\' + $path)
}

function Invoke-EsGitConfigList([hashtable]$Result, [hashtable]$Context, [string[]]$Extra = @()) {
    # git config --list --show-origin --no-includes <Extra>, from the scanner's own empty temp
    # folder (no repository configuration). A git that rejects --show-origin (before 2.8) or
    # --no-includes (before 1.7.10, which reads no includes) runs again without that option.
    while ($true) {
        $arguments = @('config', '--list')
        if ($Context.show_origin) { $arguments += '--show-origin' }
        if ($Context.no_includes) { $arguments += '--no-includes' }
        $parameters = @{ FilePath = $Context.git; Arguments = @($arguments + $Extra); Encoding = 'UTF8'; WorkingDirectory = $script:ES_TMP }
        $run = Invoke-EsCommandWithEnv $Context.env $parameters
        $Result.sources += ('run ' + $run.command)
        $run.ok = (-not $run.timed_out -and -not $run.error -and $run.exit_code -eq 0)
        if ($run.ok -or $run.timed_out -or $run.error) { return $run }
        $text = [string]$run.stdout + "`n" + [string]$run.stderr
        if ($Context.show_origin -and $text -match '(?<![-\w])show-origin') { $Context.show_origin = $false }
        elseif ($Context.no_includes -and $text -match '(?<![-\w])no-includes') { $Context.no_includes = $false }
        else { return $run }
    }
}

function Get-EsGitProblem([hashtable]$Run) {
    if ($Run.timed_out) { return 'timed out' }
    if ($Run.error) { return [string]$Run.error }
    $first = @(([string]$Run.stderr) -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }) | Select-Object -First 1
    if ($first) { return ('exit code ' + $Run.exit_code + ': ' + $first) }
    return ('exit code ' + $Run.exit_code)
}

function Add-EsGitEntries([hashtable]$Out, [string]$Text, [string]$Origin, [bool]$HasOrigin) {
    # The entries of one git config --list output into $Out (items redacted, urls, proxy_urls).
    # $Origin (an include file) replaces the listed origin. Endpoints come from the raw values
    # and the base of url.<base>.insteadOf (a mirror); other keys embed URLs only as a context
    # (credential.<url>.<setting>). Proxies come from the names of the settings (15-proxy), per
    # origin. Returns the include directives: @{ origin; value; condition }.
    $pattern = $(if ($HasOrigin) { '\A([^\t]*)\t([^=]+)=?(.*)\z' } else { '\A()([^=]+)=?(.*)\z' })
    $includes = @()
    $proxy = @{ state = (New-EsProxyState); origin = '' }
    foreach ($line in @($Text -split "`n")) {
        if ($line -notmatch $pattern) { continue }
        $setting = $line.Substring($matches[1].Length + [int]$HasOrigin).TrimEnd("`r")
        $from = $(if ($Origin) { $Origin } else { $matches[1] })
        $key = $matches[2].Trim()
        $value = $matches[3].TrimEnd("`r")
        $Out.items += @{ origin = $from; key = (Protect-EsValue $key); value = (Protect-EsNamedValue $key $value) }
        $found = @(Get-EsEndpointUrls $value)
        if ($key -match '\A(?i)url\.(.+)\.(push)?insteadof\z') { $found += @(Get-EsEndpointUrls $matches[1]) }
        $Out.urls += $found
        if ($from -cne $proxy.origin) { Add-EsGitProxyUrls $Out $proxy; $proxy.origin = $from }
        Add-EsProxyGitLine $proxy.state $setting
        if ($key -match '\A(?i)include\.path\z') { $includes += @{ origin = $from; value = $value; condition = $null } }
        elseif ($key -match '\A(?i)includeif\.(.+)\.path\z') { $includes += @{ origin = $from; value = $value; condition = $matches[1] } }
    }
    Add-EsGitProxyUrls $Out $proxy
    return $includes
}

function Add-EsGitProxyUrls([hashtable]$Out, [hashtable]$Proxy) {
    # The proxies of the git settings of one origin, as @{ tool = 'git'; url; source }, and the
    # settings found by name (net.proxy package_managers) when $Out collects them.
    $settings = @(Complete-EsProxySource $Proxy.state)
    $origin = Protect-EsValue $Proxy.origin
    foreach ($url in @(ConvertTo-EsProxyUrls $settings)) { $Out.proxy_urls += @{ tool = 'git'; url = $url; source = $origin } }
    if ($Out.ContainsKey('proxy_settings')) { $Out.proxy_settings += @(ConvertTo-EsProxySettingItems $settings 'git' $origin) }
}

function Add-EsGitIncludeNote([hashtable]$Result, [string]$Reason, [string]$Path, [string]$Status = 'partial') {
    $note = 'git include not read (' + $Reason + '): ' + $Path
    if (@($Result.notes) -notcontains $note) { Add-EsNote $Result $note $Status }
}

function Get-EsGitIncludePathReason([string]$Path) {
    # Why an include path is not read, from its text alone ($null: it may be). A credential
    # store (Test-EsCredentialPath) and a device name are never opened, tested or listed.
    if (-not $Path) { return 'not a local path' }
    if (Test-EsCredentialPath $Path) { return 'credential store' }
    if (Test-EsNetworkPath $Path) { return 'network path' }
    if (-not (Test-EsLocalPath $Path)) { return 'not a local path' }
    if (Test-EsDeviceName $Path) { return 'unreadable' }
    return $null
}

function Get-EsGitIncludeFileReason([string]$Path) {
    # Why a local include file is not read, without opening it: 'missing' (skipped, as git
    # skips it), 'unreadable' (a folder), 'network path' (a cloud placeholder, which downloads
    # when read, or a link to the network), 'credential store' (a link to one) or 'not a local
    # path' (a link to an unknown target): Get-EsLinkReason, for the file and every folder above
    # it (a folder link is never looked behind). $null: git may read it.
    $refused = Get-EsRefusedFolder $Path
    if ($refused) { return (ConvertTo-EsGitLinkReason $refused.reason) }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -eq $item) { return 'missing' }
    if ($item.PSIsContainer) { return 'unreadable' }
    if (Test-EsPlaceholderFile $item) { return 'network path' }
    return (ConvertTo-EsGitLinkReason (Get-EsLinkReason $item $Path))
}

function ConvertTo-EsGitLinkReason([string]$LinkReason) {
    # A Get-EsLinkReason reason as the reason of a git include note; $null for no reason.
    if (-not $LinkReason) { return $null }
    if ($LinkReason -like '*network path*') { return 'network path' }
    if ($LinkReason -like '*credential store*') { return 'credential store' }
    return 'not a local path'
}

function Read-EsGitInclude([hashtable]$Result, [hashtable]$Context, [hashtable]$Include, [hashtable]$Out) {
    # One include.path: listed with --file when it names a regular file on a local drive (each
    # file once), otherwise noted. Returns the include directives in that file.
    $path = Resolve-EsGitIncludePath ([string]$Include.value) (Get-EsGitOriginFile $Include.origin) $Context.home
    $reason = Get-EsGitIncludePathReason $path
    if (-not $reason) {
        if ($Context.seen.ContainsKey($path)) { return }
        $Context.seen[$path] = $true
        $reason = Get-EsGitIncludeFileReason $path
        if ($reason -eq 'missing') { return }
    }
    if (-not $reason) {
        $run = Invoke-EsGitConfigList $Result $Context @('--file', $path)
        if ($run.ok) { return (Add-EsGitEntries $Out ([string]$run.stdout) ('file:' + $path) $Context.show_origin) }
        $reason = 'unreadable'
    }
    Add-EsGitIncludeNote $Result $reason $(if ($path) { $path } else { [string]$Include.value })
}

function Read-EsGitIncludes([hashtable]$Result, [hashtable]$Context, [object[]]$Includes, [hashtable]$Out) {
    # include.path files are read one level deep: an include inside one is noted (partial).
    # includeIf.<condition>.path is only noted: its condition is not evaluated (no status change).
    $nested = @()
    foreach ($include in @($Includes)) {
        if ($null -ne $include.condition) { Add-EsGitIncludeNote $Result ('condition ' + $include.condition) $include.value ''; continue }
        $nested += @(Read-EsGitInclude $Result $Context $include $Out)
    }
    foreach ($include in $nested) {
        if ($null -ne $include.condition) { Add-EsGitIncludeNote $Result ('condition ' + $include.condition) $include.value '' }
        else { Add-EsGitIncludeNote $Result 'nested include' $include.value }
    }
}

function Get-EsGitConfig([hashtable]$Result) {
    # git config --list as @{ items; urls; proxy_urls }, with the files its include.path entries
    # name (one level). git itself never follows an include: --no-includes (a git without that
    # option has no includes, so none are read).
    $git = Find-EsToolPath 'git'
    if (-not $git) { return $null }
    try { $childEnv = Get-EsGitChildEnv $Result }
    catch { Add-EsNote $Result ('git config not run: ' + $_.Exception.Message) 'partial'; return $null }
    # ~/ in an include is the user's real home, also when git runs with a local stand-in for a
    # home on the network: an include there is then noted as a network path, not missed.
    $context = @{ git = $git; env = $childEnv; home = (Get-EsGitHome); show_origin = $true; no_includes = $true; seen = @{} }
    $run = Invoke-EsGitConfigList $Result $context
    if (-not $run.ok) {
        Add-EsNote $Result ('git config: ' + (Get-EsGitProblem $run)) 'partial'
        if ($run.timed_out -or $run.error) { return $null }
    }
    $out = @{ items = @(); urls = @(); proxy_urls = @(); proxy_settings = @() }
    $includes = @(Add-EsGitEntries $out ([string]$run.stdout) '' $context.show_origin)
    if ($context.no_includes) { Read-EsGitIncludes $Result $context $includes $out }
    $out.urls = @($out.urls | Sort-Object -Unique)
    return $out
}
