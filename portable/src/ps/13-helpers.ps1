# ---------------------------------------------------------------------------
# 13-helpers: shared probe helpers - original environment,
# token SIDs, write access from SDDL, PATH index and executable lookup, URLs.
# ---------------------------------------------------------------------------

$script:ES_PATH_DIRS = $null
$script:ES_PATH_INDEX = $null
$script:ES_PATH_RANK = $null
$script:ES_PATHEXT = $null
$script:ES_TOKEN_INFO = $null
$script:ES_PROFILE_ENTRY = $null
$script:ES_RUNNABLE_EXT = @('.exe', '.com', '.bat', '.cmd')

# SDDL aliases for the trustees that matter to a standard user.
$script:ES_SDDL_ALIASES = @{
    WD = 'S-1-1-0'; AU = 'S-1-5-11'; IU = 'S-1-5-4'; BU = 'S-1-5-32-545'; BA = 'S-1-5-32-544'
    SY = 'S-1-5-18'; PU = 'S-1-5-32-547'; AC = 'S-1-15-2-1'; CO = 'S-1-3-0'; OW = 'S-1-3-4'
    LS = 'S-1-5-19'; NS = 'S-1-5-20'; NU = 'S-1-5-2'; RD = 'S-1-5-32-555'; SU = 'S-1-5-6'
}
$script:ES_DEFAULT_GROUP_SIDS = @('S-1-1-0', 'S-1-2-0', 'S-1-5-4', 'S-1-5-11', 'S-1-5-15', 'S-1-5-32-545')

# ------------------------------------------------------------------ environment

function Get-EsOrigEnv([string]$Name) {
    # Value from the environment captured before the child environment was applied.
    if (-not $Name) { return $null }
    if ($script:ES_ENV_SNAPSHOT.ContainsKey($Name)) { return [string]$script:ES_ENV_SNAPSHOT[$Name] }
    return $null
}

function Get-EsEnvSubset([object[]]$Names) {
    # NAME -> redacted value for each listed variable that is set (names are case-insensitive on Windows).
    $out = @{}
    foreach ($name in @($Names)) {
        $key = [string]$name
        if ($out.ContainsKey($key)) { continue }
        $value = Get-EsOrigEnv $key
        if ($null -ne $value) { $out[$key] = Protect-EsNamedValue $key $value }
    }
    return $out
}

# ------------------------------------------------------------------ user token and profile

function Find-EsProfileEntry([string]$Sid) {
    # The ProfileList entry of the running user: by SID when known, else by profile path.
    $base = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $profilePath = ([string]$env:USERPROFILE).TrimEnd('\')
    $names = @()
    if ($Sid) { $names = @($Sid, ($Sid + '.bak')) } else { $names = @(Get-EsRegSubkeys $base) }
    foreach ($name in $names) {
        if ($name -notmatch '^S-1-(5-21|12-1)-') { continue }
        $values = Get-EsRegValues ($base + '\' + $name)
        if ($null -eq $values) { continue }
        $image = ([string]$values['ProfileImagePath']).TrimEnd('\')
        if ($Sid -or ($image -and $image -eq $profilePath)) {
            return @{ key = $name; sid = ($name -replace '\.bak$', ''); values = $values }
        }
    }
    return $null
}

function Get-EsTokenInfo {
    # User SID, group SIDs and elevation. Groups need FullLanguage; elsewhere defaults are assumed.
    if ($null -ne $script:ES_TOKEN_INFO) { return $script:ES_TOKEN_INFO }
    $info = @{ user_sid = $null; group_sids = @(); groups_source = 'assumed'; is_admin = $null; elevation_method = $null }
    if ($script:ES_FULL_LANGUAGE) {
        try {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $info.user_sid = [string]$identity.User.Value
            $info.group_sids = @(@($identity.Groups) | ForEach-Object { [string]$_.Value })
            $info.groups_source = 'token'
            $principal = [Security.Principal.WindowsPrincipal]$identity
            $info.is_admin = [bool]$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            $info.elevation_method = 'token (WindowsPrincipal)'
        } catch { Write-EsLog ('token query failed: ' + $_.Exception.Message) }
    }
    # Only Windows PowerShell 4-5 require elevation for -IncludeUserName; PowerShell 6+
    # allows it for the own process, so it proves nothing there.
    if ($null -eq $info.is_admin -and $script:ES_PS_MAJOR -ge 4 -and $script:ES_PS_MAJOR -le 5) {
        try {
            $null = Get-Process -Id $PID -IncludeUserName -ErrorAction Stop
            $info.is_admin = $true
        } catch {
            if ([string]$_.FullyQualifiedErrorId -match 'Elevat' -or $_.Exception.Message -match '(?i)elevat') { $info.is_admin = $false }
        }
        if ($null -ne $info.is_admin) { $info.elevation_method = 'Get-Process -IncludeUserName' }
    }
    if (-not $info.user_sid) {
        $entry = Find-EsProfileEntry ''
        if ($entry) { $info.user_sid = $entry.sid }
    }
    if ($info.group_sids.Count -eq 0) { $info.group_sids = $script:ES_DEFAULT_GROUP_SIDS }
    # Administrators grants access only to an elevated token (deny-only otherwise).
    if (-not $info.is_admin) { $info.group_sids = @($info.group_sids | Where-Object { $_ -ne 'S-1-5-32-544' }) }
    $script:ES_TOKEN_INFO = $info
    return $info
}

function Get-EsTrusteeSids {
    # SIDs that grant access to this process: user, groups, and Administrators only when elevated.
    $info = Get-EsTokenInfo
    $sids = @($info.group_sids)
    if ($info.user_sid) { $sids += $info.user_sid }
    if ($info.is_admin) { $sids += 'S-1-5-32-544' }
    return $sids
}

# ------------------------------------------------------------------ write access from SDDL

function Test-EsSddlRight([string]$Rights, [int]$Bit) {
    # True when an ACE right string grants $Bit (0x2 add file, 0x4 add subdirectory) or generic write.
    if ($Rights -match '^0x[0-9A-Fa-f]+$') {
        $mask = [long]$Rights
        return (($mask -band ($Bit -bor 0x10000000 -bor 0x40000000)) -ne 0)
    }
    for ($i = 0; $i + 1 -lt $Rights.Length; $i += 2) {
        $code = $Rights.Substring($i, 2).ToUpperInvariant()
        if (@('GA', 'GW', 'FA', 'FW') -contains $code) { return $true }
        if ($Bit -eq 2 -and $code -eq 'DC') { return $true }
        if ($Bit -eq 4 -and $code -eq 'LC') { return $true }
    }
    return $false
}

function Get-EsAclSddl([string]$Path) {
    # PowerShell 2.0 has no Get-Acl -LiteralPath, and Get-Acl -Path fails on [ ] even when
    # they are escaped: the item's own ACL method instead (PowerShell 2.0 is always
    # FullLanguage).
    if ($script:ES_PS_MAJOR -lt 3) { return [string](Get-Item -LiteralPath $Path -Force -ErrorAction Stop).GetAccessControl().Sddl }
    return [string](Get-Acl -LiteralPath $Path -ErrorAction Stop).Sddl
}

function Get-EsSddlAccess([string]$Path) {
    # Whether this user may create files / subdirectories in $Path, read from the DACL without writing.
    $result = @{ create_files = $null; create_dirs = $null; error = $null }
    if (-not (Test-EsLocalPath $Path)) { $result.error = 'not an absolute local path'; return $result }
    try { $sddl = Get-EsAclSddl $Path }
    catch { $result.error = $_.Exception.Message; return $result }
    $start = $sddl.IndexOf('D:')
    if ($start -lt 0) { $result.error = 'no DACL'; return $result }
    $dacl = $sddl.Substring($start)
    $end = $dacl.IndexOf('S:')
    if ($end -gt 0) { $dacl = $dacl.Substring(0, $end) }
    $sids = @(Get-EsTrusteeSids)
    if ($sddl -match '^O:(S-1-[0-9-]+|[A-Z][A-Z])') {
        # OWNER RIGHTS (OW) entries apply when this user, or one of its groups, owns the object.
        $owner = $matches[1]
        if ($script:ES_SDDL_ALIASES.ContainsKey($owner)) { $owner = $script:ES_SDDL_ALIASES[$owner] }
        if ($sids -contains $owner) { $sids += 'S-1-3-4' }
    }
    $allow = @{ 2 = $false; 4 = $false }
    $deny = @{ 2 = $false; 4 = $false }
    foreach ($ace in [regex]::Matches($dacl, '\((A|D|XA|XD);([A-Z]*);([^;]*);[^;]*;[^;]*;([^;)]+)')) {
        $flags = $ace.Groups[2].Value
        $inheritOnly = $false
        for ($i = 0; $i + 1 -lt $flags.Length; $i += 2) { if ($flags.Substring($i, 2) -eq 'IO') { $inheritOnly = $true } }
        if ($inheritOnly) { continue }
        $trustee = $ace.Groups[4].Value
        if ($script:ES_SDDL_ALIASES.ContainsKey($trustee)) { $trustee = $script:ES_SDDL_ALIASES[$trustee] }
        if ($sids -notcontains $trustee) { continue }
        $isDeny = $ace.Groups[1].Value.StartsWith('D') -or $ace.Groups[1].Value -eq 'XD'
        foreach ($bit in @(2, 4)) {
            if (Test-EsSddlRight $ace.Groups[3].Value $bit) {
                if ($isDeny) { $deny[$bit] = $true } else { $allow[$bit] = $true }
            }
        }
    }
    $result.create_files = ($allow[2] -and -not $deny[2])
    $result.create_dirs = ($allow[4] -and -not $deny[4])
    return $result
}

# ------------------------------------------------------------------ PATH and executables

function Get-EsPathDirs {
    # Absolute, local, existing PATH directories in order; network and relative entries are
    # skipped, and so is a folder that is (or is below) a link that is not followed.
    if ($null -ne $script:ES_PATH_DIRS) { return $script:ES_PATH_DIRS }
    $dirs = @()
    $seen = @{}
    foreach ($entry in @(([string](Get-EsOrigEnv 'Path')) -split ';')) {
        $dir = $entry.Trim().Trim('"')
        if ($dir -notmatch '^[A-Za-z]:\\' -or (Test-EsNetworkPath $dir)) { continue }
        $dir = $dir.TrimEnd('\')
        $key = $dir.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        if (Test-EsSafePath $dir 'Container') { $dirs += $dir }
    }
    $script:ES_PATH_DIRS = $dirs
    return $dirs
}

function Get-EsPathIndex {
    # lower-case file name -> full paths in PATH order; each PATH directory is listed once.
    if ($null -ne $script:ES_PATH_INDEX) { return $script:ES_PATH_INDEX }
    $index = @{}
    $rank = @{}
    $position = 0
    foreach ($dir in @(Get-EsPathDirs)) {
        $position++
        $rank[$dir.ToLowerInvariant()] = $position
        $names = @()
        try { $names = @(Get-ChildItem -LiteralPath ($dir + '\') -Name -Force -ErrorAction Stop | Select-Object -First 20000) }
        catch { Write-EsLog ('cannot list PATH directory ' + $dir + ': ' + $_.Exception.Message); continue }
        foreach ($name in $names) {
            $key = ([string]$name).ToLowerInvariant()
            $full = $dir + '\' + [string]$name
            if ($index.ContainsKey($key)) { $index[$key] = @($index[$key]) + $full } else { $index[$key] = @($full) }
        }
    }
    $script:ES_PATH_INDEX = $index
    $script:ES_PATH_RANK = $rank
    return $index
}

function Get-EsPathExt {
    if ($null -ne $script:ES_PATHEXT) { return $script:ES_PATHEXT }
    $value = Get-EsOrigEnv 'PATHEXT'
    if (-not $value) { $value = '.COM;.EXE;.BAT;.CMD' }
    $exts = @($value -split ';' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ -match '^\.[a-z0-9]+$' })
    if ($exts -notcontains '.ps1') { $exts += '.ps1' }
    $script:ES_PATHEXT = $exts
    return $exts
}

function Get-EsParentDir([string]$Path) {
    $slash = $Path.LastIndexOf('\')
    if ($slash -le 0) { return $Path }
    return $Path.Substring(0, $slash)
}

function Get-EsExtension([string]$Path) {
    $leaf = $Path.Substring($Path.LastIndexOf('\') + 1)
    $dot = $leaf.LastIndexOf('.')
    if ($dot -lt 0) { return '' }
    return $leaf.Substring($dot).ToLowerInvariant()
}

function Find-EsExecutable([object[]]$Names, [object[]]$Dirs = @()) {
    # Every match as @{ path; on_path }: PATH order (PATHEXT order inside a directory) for the
    # first name that matches, then the other names, then the spec's extra directories.
    $index = Get-EsPathIndex
    $exts = Get-EsPathExt
    $found = @()
    foreach ($name in @($Names)) {
        $matchesForName = @()
        $extRank = 0
        foreach ($ext in $exts) {
            $extRank++
            $key = ([string]$name + $ext).ToLowerInvariant()
            if (-not $index.ContainsKey($key)) { continue }
            foreach ($full in @($index[$key])) {
                $dirRank = $script:ES_PATH_RANK[(Get-EsParentDir $full).ToLowerInvariant()]
                $matchesForName += @{ path = $full; on_path = $true; rank = (100 * [int]$dirRank) + $extRank }
            }
        }
        $found += @($matchesForName | Sort-Object { $_.rank })
    }
    foreach ($pattern in @($Dirs)) {
        foreach ($dir in @(Expand-EsPathPattern ([string]$pattern))) {
            if (Get-EsPathLinkReason $dir) { continue }
            foreach ($name in @($Names)) {
                foreach ($ext in @($script:ES_RUNNABLE_EXT + '.ps1')) {
                    $candidate = $dir.TrimEnd('\') + '\' + [string]$name + $ext
                    if (Test-Path -LiteralPath $candidate -PathType Leaf) { $found += @{ path = $candidate; on_path = $false; rank = 0 } }
                }
            }
        }
    }
    $unique = @()
    $seen = @{}
    foreach ($item in $found) {
        $key = $item.path.ToLowerInvariant()
        if (-not $seen.ContainsKey($key)) { $seen[$key] = $true; $unique += $item }
    }
    return $unique
}

function Get-EsShimManager([string]$Path) {
    # Name of the version manager whose shim directory holds $Path, else $null.
    $dir = (Get-EsParentDir $Path).ToLowerInvariant().Replace('\', '/')
    foreach ($manager in @($script:ES_VMANAGERS)) {
        foreach ($marker in @($manager.markers)) {
            if (-not $marker -or -not $dir.Contains([string]$marker)) { continue }
            if ($manager.requires) {
                $nativeDir = Get-EsParentDir $Path
                $present = @($script:ES_RUNNABLE_EXT + '') | Where-Object { Test-Path -LiteralPath ($nativeDir + '\' + $manager.requires + $_) -PathType Leaf }
                if (@($present).Count -eq 0) { continue }
            }
            return [string]$manager.name
        }
    }
    return $null
}

function Test-EsAppAlias([string]$Path) {
    return ($Path.ToLowerInvariant().Replace('\', '/').Contains('/microsoft/windowsapps/'))
}

function Test-EsWslLauncher([string]$Path) {
    return ($Path.ToLowerInvariant() -match '\\windows\\(system32|sysnative|syswow64)\\(bash|wsl|wslhost)\.exe$')
}

function Get-EsNoRunReason([hashtable]$Tool, [string]$Path) {
    # Why a located executable must not be run, or $null when it may be.
    if ($Tool.mode -eq 'presence') { return 'inventory only (spec mode presence)' }
    $ext = Get-EsExtension $Path
    if ($ext -eq '.ps1') { return 'PowerShell script shim; not run inside the scanner session' }
    if ($script:ES_RUNNABLE_EXT -notcontains $ext) { return ('file type ' + $ext + ' is not run') }
    if ((Test-EsAppAlias $Path) -and $Tool.id -ne 'winget') { return 'app execution alias (WindowsApps); not run' }
    if (Test-EsWslLauncher $Path) { return 'WSL launcher; not run' }
    $manager = Get-EsShimManager $Path
    if ($manager) { return ('version-manager shim (' + $manager + '); not run') }
    $link = Get-EsPathLinkReason $Path
    if ($link) { return ($link + '; not run') }
    return $null
}

function Find-EsToolPath([string]$Id) {
    # First runnable path of a spec tool (usable before tools.inventory has run), or $null.
    foreach ($tool in @($script:ES_TOOLS)) {
        if ($tool.id -ne $Id) { continue }
        foreach ($match in @(Find-EsExecutable $tool.exe $tool.dirs)) {
            if (-not (Get-EsNoRunReason $tool $match.path)) { return $match.path }
        }
    }
    return $null
}

# ------------------------------------------------------------------ URLs and endpoints

# XML namespaces and schemas are identifiers, not package sources.
$script:ES_SCHEMA_URL_RE = '(?i)^https?://(www\.w3\.org|schemas\.(xmlsoap\.org|microsoft\.com|openxmlformats\.org)|json-schema\.org|maven\.apache\.org/(POM|SETTINGS|xsd|maven-v))'

# An http(s) URL that does not continue a word or a key (credential.https://...), its
# authority (userinfo@host:port) and the rest; the host[:port] at the start of what follows
# the last "@" of the authority.
$script:ES_ENDPOINT_URL_RE = '(?i)(?<![A-Za-z0-9.+-])(https?)://([^/?#\s]*)([^\s"''<>]*)'
$script:ES_ENDPOINT_HOST_RE = '\A(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9][A-Za-z0-9.-]*)(:[0-9]{1,5})?(?![A-Za-z0-9.:\[\]@-])'

function Get-EsEndpointUrls([string]$Text) {
    # scheme://host[:port] (lower case) of every http(s) URL in configuration text, in order of
    # first appearance. Read from the raw text: redaction would cut a URL at its userinfo, and
    # the result never holds userinfo, a path or a query. Comment lines and XML namespace and
    # schema references are skipped.
    if (-not $Text) { return @() }
    $urls = @()
    foreach ($line in ($Text -split "`n")) {
        if ($line -match '\A\s*(#|;|<!--|//\s|REM\s)') { continue }
        $clean = $line -replace '(?i)\b(xmlns(:\w+)?|(xsi:)?schemaLocation)\s*=\s*"[^"]*"', ''
        foreach ($m in [regex]::Matches($clean, $script:ES_ENDPOINT_URL_RE)) {
            $authority = $m.Groups[2].Value
            $hostMatch = [regex]::Match($authority.Substring($authority.LastIndexOf('@') + 1), $script:ES_ENDPOINT_HOST_RE)
            if (-not $hostMatch.Success) { continue }
            # One trailing dot (an absolute DNS name) would let a public host pass as another host.
            $hostPort = $hostMatch.Value -replace '\.(:[0-9]+)?\z', '$1'
            $base = ($m.Groups[1].Value + '://' + $hostPort).ToLowerInvariant()
            if (($base + $m.Groups[3].Value) -match $script:ES_SCHEMA_URL_RE -or $urls -contains $base) { continue }
            $urls += $base
        }
    }
    return $urls
}

function Test-EsNetNever([string]$HostName) {
    # Cloud metadata and link-local hosts and addresses (spec net_never): never resolved or
    # contacted. An entry ending in "." or ":" is an address prefix, any other a whole host.
    $name = ([string]$HostName).Trim().TrimStart('[').TrimEnd(']').TrimEnd('.').ToLowerInvariant()
    if (-not $name) { return $false }
    foreach ($entry in @($script:ES_NET_NEVER)) {
        $text = [string]$entry
        if ($text.EndsWith('.') -or $text.EndsWith(':')) {
            if ($name.Length -ge $text.Length -and $name.Substring(0, $text.Length) -ceq $text) { return $true }
        } elseif ($name -ceq $text) { return $true }
    }
    return $false
}

# Default ports of URL schemes; an unknown scheme without an explicit port is not usable.
$script:ES_SCHEME_PORTS = @{ http = 80; https = 443; socks = 1080; socks4 = 1080; socks4a = 1080; socks5 = 1080; socks5h = 1080; ftp = 21; git = 9418; ssh = 22 }

function ConvertTo-EsEndpoint([string]$Value, [string]$Source) {
    # host and port from a URL or host:port. $null unless the host is a name, an IPv4 or an
    # IPv6 address; also for localhost and net-never hosts (Test-EsNetNever).
    if (-not $Value) { return $null }
    $v = $Value.Trim().Trim('"', "'")
    $port = $null
    if ($v -match '\A([A-Za-z][A-Za-z0-9+.\-]*)://') {
        $scheme = $matches[1].ToLowerInvariant()
        $v = $v.Substring($matches[0].Length)
        if ($script:ES_SCHEME_PORTS.ContainsKey($scheme)) { $port = $script:ES_SCHEME_PORTS[$scheme] } else { $port = -1 }
    }
    $authority = ($v -split '[/?#\s]')[0]
    $hostPort = $authority.Substring($authority.LastIndexOf('@') + 1)
    $hostName = $null
    if ($hostPort -match '\A\[([0-9A-Fa-f:.]+)\](?::([0-9]{1,5}))?\z' -or $hostPort -match '\A([A-Za-z0-9][A-Za-z0-9.\-]*)(?::([0-9]{1,5}))?\z') {
        $hostName = $matches[1]
        if ($matches[2]) { $port = [int]$matches[2] }
    } elseif ($hostPort -match '\A[0-9A-Fa-f]*:[0-9A-Fa-f.]*:[0-9A-Fa-f:.]*\z') { $hostName = $hostPort }
    if (-not $hostName -or $port -eq -1) { return $null }
    # One trailing dot goes, except after an IPv4 literal: "10.0.0.1." stays as written, and
    # net.reachability skips it (Get-EsNameRefusal) rather than contact or resolve it.
    if ($hostName -notmatch '\A[0-9]{1,3}(\.[0-9]{1,3}){3}\.\z') { $hostName = $hostName -replace '\.\z', '' }
    $hostName = $hostName.ToLowerInvariant()
    if ((Test-EsNetNever $hostName) -or @('localhost', '127.0.0.1', '::1') -contains $hostName) { return $null }
    if (-not $port) { $port = 80 }
    return @{ host = $hostName; port = $port; source = $Source }
}

# ------------------------------------------------------------------ text

function ConvertFrom-EsUtf8Bytes([int[]]$Bytes) {
    # UTF-8 bytes as text, decoded by hand (ConstrainedLanguage has no .NET encoders). A
    # malformed sequence becomes U+FFFD; a code point above U+FFFF a surrogate pair.
    $chars = @()
    $i = 0
    while ($i -lt $Bytes.Count) {
        $b = $Bytes[$i]
        $i++
        $more = 0
        if ($b -lt 0x80) { $code = $b }
        elseif ($b -lt 0xC0 -or $b -ge 0xF8) { $code = 0xFFFD }
        elseif ($b -ge 0xF0) { $code = $b - 0xF0; $more = 3 }
        elseif ($b -ge 0xE0) { $code = $b - 0xE0; $more = 2 }
        else { $code = $b - 0xC0; $more = 1 }
        for ($k = 0; $k -lt $more; $k++) {
            if ($i -ge $Bytes.Count -or $Bytes[$i] -lt 0x80 -or $Bytes[$i] -gt 0xBF) { $code = 0xFFFD; break }
            $code = $code * 64 + ($Bytes[$i] - 0x80)
            $i++
        }
        if ($code -gt 0x10FFFF) { $code = 0xFFFD }
        if ($code -lt 0x10000) { $chars += [char][int]$code; continue }
        $low = ($code - 0x10000) % 1024
        $chars += [char][int](0xD800 + ($code - 0x10000 - $low) / 1024)
        $chars += [char][int](0xDC00 + $low)
    }
    return ($chars -join '')
}
