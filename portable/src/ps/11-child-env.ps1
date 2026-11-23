# ---------------------------------------------------------------------------
# 11-child-env: the environment of every child process (docs/DEVELOPING.md rule 6). A child
# sees only the allowlisted scan-start variables (spec/child_env.toml [child_env_keep], with
# path values vetted), then [child_env], then the per-call extras. This process environment is
# set to that table just around each start and restored right after; setting it fails closed.
# Everything here must work in PowerShell 2.0 and in ConstrainedLanguage mode.
# ---------------------------------------------------------------------------

$script:ES_CHILD_VETTED = $null
$script:ES_CHILD_VETTED_FOR = $null
$script:ES_CHILD_VETTED_KEY = $null

function Test-EsChildPathRefused([string]$Path, [bool]$AsFolder) {
    # A path a child must not be pointed at: UNC or device path, a mapped network drive, or a
    # credential store (a folder above it, or itself; as a file too unless $AsFolder). Text only:
    # the path is never touched.
    $p = $Path.Trim('"').Replace('/', '\')
    if (-not $p) { return $false }
    if ($p.StartsWith('\\') -or (Test-EsNetworkPath $p)) { return $true }
    if ($AsFolder) { return [bool](Get-EsCredentialFolder ($p.TrimEnd('\') + '\_')) }
    return [bool](Get-EsCredentialFolder $p)
}

function Get-EsChildHomeFolder([string]$Name) {
    # The replacement of a refused home_paths value: the private temp folder itself for the temp
    # variables, else an empty folder inside it; '' (the variable is removed) when there is none.
    if (-not $script:ES_TMP) { return '' }
    if (@('TMPDIR', 'TMP', 'TEMP') -contains $Name) { return $script:ES_TMP }
    $folder = $script:ES_TMP + '\childhome'
    try {
        if (-not (Test-Path -LiteralPath $folder -PathType Container)) { $null = New-Item -ItemType Directory -Path $folder -ErrorAction Stop }
    } catch {
        Write-EsLog ('child home folder not created: ' + $_.Exception.Message)
        return ''
    }
    return $folder
}

function Get-EsVettedPathList([string]$Value) {
    # A path_lists value without its refused (and empty) entries; '' when none is left.
    $kept = @(@($Value.Split(';')) | Where-Object { $_ -and -not (Test-EsChildPathRefused $_ $true) })
    return ($kept -join ';')
}

function Get-EsChildEnvVetted([hashtable]$Base) {
    # The allowlisted scan-start variables, path values vetted (spec/child_env.toml): a refused
    # home_paths value is replaced (Get-EsChildHomeFolder), refused path_lists entries are dropped,
    # and any other value that is a refused absolute path is removed.
    $out = @{}
    foreach ($name in @($Base.PSBase.Keys)) {
        $value = [string]$Base[$name]
        if (-not $value -or -not (Test-EsChildEnvKept $name)) { continue }
        if ($script:ES_CHILD_ENV_PATH_LISTS -contains $name) { $value = Get-EsVettedPathList $value }
        elseif ($script:ES_CHILD_ENV_HOME_PATHS -contains $name) {
            if (Test-EsChildPathRefused $value $true) { $value = Get-EsChildHomeFolder $name }
        } elseif ($value -cmatch '\A(?:[\\/]|[A-Za-z]:[\\/])' -and (Test-EsChildPathRefused $value $false)) { $value = '' }
        if ($value) { $out[$name] = $value }
    }
    return $out
}

function Get-EsChildEnvBase {
    # Get-EsChildEnvVetted of the snapshot (the live environment when there is none, as in
    # library use), kept for the scan: the snapshot, the network drives and the temp folder
    # decide it.
    $base = $script:ES_ENV_SNAPSHOT
    if ($null -eq $base -or $base.PSBase.Count -eq 0) { return (Get-EsChildEnvVetted (Get-EsProcessEnv)) }
    $key = [string]$script:ES_TMP + '|' + (@($script:ES_NETWORK_DRIVES) -join ',')
    if ($null -eq $script:ES_CHILD_VETTED -or -not ($script:ES_CHILD_VETTED_FOR -eq $base) -or $script:ES_CHILD_VETTED_KEY -cne $key) {
        $script:ES_CHILD_VETTED = Get-EsChildEnvVetted $base
        $script:ES_CHILD_VETTED_FOR = $base
        $script:ES_CHILD_VETTED_KEY = $key
    }
    return $script:ES_CHILD_VETTED
}

function Get-EsChildEnvTable([hashtable]$Extra) {
    # The whole environment of one child: Get-EsChildEnvBase, then [child_env], then the
    # per-call extras (the scanner's own values, not vetted). An empty value removes the variable.
    $table = @{}
    $base = Get-EsChildEnvBase
    foreach ($name in @($base.PSBase.Keys)) { $table[$name] = $base[$name] }
    foreach ($layer in @($script:ES_CHILD_ENV, $Extra)) {
        if ($null -eq $layer) { continue }
        foreach ($name in @($layer.PSBase.Keys)) {
            $value = [string]$layer[$name]
            if ($value) { $table[$name] = $value } else { $table.Remove($name) }
        }
    }
    return $table
}

function Assert-EsProcessEnv([hashtable]$Table) {
    # Throws unless this process environment is exactly $Table (read back after setting it).
    $now = Get-EsProcessEnv
    foreach ($name in @($now.PSBase.Keys)) {
        if (-not $Table.ContainsKey($name)) { throw ('the child environment could not be set: ' + $name + ' is still set') }
        if ($now[$name] -cne [string]$Table[$name]) { throw ('the child environment could not be set: ' + $name + ' has another value') }
    }
    foreach ($name in @($Table.PSBase.Keys)) {
        if (-not $now.ContainsKey($name)) { throw ('the child environment could not be set: ' + $name + ' is missing') }
    }
}

function Set-EsProcessEnv([hashtable]$Table, [hashtable]$Before = $null) {
    # Makes this process environment exactly $Table (a child copies it when it starts) and
    # returns the previous one ($Before when the caller captured it first, which it then restores
    # with Restore-EsProcessEnv in a finally). Fails closed: when a variable cannot be removed or
    # set, or the environment read back is not $Table, the previous one is restored and the error
    # is thrown, so no child starts with a wrong environment. Item cmdlets only: they work in
    # ConstrainedLanguage and on PowerShell 2.0.
    if ($null -eq $Before) { $Before = Get-EsProcessEnv }
    try {
        foreach ($name in @($Before.PSBase.Keys)) {
            if (-not $Table.ContainsKey($name)) { Remove-Item -LiteralPath ('env:' + $name) -ErrorAction Stop }
        }
        foreach ($name in @($Table.PSBase.Keys)) {
            if ($Before[$name] -cne [string]$Table[$name]) { Set-Item -LiteralPath ('env:' + $name) -Value ([string]$Table[$name]) -ErrorAction Stop }
        }
        Assert-EsProcessEnv $Table
    } catch {
        $null = Restore-EsProcessEnv $Before
        throw
    }
    return $Before
}

function Restore-EsProcessEnv([hashtable]$Saved) {
    # Makes this process environment $Saved again, variable by variable: one that cannot be
    # removed or set does not stop the others. Returns (and logs) the names that failed.
    $failed = @()
    $now = Get-EsProcessEnv
    foreach ($name in @($now.PSBase.Keys)) {
        if ($Saved.ContainsKey($name)) { continue }
        try { Remove-Item -LiteralPath ('env:' + $name) -ErrorAction Stop } catch { $failed += $name }
    }
    foreach ($name in @($Saved.PSBase.Keys)) {
        if ($now.ContainsKey($name) -and $now[$name] -ceq [string]$Saved[$name]) { continue }
        try { Set-Item -LiteralPath ('env:' + $name) -Value ([string]$Saved[$name]) -ErrorAction Stop } catch { $failed += $name }
    }
    if ($failed.Count -gt 0) { Write-EsLog ('environment not restored: ' + ($failed -join ', ')) }
    return $failed
}
