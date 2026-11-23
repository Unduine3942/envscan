# ---------------------------------------------------------------------------
# 40-render: envscan.md (full report, one section per probe).
# AGENT_BRIEF.md lives in 41-brief.ps1.
# ---------------------------------------------------------------------------

$script:ES_MD_MAX_ITEMS = 300
$script:ES_MD_MAX_INLINE = 30
# Strings that render as-is (no markdown-active characters, one line, short). \A and \z:
# $ would also match before a final newline.
$script:ES_MD_PLAIN_RE = '\A[^<>*_|`\[\]#\\\r\n]{0,300}\z'

function Format-EsMdText([string]$Text) {
    # One line; strings with markdown-active characters become code spans.
    $t = ([string]$Text) -replace '[\r\n]+', ' '
    if ($t.Length -gt 300) { $t = $t.Substring(0, 300) + '...' }
    if ($t -match '[<>*_|`\[\]#\\]') {
        if ($t.Contains('`')) { return ('`` ' + $t + ' ``') }
        return ('`' + $t + '`')
    }
    return $t
}

function Format-EsMdScalar($Value) {
    if ($Value -is [string] -and $Value -cmatch $script:ES_MD_PLAIN_RE) { return $Value }
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [datetime]) { return (Format-EsUtc $Value.ToUniversalTime()) }
    return (Format-EsMdText ([string]$Value))
}

function Test-EsFlatTable($Value) {
    if (-not ($Value -is [hashtable])) { return $false }
    foreach ($key in @($Value.PSBase.Keys)) {
        $item = $Value[$key]
        if ($item -is [hashtable]) { return $false }
        if ($item -is [array]) { foreach ($inner in $item) { if (-not (Test-EsJsonScalar $inner)) { return $false } } }
    }
    return $true
}

function Format-EsMdInline([hashtable]$Table) {
    $parts = foreach ($key in @(Get-EsOrderedKeys $Table)) {
        $value = $Table[$key]
        if ($value -is [string] -and $value -cmatch $script:ES_MD_PLAIN_RE) { $key + ': ' + $value; continue }
        if ($null -eq $value -or ($value -is [array] -and @($value).Count -eq 0)) { continue }
        if ($value -is [array]) { $key + ': ' + ((@($value | Select-Object -First $script:ES_MD_MAX_INLINE | ForEach-Object { Format-EsMdScalar $_ })) -join ', ') }
        else { $key + ': ' + (Format-EsMdScalar $value) }
    }
    return (@($parts) -join '; ')
}

function Format-EsMdData($Value, [string]$Indent) {
    # Writes markdown list lines for probe data to the pipeline.
    if ($Value -is [hashtable]) {
        foreach ($key in @(Get-EsOrderedKeys $Value)) {
            $item = $Value[$key]
            if (Test-EsJsonScalar $item) { $Indent + '- ' + $key + ': ' + (Format-EsMdScalar $item); continue }
            if ($item -is [array] -and @($item).Count -eq 0) { $Indent + '- ' + $key + ': (none)'; continue }
            if ($item -is [hashtable] -and $item.PSBase.Count -eq 0) { $Indent + '- ' + $key + ': (none)'; continue }
            $allScalar = $item -is [array]
            if ($allScalar) { foreach ($inner in $item) { if (-not (Test-EsJsonScalar $inner)) { $allScalar = $false; break } } }
            if ($allScalar) {
                $list = @($item)
                $text = (@($list | Select-Object -First $script:ES_MD_MAX_INLINE | ForEach-Object { Format-EsMdScalar $_ }) -join ', ')
                if ($list.Count -gt $script:ES_MD_MAX_INLINE) { $text += (' (+' + ($list.Count - $script:ES_MD_MAX_INLINE) + ' more)') }
                $Indent + '- ' + $key + ': ' + $text
                continue
            }
            $Indent + '- ' + $key + ':'
            Format-EsMdData $item ($Indent + '  ')
        }
        return
    }
    if ($Value -is [array]) {
        $list = @($Value)
        foreach ($item in @($list | Select-Object -First $script:ES_MD_MAX_ITEMS)) {
            if (Test-EsJsonScalar $item) { $Indent + '- ' + (Format-EsMdScalar $item) }
            elseif (Test-EsFlatTable $item) { $Indent + '- ' + (Format-EsMdInline $item) }
            else { $Indent + '-'; Format-EsMdData $item ($Indent + '  ') }
        }
        if ($list.Count -gt $script:ES_MD_MAX_ITEMS) { $Indent + '- ... ' + ($list.Count - $script:ES_MD_MAX_ITEMS) + ' more (see envscan.json)' }
        return
    }
    $Indent + '- ' + (Format-EsMdScalar $Value)
}

function Format-EsMdFence([string]$Label, [string]$Text) {
    $fence = '```'
    if ($Text.Contains('```')) { $fence = '~~~~' }
    '**' + $Label + '**'
    ''
    $fence + 'text'
    ($Text -replace "`r", '')
    $fence
    ''
}

function Format-EsMdProbe([string]$Id, [hashtable]$Envelope) {
    '## ' + $Id + ' - ' + $Envelope.title
    ''
    'status **' + $Envelope.status + '** - tier ' + $Envelope.tier + ' - scope ' + $Envelope.scope + ' - ' + $Envelope.duration_ms + ' ms'
    ''
    if ($Envelope.error) { '> error: ' + (Format-EsMdText $Envelope.error); '' }
    foreach ($note in @($Envelope.notes)) { if ($note) { '> note: ' + (Format-EsMdText $note) } }
    if (@($Envelope.notes).Count -gt 0) { '' }
    if (@($Envelope.sources).Count -gt 0) { 'Sources: ' + ((@($Envelope.sources | ForEach-Object { Format-EsMdText $_ })) -join ', '); '' }
    if ($Envelope.data -is [hashtable] -and $Envelope.data.Count -gt 0) { Format-EsMdData $Envelope.data ''; '' }
    if ($Envelope.raw) {
        foreach ($label in @($Envelope.raw.PSBase.Keys | Sort-Object)) { Format-EsMdFence ('raw: ' + $label) ([string]$Envelope.raw[$label]) }
    }
    if ($Envelope.truncated) { '_raw output truncated_'; '' }
}

function ConvertTo-EsMarkdownReport([hashtable]$Report) {
    $run = $Report.run
    $hostBlock = $Report.host
    $lines = @(
        '# envscan report: ' + $hostBlock.hostname
        ''
        '- OS: ' + $hostBlock.os_name + ' ' + $hostBlock.os_version + ' (' + $hostBlock.arch + ')'
        '- Scanner: ' + $Report.scanner.name + ' ' + $Report.scanner.version + ' (' + $Report.scanner.impl + ', ' + $Report.scanner.shell_version + ')'
        '- Started: ' + $run.started_utc + ', duration ' + $run.duration_ms + ' ms, tiers: ' + (@($run.tiers) -join ', ') + ', exit code ' + $run.exit_code
        '- Redaction: ' + $(if ($run.redaction) { 'on' } else { 'OFF (--no-redact)' })
        '- Probe status counts: ' + (@($script:ES_STATUSES | Where-Object { $run.counts[$_] -gt 0 } | ForEach-Object { $_ + ' ' + $run.counts[$_] }) -join ', ')
        ''
        '## Findings'
        ''
    )
    if (@($Report.findings).Count -eq 0) { $lines += 'No findings.' }
    foreach ($finding in @($Report.findings)) {
        $lines += ('- **' + $finding.severity.ToUpperInvariant() + '** ' + $finding.title + ' (' + $finding.id + '): ' + (Format-EsMdText $finding.detail))
        $lines += ('  - Recommendation: ' + $finding.recommendation)
        $lines += ('  - Evidence: ' + (@($finding.evidence) -join ', '))
    }
    $lines += ''
    $body = foreach ($id in @($Report.probes.__order)) {
        if ($Report.probes.ContainsKey($id)) { Format-EsMdProbe $id $Report.probes[$id] }
    }
    return ((@($lines) + @($body)) -join "`n")
}
