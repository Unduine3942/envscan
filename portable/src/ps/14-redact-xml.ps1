# ---------------------------------------------------------------------------
# 14-redact-xml: the xml LINE RULE and the xml part of the TEXT RULES of spec/redaction.toml
# (secret elements, attributes, key/name + value pairs, elements over several lines, start tags
# over several lines). Part of the redaction rules in 14-redact.ps1.
# Case-insensitive matching is ASCII only (explicit [Aa] classes, never (?i) or Unicode
# lower-casing: the Kelvin sign is not "k"), and so are blank tests. Linear time: every cursor
# moves forward, the closing tags of a line are indexed once, and the regexes are atomic.
# Everything here must work in PowerShell 2.0 and in ConstrainedLanguage mode.
# ---------------------------------------------------------------------------

$script:ES_XML_OWN_CLOSE = @{}
# Regex objects, not pattern strings: the static [regex] cache holds only 15 patterns and the
# rules use more, so a pattern string would be parsed again for every line.
$script:ES_BLANK_RX = [regex]'\A[\x09-\x0D\x20]*\z'
$script:ES_INDENT_RX = [regex]'\A[\x09-\x0D\x20]*'
$script:ES_XML_ATTRS_RX = [regex]('\G(?>(?:[^"''>]+|"[^"]*"|''[^'']*'')*)')

function ConvertTo-EsAsciiNoCase([string]$Text) {
    # A regex for $Text that ignores the case of ASCII letters only.
    $parts = foreach ($ch in $Text.ToCharArray()) {
        $c = [string]$ch
        if ($c -cmatch '[A-Za-z]') { '[' + $c.ToUpperInvariant() + $c.ToLowerInvariant() + ']' } else { [regex]::Escape($c) }
    }
    return ($parts -join '')
}

function ConvertTo-EsAsciiAlternation([object[]]$Words) {
    # ConvertTo-EsAlternation with ASCII-only case folding, longest first.
    $list = @(@($Words) | ForEach-Object { [string]$_ } | Where-Object { $_ } | Sort-Object -Property Length -Descending)
    return ((@($list | ForEach-Object { ConvertTo-EsAsciiNoCase $_ })) -join '|')
}

function Initialize-EsXmlRules([hashtable]$Rules) {
    $name = '[A-Za-z_][A-Za-z0-9_.\-]*'
    $elements = ConvertTo-EsAsciiAlternation $Rules['xml_elements']
    $attributes = ConvertTo-EsAsciiAlternation $Rules['xml_attributes']
    # "<", an optional namespace prefix (taken only when an element name follows its ":"; the
    # regex falls back to no prefix), the element not followed by a word character. Group 1 is
    # [prefix:]element.
    $script:ES_XML_HEAD_RE = '<((?:(?>' + $name + '):)?(?:' + $elements + '))(?![A-Za-z0-9_])'
    $script:ES_XML_CLOSE_RE = '</(' + $name + '(?::' + $name + ')?)?'
    # A secret element name right after a namespace prefix (Test-EsXmlTagKey).
    $script:ES_XML_LOCAL_RX = [regex]('\G(?:' + $elements + ')(?![A-Za-z0-9_])')
    $script:ES_XML_ATTRIBUTE_RE = '(\b(?:' + $attributes + ')\s*=\s*")(?>[^"]*)(")'
    $key = ConvertTo-EsAsciiAlternation @('key', 'name')
    $value = ConvertTo-EsAsciiNoCase 'value'
    $script:ES_XML_PAIR_RE = '\b(?:' + $key + ')\s*=\s*"((?>[^"]*))"\s+' + $value + '\s*=\s*"((?>[^"]*))"'
    $script:ES_XML_SECRET_WORD_RE = ConvertTo-EsAsciiAlternation (@($Rules['name_contains']) + @('pwd', 'pass'))
    $script:ES_XML_URLKEY_RE = '(<' + (ConvertTo-EsAsciiNoCase 'add') + '\s+' + (ConvertTo-EsAsciiNoCase 'key') +
        '\s*=\s*"[A-Za-z][A-Za-z0-9+.\-]*://(?>[^"]*)"\s+' + $value + '\s*=\s*")(?>[^"]*)(")'
    $script:ES_XML_HEAD_RX = [regex]$script:ES_XML_HEAD_RE
    $script:ES_XML_CLOSE_RX = [regex]$script:ES_XML_CLOSE_RE
    $script:ES_XML_ATTRIBUTE_RX = [regex]$script:ES_XML_ATTRIBUTE_RE
    $script:ES_XML_PAIR_RX = [regex]$script:ES_XML_PAIR_RE
    $script:ES_XML_URLKEY_RX = [regex]$script:ES_XML_URLKEY_RE
    $script:ES_XML_OWN_CLOSE = @{}
}

function Test-EsBlank([string]$Text) {
    # ASCII blank: nothing but space, tab, vertical tab, form feed, CR, LF.
    return $script:ES_BLANK_RX.IsMatch($Text)
}

function Get-EsIndentLength([string]$Line) {
    return $script:ES_INDENT_RX.Match($Line).Length
}

function Protect-EsXmlLine([string]$Line, $Pending = $null) {
    # The xml LINE RULE: element content, secret attributes, key/name + value pairs, NuGet
    # apikeys. $Pending: the line starts inside a start tag (text mode, Find-EsXmlElements).
    $l = Protect-EsXmlElements $Line $Pending
    $ph = $script:ES_PLACEHOLDER
    $l = $script:ES_XML_ATTRIBUTE_RX.Replace($l, ('$1' + $ph + '$2'))
    $l = Protect-EsXmlPairs $l
    return $script:ES_XML_URLKEY_RX.Replace($l, ('$1' + $ph + '$2'))
}

function Protect-EsXmlPairs([string]$Line) {
    # key="..secret word.." value="..." and name="..." value="...": the value is replaced.
    $parts = @(foreach ($m in $script:ES_XML_PAIR_RX.Matches($Line)) {
            if ($m.Groups[1].Value -cnotmatch $script:ES_XML_SECRET_WORD_RE) { continue }
            , @($m.Groups[2].Index, ($m.Groups[2].Index + $m.Groups[2].Length))
        })
    return (Join-EsXmlSpans $Line $parts)
}

function Join-EsXmlSpans([string]$Line, [object[]]$Spans) {
    # $Line with each @(start, end) range (in order, not overlapping) replaced by the placeholder.
    if ($Spans.Count -eq 0) { return $Line }
    $pos = 0
    $parts = foreach ($span in $Spans) {
        $Line.Substring($pos, $span[0] - $pos) + $script:ES_PLACEHOLDER
        $pos = $span[1]
    }
    return ((@($parts) -join '') + $Line.Substring($pos))
}

function Protect-EsXmlElements([string]$Line, $Pending = $null) {
    # The content of each secret element on the line (Find-EsXmlElements) -> placeholder.
    return (Join-EsXmlSpans $Line @((Find-EsXmlElements $Line $Pending).spans))
}

function Find-EsXmlElements([string]$Line, $Pending = $null) {
    # The secret elements of one line as @{ spans; open; pending }: spans = @(start, end) content
    # ranges to replace; open = @{ tag; at; rest; first } for the element left open (no closing
    # tag after it; first: its start tag is the first non-blank thing on the line); pending =
    # @{ tag; quote } for a start tag whose ">" is not on the line (the quote still open at the
    # end, or ''). Scanning stops at either. $Pending: the line starts inside such a start tag.
    $found = @{ spans = @(); open = $null; pending = $null }
    $heads = $script:ES_XML_HEAD_RX.Matches($Line)
    if ($heads.Count -eq 0 -and $null -eq $Pending) { return $found }
    $items = @($heads)
    if ($null -ne $Pending) { $items = @(@{ pending = $Pending }) + $items }
    $found.spans = @(Get-EsXmlSpans $found $Line $items)
    return $found
}

function Get-EsXmlSpans([hashtable]$Found, [string]$Line, [object[]]$Items) {
    # The loop of Find-EsXmlElements (inline, as it runs once per start tag): the ">" of each
    # start tag (ES_XML_ATTRS_RX: attribute text and closed quotes, atomic; it stops at the ">"
    # or a quote not closed on the line), then the content's end (Initialize-EsXmlIndex chains:
    # the own closing tag, else the next "</"). Writes the spans; sets $Found.open or .pending.
    $pos = 0
    $lead = $script:ES_INDENT_RX.Match($Line).Length
    $index = $null
    foreach ($item in $Items) {
        if ($item -is [hashtable]) {
            $tag = [string]$item.pending.tag; $at = 0; $first = $true
            $end = Find-EsXmlTagEnd $Line 0 ([string]$item.pending.quote)
            $gt = $end.at
            if ($gt -lt 0) { $Found.pending = @{ tag = $tag; quote = $end.quote }; break }
        } else {
            if ($item.Index -lt $pos) { continue }
            $tag = $item.Groups[1].Value.ToLowerInvariant(); $at = $item.Index; $first = ($at -eq $lead)
            $gt = $at + $item.Length
            $gt += $script:ES_XML_ATTRS_RX.Match($Line, $gt).Length
            if ($gt -ge $Line.Length -or [string]$Line[$gt] -ne '>') {
                $Found.pending = @{ tag = $tag; quote = $(if ($gt -lt $Line.Length) { [string]$Line[$gt] } else { '' }) }
                break
            }
            if ([string]$Line[$gt - 1] -eq '/') { $pos = $gt + 1; continue }
        }
        $start = $gt + 1
        if ($null -eq $index) { $index = Initialize-EsXmlIndex $Line }
        $close = -1
        foreach ($key in @(('f|' + $tag), ('p|' + $tag))) {
            $rec = $index.ptr[$key]
            if ($null -eq $rec) { continue }
            while ($rec -ge 0 -and $index.at[$rec % $index.n] -lt $start) { $rec = $index.next[$rec] }
            $index.ptr[$key] = $rec
            if ($rec -ge 0 -and ($close -lt 0 -or $index.at[$rec % $index.n] -lt $close)) { $close = $index.at[$rec % $index.n] }
        }
        if ($close -lt 0) {
            while ($index.any -lt $index.n -and $index.at[$index.any] -lt $start) { $index.any = $index.any + 1 }
            if ($index.any -lt $index.n) { $close = $index.at[$index.any] }
        }
        if ($close -ge 0) { , @($start, $close); $pos = $close; continue }
        $rest = $Line.Substring($start)
        $Found.open = @{ tag = $tag; at = $at; rest = $rest; first = $first }
        if (-not $script:ES_BLANK_RX.IsMatch($rest)) { , @($start, $Line.Length) }
        break
    }
}

function Find-EsXmlTagEnd([string]$Line, [int]$From, [string]$Quote) {
    # The ">" that ends a start tag: the first one at or after $From outside "..." and '...'
    # ($Quote: a quote already open). @{ at; quote }: at = -1 when the line has none, quote =
    # the quote still open at the end of the line ('' when none). One atomic regex scan
    # (ES_XML_ATTRS_RX: text and closed quotes); it stops at the ">" or an unclosed quote.
    $i = $From
    if ($Quote) {
        $c = $Line.IndexOf($Quote, $i)
        if ($c -lt 0) { return @{ at = -1; quote = $Quote } }
        $i = $c + 1
    }
    $end = $i + $script:ES_XML_ATTRS_RX.Match($Line, $i).Length
    if ($end -ge $Line.Length) { return @{ at = -1; quote = '' } }
    $ch = [string]$Line[$end]
    if ($ch -eq '>') { return @{ at = $end; quote = '' } }
    return @{ at = -1; quote = $ch }
}

function Get-EsXmlCommentRanges([string]$Line) {
    # <!-- ... --> ranges of the line as a flat @(start, end, ...); an unterminated comment runs
    # to the end of the line.
    if ($Line.IndexOf('<!--') -lt 0) { return @() }
    $from = 0
    return @(while ($from -lt $Line.Length) {
            $s = $Line.IndexOf('<!--', $from)
            if ($s -lt 0) { break }
            $e = $Line.IndexOf('-->', $s + 4)
            $s
            if ($e -lt 0) { $Line.Length; break }
            $e + 3
            $from = $e + 3
        })
}

function Initialize-EsXmlIndex([string]$Line) {
    # The closing tags of the line outside comments: at (positions), n, any (cursor), and per
    # name a chain (ptr: first record, next: following record with the same key) so that every
    # lookup moves forward only. Keys: 'f|<name>' and, for "</prefix:local", 'p|<prefix>'.
    $line = $Line
    $ranges = Get-EsXmlCommentRanges $line
    $r = 0
    $kept = @(foreach ($c in $script:ES_XML_CLOSE_RX.Matches($line)) {
            while ($r -lt $ranges.Count -and $ranges[$r + 1] -le $c.Index) { $r += 2 }
            if ($r -lt $ranges.Count -and $ranges[$r] -le $c.Index) { continue }
            $c
        })
    $n = $kept.Count
    $next = @(-1) * (2 * $n)
    $ptr = @{}
    $last = @{}
    for ($i = 0; $i -lt $n; $i++) {
        $name = $kept[$i].Groups[1].Value.ToLowerInvariant()
        $keys = @('f|' + $name)
        if ($name.IndexOf(':') -gt 0) { $keys += ('p|' + $name.Substring(0, $name.IndexOf(':'))) }
        foreach ($key in $keys) {
            $rec = $(if ($key.StartsWith('f')) { $i } else { $n + $i })
            if ($last.ContainsKey($key)) { $next[$last[$key]] = $rec } else { $ptr[$key] = $rec }
            $last[$key] = $rec
        }
    }
    return @{ at = @(foreach ($c in $kept) { $c.Index }); n = $n; any = 0; next = $next; ptr = $ptr }
}

function Get-EsXmlOwnClose([string]$Line, [string]$Tag) {
    # Position of the element's own closing tag on a line inside it (text mode): "</$Tag" not
    # followed by a name character ("</password:x" counts for "password"), outside comments;
    # -1 when there is none.
    if ($Line.IndexOf('</') -lt 0) { return -1 }
    $pattern = $script:ES_XML_OWN_CLOSE[$Tag]
    if ($null -eq $pattern) {
        $pattern = [regex]('</' + (ConvertTo-EsAsciiNoCase $Tag) + '(?![A-Za-z0-9_.\-])')
        $script:ES_XML_OWN_CLOSE[$Tag] = $pattern
    }
    $ranges = Get-EsXmlCommentRanges $Line
    $r = 0
    foreach ($m in $pattern.Matches($Line)) {
        while ($r -lt $ranges.Count -and $ranges[$r + 1] -le $m.Index) { $r += 2 }
        if ($r -lt $ranges.Count -and $ranges[$r] -le $m.Index) { continue }
        return $m.Index
    }
    return -1
}

function Test-EsXmlTagKey([string]$Text, $Match) {
    # True when a key/value match of Protect-EsPairs is the namespace prefix of a tag name:
    # "<token:password" or "</ns:clientSecret" (the key, then ":" and an xml_elements name
    # directly, not followed by a word character). "<password:x>" and "<password: x" stay keys.
    # The xml rule handles the element; its local name is not a value.
    if ($Match.Groups[2].Value -cne ':') { return $false }
    $i = $Match.Index
    $lt = ($i -ge 1 -and [string]$Text[$i - 1] -eq '<') -or ($i -ge 2 -and $Text.Substring($i - 2, 2) -eq '</')
    if (-not $lt) { return $false }
    return $script:ES_XML_LOCAL_RX.Match($Text, $i + $Match.Length).Success
}

# ------------------------------------------------------------------ text mode

function Set-EsXmlTextState([string]$Line, [hashtable]$State, $Pending = $null) {
    # After a line in text mode: a secret element left open opens the multi-line state
    # (State.xml = its tag) when the rest of the line is blank or its start tag is the first
    # thing on the line; a start tag without ">" opens the start-tag state (State.pending).
    $found = Find-EsXmlElements $Line $Pending
    if ($null -ne $found.pending) { $State.pending = $found.pending; return }
    $open = $found.open
    if ($null -ne $open -and ($open.first -or (Test-EsBlank $open.rest))) { $State.xml = $open.tag }
}

function Protect-EsXmlPendingLine([string]$Line, [hashtable]$State) {
    # A line after a start tag without ">": the state ends without effect when the line starts
    # with "<"; else the line gets the line rules, and the tag's ">" (when on this line) ends a
    # start tag that begins the line.
    $pending = $State.pending
    $State.pending = $null
    $lead = Get-EsIndentLength $Line
    if ($lead -lt $Line.Length -and [string]$Line[$lead] -eq '<') { return (Protect-EsTextLine $Line $State) }
    # A line that does not end the tag gets the plain line rules; the state goes on.
    $gt = Find-EsXmlTagEnd $Line 0 ([string]$pending.quote)
    if ($gt.at -lt 0) {
        $State.pending = @{ tag = $pending.tag; quote = $gt.quote }
        return (Protect-EsLine $Line)
    }
    $result = Protect-EsLine $Line $pending
    Set-EsXmlTextState $Line $State $pending
    return $result
}

function Protect-EsXmlUntilLine([string]$Line, [hashtable]$State) {
    # A line inside a secret element (State.xml): replaced up to the element's own closing tag
    # (outside comments on the line); what follows goes through the text rules again.
    # Hot path (every line of a long value): regex objects inline, no function calls.
    $at = -1
    if ($Line.IndexOf('</') -ge 0) { $at = Get-EsXmlOwnClose $Line $State.xml }
    $indent = $script:ES_INDENT_RX.Match($Line).Length
    if ($at -lt 0) {
        if ($indent -eq $Line.Length) { return $Line }
        return ($Line.Substring(0, $indent) + $script:ES_PLACEHOLDER)
    }
    $State.xml = $null
    $before = $Line.Substring(0, $at)
    if (-not $script:ES_BLANK_RX.IsMatch($before)) { $before = $Line.Substring(0, $indent) + $script:ES_PLACEHOLDER }
    return ($before + (Protect-EsTextLine $Line.Substring($at) $State))
}
