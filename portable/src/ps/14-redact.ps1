# ---------------------------------------------------------------------------
# 14-redact: secret redaction, implementing the rules documented in
# spec/redaction.toml: names, values, configuration lines, multi-line text,
# command lines, environment/registry values, probe data (safety net).
# Everything here must work in PowerShell 2.0 and in ConstrainedLanguage mode:
# only string members, -replace/-match and [regex] statics are used.
# ---------------------------------------------------------------------------

$script:ES_REDACT_READY = $false
$script:ES_PK_TEXT = '<redacted: private key>'
# A line, command line or value longer than this is replaced whole instead of scanned (fail
# closed: the longest real command line is 32767 characters, and the regular expressions are
# linear, but a hostile 1 MB value must not hold the scan for long).
$script:ES_MAX_LENGTH = 131072
$script:ES_TOO_LONG = '<redacted: too long>'

function ConvertTo-EsAlternation([object[]]$Words) {
    # Regex alternation of literal words, longest first.
    $list = @(@($Words) | ForEach-Object { [string]$_ } | Where-Object { $_ } | Sort-Object -Property Length -Descending)
    return ((@($list | ForEach-Object { [regex]::Escape($_) })) -join '|')
}

function Initialize-EsNameRules([hashtable]$Rules) {
    $segments = @{}
    foreach ($word in @($Rules['name_segments'])) { $segments[[string]$word] = $true }
    $script:ES_REDACT_SEGMENTS = $segments
    $exact = @{}
    foreach ($word in @($Rules['exact_exceptions'])) { $exact[[string]$word] = $true }
    $script:ES_REDACT_EXACT = $exact
    $script:ES_SUFFIX_EXCEPT_RE = '(?:' + (ConvertTo-EsAlternation $Rules['suffix_exceptions']) + ')$'
    $script:ES_CONTAINS_RE = ConvertTo-EsAlternation $Rules['name_contains']
    $script:ES_NAME_SUFFIX_RE = '(?:' + (ConvertTo-EsAlternation $Rules['name_suffixes']) + ')$'
}

function Initialize-EsValueRules([hashtable]$Rules) {
    $min = [int]$Rules['token_min_length']
    $script:ES_TOKEN_MIN = $min
    $alternatives = foreach ($prefix in @($Rules['token_prefixes'])) {
        $rest = $min - ([string]$prefix).Length
        if ($rest -lt 4) { $rest = 4 }
        [regex]::Escape([string]$prefix) + '[A-Za-z0-9_\-.+/=]{' + $rest + ',}'
    }
    $script:ES_TOKEN_RE = '(?<![A-Za-z0-9_\-])(?:' + (@($alternatives) -join '|') + ')'
    $script:ES_URL_PASS_RE = '(?i)\b([a-z][a-z0-9+.\-]*://[^/?#\s:]*):[^/?#\s]*@'
    $script:ES_URL_USER_RE = '(?i)\b([a-z][a-z0-9+.\-]*://)[^/?#\s:@]{' + $min + ',}@'
    $script:ES_CONDA_RE = '(?i)(://\S*?/t/)[^/\s]{8,}(?=/)'
    # user:password@host without a scheme, anywhere in a value. In a token (no whitespace or
    # quotes) the user runs from its start to the first ":" (no /; "@" allowed for UPN logins),
    # the password (no / or \) to an "@" that is followed by a host name or [IPv6], an optional
    # :port and the end of the token or one of / , ; ) ] } > < | & # ? \ (so user@host:path
    # and image:tag@sha256:<hex> stay).
    # Fail closed where the bounds of the rule below (user 128, password 256) keep it from matching:
    # a token (no whitespace or quote; tested once from its start, so linear) with a first ':'
    # followed by a password of 257+ characters (no / or \) and an '@', or by a user part of 129+
    # characters before the ':' and an '@', is replaced whole. The placeholder holds no ':'.
    $script:ES_LONG_USERINFO_RE = '(?<![^\s"''])(?:(?>[^\s"'':]*):[^\s"''/\\]{257,}@|(?>[^\s"'':]{129,}):[^\s"''/\\]+@)[^\s"'']*'
    $script:ES_BARE_USERINFO_RE = '(?<![^\s"'';,=(|])((?>[^\s"''/:=;,(|]{1,128})):([^\s"''/\\]{1,256}?)@([A-Za-z0-9._-]+|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})?(?=\z|[\s"''/,;)\]}><|&#?\\.!])'
    $script:ES_BEARER_RE = '(?i)\b(bearer|basic)\s+[A-Za-z0-9\-._~+/]{8,}=*'
    # Quotes around the separator may be escaped (\" in JSON inside a string); the credentials
    # stop at whitespace, a quote, , ; or a backslash followed by a quote.
    $script:ES_AUTH_HEADER_RE = '(?i)(?<![A-Za-z0-9_.\-])([A-Za-z0-9_.\-]*authorization(?:\\?["''])?\s*[:=]\s*(?:\\?["''])?)([A-Za-z]+\s+)?((?:[^\s"'',;\\]|\\(?!["'']))+)'
    # Quoted value: "..." with backslash escapes, '...' with doubled quotes; an unterminated
    # quote runs to the end.
    # The shell idiom 'a'\''b (a quote written as \' between two single-quoted strings) is one value.
    $single = '''(?:[^'']|'''')*(?:''|\z)'
    $script:ES_QUOTED_RE = '"(?:[^"\\]|\\[\s\S])*(?:"|\z)|' + $single + '(?:\\''' + $single + ')*'
    $script:ES_QUOTED_START_RE = '\G(?:' + $script:ES_QUOTED_RE + ')'
    $script:ES_QUOTED_START_RX = [regex]$script:ES_QUOTED_START_RE
    # Content of an escaped-quoted string (\"...\"), after its opening \" with quote character
    # group %N%: any run of two or more backslashes (a quote after it is content: \\\" in a string
    # in a string), a single backslash that is not followed by the quote, anything else. The
    # delimiter is a quote after exactly one backslash. Atomic, so the scan is linear.
    $script:ES_ESC_BODY = '(?>(?:[^\\]+|\\{2,}|\\(?!\%N%))*)'
    # Unquoted run: up to whitespace; a run of , ; & # } ] ) " ' < > | belongs to the value only
    # when a value character follows that does not start another key. The placeholder counts
    # as one value character, so a second pass gives the same text (redaction runs more than
    # once) and a value that only starts with the placeholder is still redacted.
    $run = '(?:' + [regex]::Escape($script:ES_PLACEHOLDER) + '|[^\s,;&#}\])"''<>|]|[,;&#}\])"''<>|]+(?=[^\s,;&#}\])"''<>|])(?![A-Za-z0-9_.\-]+["'']?\s*[:=]))+'
    # Pair keys: an escaped-quoted value (\"...\" inside a string) keeps its delimiters; any
    # other value is a quoted string or an unquoted run.
    $pairKey = '(?i)(?<![A-Za-z0-9_.\-])((?:' + (ConvertTo-EsAlternation $Rules['pair_keys']) + ')\s*=\s*)'
    $script:ES_PAIR_KEYS_ESC_RE = $pairKey + '(\\(["'']))' + $script:ES_ESC_BODY.Replace('%N%', '3') + '(\\\3|\z)'
    $script:ES_PAIR_KEYS_RE = $pairKey + '(?!\\["''])(?:' + $script:ES_QUOTED_RE + '|' + $run + ')'
    $words = @($Rules['name_segments']) + @($Rules['name_contains']) + @($Rules['name_suffixes']) + @($Rules['pair_keys'])
    # A key (a run of [A-Za-z0-9_.-], tested once from its start) that holds a secret word and is
    # followed by : or = (a quote and spaces may come between). Atomic, so the scan is linear.
    $hint = '(?<![A-Za-z0-9_.\-])(?=[A-Za-z0-9_.\-]*?(?:' + (ConvertTo-EsAlternation $words) + '))(?>[A-Za-z0-9_.\-]+)(?:\\?["''])?\s*[:=]'
    $script:ES_KEY_HINT_RE = '(?i)' + $hint
    $script:ES_PAIR_RE = '(?<![A-Za-z0-9_.\-])([A-Za-z0-9_.\-]+)((?:\\?["''])?\s*[:=]\s*)'
    $script:ES_PAIR_RX = [regex]$script:ES_PAIR_RE
    $script:ES_PAIR_VALUE_RE = '\G' + $run
    $script:ES_PAIR_VALUE_RX = [regex]$script:ES_PAIR_VALUE_RE
    $script:ES_NAME_CACHE = @{}
    # True for any string that one of the value rules could change (cheap pre-test).
    $script:ES_REDACT_ANY_RE = '(?i:://|\bbearer\s|\bbasic\s|authorization|' + $hint + ')|' +
        [regex]::Escape($script:ES_PK_MARKER) + '|' + $script:ES_TOKEN_RE + '|' + $script:ES_BARE_USERINFO_RE + '|' + $script:ES_LONG_USERINFO_RE
}

function Initialize-EsLineRules([hashtable]$Rules) {
    $script:ES_LINE_KEY_RE = '^(\s*(?:-\s+)?(?:export\s+|set\s+)?["'']?)([A-Za-z0-9_.\-:/@$]+)(["'']?\s*[:=]\s*)(\S.*)$'
    # A block value opens on the key line: { [ or a YAML block scalar (| |- > >- |2 ...).
    $script:ES_BLOCK_KEY_RE = '^(\s*)(?:-\s+)?["'']?([A-Za-z0-9_.\-:/@$]+)["'']?\s*[:=]\s*(?:[\[{]|[|>][-+0-9]*)?\s*$'
    # A TOML multi-line string (""" or ''') opened after a key and not closed on that line.
    $script:ES_TRIPLE_KEY_RE = '^\s*["'']?([A-Za-z0-9_.\-:/@$]+)["'']?\s*[:=]\s*("""|'''''')(?!.*\2)'
    # A secret key and a quoted value separated by whitespace only (Groovy, yarn classic):
    # password "x", "//reg/:_authToken" "x". An unquoted value after whitespace is left alone.
    $script:ES_SPACE_PAIR_RE = '(?<![^\s{(;,])(["'']?)([A-Za-z0-9_.\-:/@$]+)\1[ \t]+("(?:[^"\\]|\\.)*"|''[^'']*'')'
    $script:ES_SPACE_PAIR_RX = [regex]$script:ES_SPACE_PAIR_RE
    # The xml rules: Initialize-EsXmlRules (14-redact-xml.ps1).
    $optionHead = '(?i)((?:^|\s)(?:--?|/)(?=[a-z0-9_.\-]*?(?:' + (ConvertTo-EsAlternation $Rules['option_words']) + '))(?>[a-z0-9_.\-]+))(=|:|\s+)'
    # An escaped-quoted value (\"...\" inside a string) runs to the next \" and keeps its delimiters.
    $script:ES_CLI_OPTION_ESC_RE = $optionHead + '(\\(["'']))' + $script:ES_ESC_BODY.Replace('%N%', '4') + '(\\\4|\z)'
    $script:ES_CLI_OPTION_RE = $optionHead + '(?!\\["''])(' + $script:ES_QUOTED_RE + '|\S+)'
    # -u / --user / --proxy-user user:secret. The whole value may be quoted ("bob:pa ss": the
    # content runs to the closing quote), or only the secret ('pass', "pa ss", 'a'\''b').
    $userHead = '(?i)((?:^|\s)(?:-u(?=[^\s=-])|(?:-u|--user|--proxy-user)[\s=]+)'
    $script:ES_CLI_USER_QUOTED_RE = $userHead + '(["''])[^\s:"'']+:)(?:(?!\2)[\s\S])*(\2|\z)'
    $script:ES_CLI_USER_RE = $userHead + '[^\s:"'']+):(?:' + $script:ES_QUOTED_RE + '|[^\s"'']+)'
    $script:ES_CLI_HEADER_RE = '(?i)((?:^|\s)(?:-H|--header)[\s=]+["'']?[A-Za-z0-9\-]*(?:' + (ConvertTo-EsAlternation $Rules['header_words']) + ')[A-Za-z0-9\-]*\s*:\s*)[^"''\r\n]+'
}

function Initialize-EsToolRules([hashtable]$Rules) {
    # tool_options "tool:option" -> tool -> options. A line must name the tool as a program.
    $tools = @{}
    foreach ($entry in @($Rules['tool_options'])) {
        $text = [string]$entry
        $colon = $text.IndexOf(':')
        if ($colon -lt 1) { continue }
        $tool = $text.Substring(0, $colon).ToLowerInvariant()
        if (-not $tools.ContainsKey($tool)) { $tools[$tool] = @() }
        $tools[$tool] += $text.Substring($colon + 1)
    }
    $script:ES_TOOL_OPTIONS = $tools
    # Tool option value: an escaped-quoted string (\"two words\"), a quoted string or a word.
    $script:ES_TOOL_VALUE = '(\\(["''])' + $script:ES_ESC_BODY.Replace('%N%', '3') + '(?:\\\3|\z)|' + $script:ES_QUOTED_RE + '|\S+)'
    $script:ES_TOOL_EXT = '(?:\.(?:exe|cmd|bat|com))?(?=["'']|\s|$)'
    $script:ES_TOOL_ANY_RE = '(?i)(?:^|[\s"''/\\;&|(=])(?:' + (ConvertTo-EsAlternation @($tools.PSBase.Keys)) + ')' + $script:ES_TOOL_EXT
}

function Initialize-EsRedaction {
    $r = $script:ES_REDACT
    $script:ES_PLACEHOLDER = [string]$r['placeholder']
    $script:ES_PK_MARKER = [string]$r['private_key_marker']
    Initialize-EsNameRules $r
    Initialize-EsValueRules $r
    Initialize-EsLineRules $r
    Initialize-EsXmlRules $r
    Initialize-EsToolRules $r
    $script:ES_REDACT_READY = $true
}

# ------------------------------------------------------------------ names

function Test-EsSecretName([string]$Name) {
    if (-not $Name) { return $false }
    if ($script:ES_REDACT_EXACT.ContainsKey($Name.ToUpperInvariant())) { return $false }
    # camelCase boundaries become separators: sessionKey -> session_Key, HTTPProxy -> HTTP_Proxy.
    $split = ($Name -creplace '([a-z0-9])([A-Z])', '$1_$2') -creplace '([A-Z]+)([A-Z][a-z])', '$1_$2'
    $segments = @()
    foreach ($segment in ($split.ToUpperInvariant() -split '[^A-Z0-9]+')) { if ($segment) { $segments += $segment } }
    if ($segments.Count -eq 0) { return $false }
    if (($segments -join '_') -match $script:ES_SUFFIX_EXCEPT_RE) { return $false }
    foreach ($segment in $segments) { if ($script:ES_REDACT_SEGMENTS.ContainsKey($segment)) { return $true } }
    $joined = $segments -join ''
    return ($joined -match $script:ES_CONTAINS_RE -or $joined -match $script:ES_NAME_SUFFIX_RE)
}

# ------------------------------------------------------------------ values

function Protect-EsPairs([string]$Text) {
    # key/value rule: the value of every secret key anywhere in the text.
    $found = $script:ES_PAIR_RX.Matches($Text)
    $ph = $script:ES_PLACEHOLDER
    $length = $Text.Length
    $parts = @()
    $pos = 0
    foreach ($m in $found) {
        if ($m.Index -lt $pos) { continue }
        $key = $m.Groups[1].Value
        if ($key.Length -ge 13 -and $key.ToUpperInvariant().EndsWith('AUTHORIZATION')) { continue }
        # The name verdict is cached per key (case kept apart by a "^" before each capital).
        $cacheKey = $key
        if ($key -cmatch '[A-Z]') { $cacheKey = $key -creplace '([A-Z])', '^$1' }
        $secret = $script:ES_NAME_CACHE[$cacheKey]
        if ($null -eq $secret) {
            if ($script:ES_NAME_CACHE.Count -gt 4096) { $script:ES_NAME_CACHE = @{} }
            $secret = [bool](Test-EsSecretName $key)
            $script:ES_NAME_CACHE[$cacheKey] = $secret
        }
        if (-not $secret) { continue }
        if ((Test-EsXmlTagKey $Text $m)) { continue }
        $start = $m.Index + $m.Length
        if ($start -ge $length) { continue }
        $first = [string]$Text[$start]
        $escaped = $(if ($first -eq '\' -and $start + 1 -lt $length) { [string]$Text[$start + 1] } else { '' })
        if ($escaped -eq '"' -or $escaped -eq "'") {
            # Escaped-quoted value (\"...\" inside a string): content up to the next \" (or \'),
            # or to the end; the delimiters stay.
            $close = -1
            $from = $start + 2
            while ($from -lt $length) {
                $at = $Text.IndexOf('\' + $escaped, $from)
                if ($at -lt 0) { break }
                if ($Text[$at - 1] -ne '\') { $close = $at; break }
                $from = $at + 2
            }
            if ($close -lt 0) { $close = $length }
            $parts += $Text.Substring($pos, $start + 2 - $pos) + $ph
            $pos = $close
        } elseif ($first -eq '"' -or $first -eq "'") {
            # Content up to the closing quote (escaped quotes skipped), or to the end.
            $quoted = $script:ES_QUOTED_START_RX.Match($Text, $start).Value
            $close = $start + $quoted.Length - 1
            if ($quoted.Length -lt 2 -or $quoted.Substring($quoted.Length - 1) -ne $first) { $close = $length }
            $parts += $Text.Substring($pos, $start + 1 - $pos) + $ph
            $pos = $close
        } elseif ($first -eq '{' -or $first -eq '[') {
            if (Test-EsBlank $Text.Substring($start + 1)) { continue }
            $parts += $Text.Substring($pos, $start - $pos) + $ph
            $pos = $length
            break
        } else {
            $run = $script:ES_PAIR_VALUE_RX.Match($Text, $start)
            if (-not $run.Success) { continue }
            $parts += $Text.Substring($pos, $start - $pos) + $ph
            $pos = $start + $run.Length
        }
    }
    if ($parts.Count -eq 0) { return $Text }
    if ($pos -lt $length) { $parts += $Text.Substring($pos) }
    return ($parts -join '')
}

function Protect-EsValue($Value) {
    if ($null -eq $Value -or -not $script:ES_OPT.redact) { return $Value }
    $v = [string]$Value
    if ($v.Length -eq 0 -or $v -cnotmatch $script:ES_REDACT_ANY_RE) { return $v }
    if ($v.Contains($script:ES_PK_MARKER)) { return $script:ES_PK_TEXT }
    if ($v.Length -gt $script:ES_MAX_LENGTH) { return $script:ES_TOO_LONG }
    $ph = $script:ES_PLACEHOLDER
    if ($v.Contains('://')) {
        $v = $v -replace $script:ES_URL_PASS_RE, ('$1:' + $ph + '@')
        $v = $v -replace $script:ES_URL_USER_RE, ('$1' + $ph + '@')
        if ($v.Contains('/t/')) { $v = $v -replace $script:ES_CONDA_RE, ('$1' + $ph) }
    }
    if ($v.IndexOf('@') -gt 0) {
        $v = $v -replace $script:ES_BARE_USERINFO_RE, ('$1:' + $ph + '@$3$4')
        $v = $v -replace $script:ES_LONG_USERINFO_RE, $ph
    }
    if ($v.Length -ge $script:ES_TOKEN_MIN) { $v = $v -creplace $script:ES_TOKEN_RE, $ph }
    $lower = $v.ToLowerInvariant()
    if ($lower.Contains('bearer') -or $lower.Contains('basic')) { $v = $v -replace $script:ES_BEARER_RE, ('$1 ' + $ph) }
    if ($lower.Contains('authorization')) { $v = $v -replace $script:ES_AUTH_HEADER_RE, ('$1$2' + $ph) }
    if ($v -match $script:ES_KEY_HINT_RE) {
        $v = $v -replace $script:ES_PAIR_KEYS_ESC_RE, ('$1$2' + $ph + '$4')
        $v = $v -replace $script:ES_PAIR_KEYS_RE, ('$1' + $ph)
        $v = Protect-EsPairs $v
    }
    return $v
}

# ------------------------------------------------------------------ lines and text

function Protect-EsLine($Line, $Pending = $null) {
    # LINE RULES, then the value rules. $Pending (text mode): the line starts inside a secret
    # start tag whose ">" was not on an earlier line (Find-EsXmlElements).
    if ($null -eq $Line -or -not $script:ES_OPT.redact) { return $Line }
    $l = [string]$Line
    if ($l.Length -gt $script:ES_MAX_LENGTH) { return $script:ES_TOO_LONG }
    if ($l.IndexOfAny([char[]]'"''') -ge 0) { $l = Protect-EsSpacePairs $l }
    if ($null -eq $Pending -and $l.IndexOfAny([char[]]'=:<') -lt 0) { return (Protect-EsValue $l) }
    $ph = $script:ES_PLACEHOLDER
    # user:password@host first: the key rule would take user:password@host as the key.
    if ($l.IndexOf('@') -gt 0) {
        $l = $l -replace $script:ES_BARE_USERINFO_RE, ('$1:' + $ph + '@$3$4')
        $l = $l -replace $script:ES_LONG_USERINFO_RE, $ph
    }
    if ($l -match $script:ES_LINE_KEY_RE -and $matches[4] -notmatch '^[\[{]\s*$' -and (Test-EsSecretName $matches[2])) {
        $l = $matches[1] + $matches[2] + $matches[3] + $ph
    }
    if ($null -ne $Pending -or $l.IndexOf('<') -ge 0) { $l = Protect-EsXmlLine $l $Pending }
    return (Protect-EsValue $l)
}

function Protect-EsSpacePairs([string]$Line) {
    # ES_SPACE_PAIR_RE: the quoted value of a secret key that only whitespace separates from it.
    $parts = @()
    $pos = 0
    foreach ($m in $script:ES_SPACE_PAIR_RX.Matches($Line)) {
        if (-not (Test-EsSecretName $m.Groups[2].Value)) { continue }
        $value = $m.Groups[3]
        $quote = $value.Value.Substring(0, 1)
        $parts += $Line.Substring($pos, $value.Index - $pos) + $quote + $script:ES_PLACEHOLDER + $quote
        $pos = $value.Index + $value.Length
    }
    if ($parts.Count -eq 0) { return $Line }
    return (($parts -join '') + $Line.Substring($pos))
}

function Protect-EsText($Text) {
    # Whole files and raw output: line rules plus multi-line values opened by a secret key
    # (Start-EsTextBlock): an indented block, a triple-quoted string, an XML element, a start tag
    # over several lines.
    if ($null -eq $Text -or -not $script:ES_OPT.redact) { return $Text }
    $t = [string]$Text
    if ($t.Contains($script:ES_PK_MARKER)) { return $script:ES_PK_TEXT }
    $state = @{ block = -1; until = $null; xml = $null; pending = $null }
    $out = foreach ($line in ($t -split "`r?`n")) { Protect-EsTextLine $line $state }
    return ((@($out)) -join "`n")
}

function Protect-EsTextLine([string]$Line, [hashtable]$State) {
    # One line of Protect-EsText; $State carries an open value from line to line.
    if ($State.until) { return (Protect-EsUntilLine $Line $State) }
    if ($State.xml) { return (Protect-EsXmlUntilLine $Line $State) }
    if ($State.pending) { return (Protect-EsXmlPendingLine $Line $State) }
    if ($State.block -ge 0) {
        $indent = $script:ES_INDENT_RX.Match($Line).Length
        if ($indent -eq $Line.Length -or $Line -match '^\s*[}\]]+[,;]?\s*$') { return $Line }
        if ($indent -gt $State.block -or ($indent -eq $State.block -and $Line.Substring($indent).StartsWith('- '))) {
            return ($Line.Substring(0, $indent) + $script:ES_PLACEHOLDER)
        }
        $State.block = -1
    }
    $result = Protect-EsLine $Line
    Start-EsTextBlock $Line $State
    return $result
}

function Start-EsTextBlock([string]$Line, [hashtable]$State) {
    # A value that goes on over the next lines: an indented block ({ [ or a YAML | >) or a
    # triple-quoted string after a secret key, or a secret XML element left open or a secret
    # start tag without ">" (Set-EsXmlTextState).
    if ($Line.IndexOfAny([char[]]':=') -ge 0) {
        if ($Line -match $script:ES_BLOCK_KEY_RE -and (Test-EsSecretName $matches[2])) { $State.block = $matches[1].Length; return }
        if ($Line -match $script:ES_TRIPLE_KEY_RE -and (Test-EsSecretName $matches[1])) { $State.until = $matches[2]; return }
    }
    if ($Line.IndexOf('<') -ge 0) { Set-EsXmlTextState $Line $State }
}

function Protect-EsUntilLine([string]$Line, [hashtable]$State) {
    # A line inside a triple-quoted string: replaced up to the closing delimiter, which ends the
    # value and stays (with what follows it).
    $indent = Get-EsIndentLength $Line
    $at = $Line.IndexOf($State.until)
    if ($at -lt 0) {
        if (Test-EsBlank $Line) { return $Line }
        return ($Line.Substring(0, $indent) + $script:ES_PLACEHOLDER)
    }
    $State.until = $null
    $before = $Line.Substring(0, $at)
    if (-not (Test-EsBlank $before)) { $before = $Line.Substring(0, $indent) + $script:ES_PLACEHOLDER }
    return ($before + $Line.Substring($at))
}

# ------------------------------------------------------------------ command lines, named values

function Protect-EsToolOptions([string]$Text) {
    # tool_options: the password options of a known tool named in the line (mysql -pX,
    # sqlcmd -P X). "-" options are case-sensitive (mysql -p is the password, -P the port);
    # Windows "/" options are not.
    if ($Text -notmatch $script:ES_TOOL_ANY_RE) { return $Text }
    $ph = $script:ES_PLACEHOLDER
    $t = $Text
    foreach ($tool in @($script:ES_TOOL_OPTIONS.PSBase.Keys)) {
        if ($t -notmatch ('(?i)(?:^|[\s"''/\\;&|(=])' + [regex]::Escape($tool) + $script:ES_TOOL_EXT)) { continue }
        foreach ($option in @($script:ES_TOOL_OPTIONS[$tool])) {
            $o = [regex]::Escape([string]$option)
            $case = $(if (([string]$option).StartsWith('/')) { '(?i)' } else { '' })
            $t = $t -creplace ($case + '(\s' + $o + ')(?=\S)' + $script:ES_TOOL_VALUE), ('$1' + $ph)
            $t = $t -creplace ($case + '(\s' + $o + '\s+)' + $script:ES_TOOL_VALUE), ('$1' + $ph)
        }
    }
    return $t
}

function Protect-EsCommandLine([string]$Text) {
    # Command lines: options, tool options, user:secret options and headers, then the value rules.
    if (-not $Text -or -not $script:ES_OPT.redact) { return $Text }
    if ($Text.Length -gt $script:ES_MAX_LENGTH) { return $script:ES_TOO_LONG }
    $ph = $script:ES_PLACEHOLDER
    # Tool options first: an attached value (7z -pSecretPw) would read as an option name.
    $t = Protect-EsToolOptions $Text
    $t = $t -replace $script:ES_CLI_OPTION_ESC_RE, ('$1$2$3' + $ph + '$5')
    $t = $t -replace $script:ES_CLI_OPTION_RE, ('$1$2' + $ph)
    if ($t.IndexOf(':') -ge 0) {
        $t = $t -replace $script:ES_CLI_USER_QUOTED_RE, ('$1' + $ph + '$3')
        $t = $t -replace $script:ES_CLI_USER_RE, ('$1:' + $ph)
        $t = $t -replace $script:ES_CLI_HEADER_RE, ('$1' + $ph)
    }
    return (Protect-EsValue $t)
}

function Protect-EsNamedValue([string]$Name, $Value) {
    # Environment and registry values: secret names lose their value; strings get the
    # command-line and value rules; other types (numbers, booleans) pass unchanged.
    if ($null -eq $Value -or -not $script:ES_OPT.redact) { return $Value }
    if (Test-EsSecretName $Name) { return $script:ES_PLACEHOLDER }
    if ($Value -is [string]) { return (Protect-EsCommandLine $Value) }
    if ($Value -is [array]) {
        $items = @(foreach ($item in $Value) { if ($item -is [string]) { Protect-EsCommandLine $item } else { , $item } })
        return , $items
    }
    return $Value
}

function Protect-EsTable([hashtable]$Table) {
    # Copy of a name -> value table; values whose (leaf) name looks secret are replaced.
    $out = @{}
    if ($null -eq $Table) { return $out }
    foreach ($name in @($Table.PSBase.Keys)) {
        $leaf = [string]$name
        $slash = $leaf.LastIndexOf('\')
        if ($slash -ge 0) { $leaf = $leaf.Substring($slash + 1) }
        $out[$name] = Protect-EsNamedValue $leaf $Table[$name]
    }
    return $out
}

# ------------------------------------------------------------------ probe data (safety net)

function Protect-EsData($Value, [int]$Depth = 0) {
    # Value rules applied to every string in probe data. One regex test per string decides
    # whether the (slower) rule function needs to run at all.
    if ($null -eq $Value -or -not $script:ES_OPT.redact) { return $Value }
    if ($Depth -gt 30) { return $script:ES_PLACEHOLDER }
    $re = $script:ES_REDACT_ANY_RE
    if ($Value -is [string]) {
        if ($Value -cmatch $re) { return (Protect-EsValue $Value) }
        return $Value
    }
    if ($Value -is [hashtable]) {
        # .PSBase.Keys: .Keys would return the value of an entry named "Keys".
        $copy = @{}
        foreach ($key in @($Value.PSBase.Keys)) {
            $item = $Value[$key]
            if ($item -is [string]) { if ($item -cmatch $re) { $item = Protect-EsValue $item } }
            elseif ($item -is [hashtable] -or $item -is [array]) { $item = Protect-EsData $item ($Depth + 1) }
            $copy[$key] = $item
        }
        return $copy
    }
    if ($Value -is [array]) {
        $items = @(foreach ($item in $Value) {
                if ($item -is [string]) { if ($item -cmatch $re) { Protect-EsValue $item } else { $item } }
                elseif ($item -is [hashtable] -or $item -is [array]) { , (Protect-EsData $item ($Depth + 1)) }
                else { , $item }
            })
        return , $items
    }
    return $Value
}
