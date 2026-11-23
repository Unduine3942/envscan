# ---------------------------------------------------------------------------
# 15-proxy: proxy settings in configuration lines, found by the NAME of the setting and never
# by "proxy" in a value (a registry URL ".../repository/npm-proxy/" is not a proxy).
# A port of src/sh/awk/proxy.awk: keep the two in step (tests/proxy_cases.py runs the same
# cases through both). Forms: key=value, key: value, key "value" (yarn, apt), export, set and
# setenv, quoted JSON and TOML keys, XML <name>value</name> and NuGet <add key="http_proxy"
# value="..."/>. A proxy key that opens a block (YAML "proxy_servers:", JSON "proxies": {,
# Maven <proxies> and <proxy>) makes its children proxy settings; host, port and protocol
# children fold into one proxy, as do Java-style *.proxyHost and *.proxyPort pairs. User
# names, passwords and tokens are never returned. A Ruby symbol key (.gemrc ":http_proxy:")
# counts without its colon. Go's GOPROXY (a module mirror) and GONOPROXY are no proxy settings.
# A value without a scheme may start with user:password@ (pip, wget): the endpoint leaves it
# out. Under a key ending in "proxy" a bare host (also a single label, not a keyword such as
# null, off or direct) gets port 80.
# Matching is case-sensitive as in awk; keys are lower-cased where awk lower-cases them.
# ---------------------------------------------------------------------------

$script:ES_PROXY_NAME_RE = 'prox(y|ies)'
$script:ES_PROXY_SECRET_RE = '(user|username|login|pass|password|passwd|pwd|token|secret|credential|credentials|auth|authorization)$'
# Exclusion lists: no_proxy, nonProxyHosts and the like ("b[y]pass": the plain word is on the
# suspicious-content list of PowerShell script block logging).
$script:ES_PROXY_EXCLUDE_RE = 'no[_-]?prox(y|ies)|non[_-]?prox(y|ies)|b[y]pass|exclu'
$script:ES_PROXY_KEY_RE = '^[A-Za-z0-9_@][A-Za-z0-9_.@-]*(::?[A-Za-z0-9_.@-]+)*'
$script:ES_PROXY_HOST_RE = '^(\[[0-9A-Fa-f:.%]+]|[A-Za-z0-9._-]+)(:[0-9]+)?'
# A bare host: dotted labels (or an IPv4 address), or one label with a letter that is no keyword.
$script:ES_PROXY_DOTTED_RE = '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$'
$script:ES_PROXY_LABEL_RE = '^[A-Za-z0-9-]*[A-Za-z][A-Za-z0-9-]*$'
$script:ES_PROXY_KEYWORD_RE = '^(null|nil|none|false|true|off|on|no|yes|direct|system|auto|default|disable|disabled|enable|enabled|unset|empty|undefined|manual|inherit)$'

function New-EsProxyState {
    # Open blocks (bk key, bi indent, bx opened by XML, bh/bp/bs host, port, protocol) and the
    # settings of the current source (rkey, rvalue, rendpoint, rexclusion; jh/jp Java pairs).
    return @{ depth = 0; bk = @{}; bi = @{}; bx = @{}; bh = @{}; bp = @{}; bs = @{}; incom = $false; n = 0
        rkey = @{}; rvalue = @{}; rendpoint = @{}; rexclusion = @{}; jh = @{}; jp = @{}
    }
}

function Test-EsProxySecret([string]$LKey) {
    # A user name, password or token setting: never returned. A key ending in the exclusion
    # word b[y]pass ends in "pass" but is not one.
    if ($LKey -cmatch 'b[y]pass$') { return $false }
    return ($LKey -cmatch $script:ES_PROXY_SECRET_RE)
}

function Test-EsProxyGoModule([string]$LKey) {
    # Go's module settings: GOPROXY names a module mirror (a registry, which the endpoints
    # report), GONOPROXY the modules fetched without it; neither is an HTTP proxy.
    return ($LKey -cmatch '^go(no)?proxy$')
}

function Get-EsProxyClean([string]$Value) {
    # The value without quotes, a trailing ";" or ",", or a shell or inline comment.
    $v = $Value -creplace '^[ \t]+', ''
    if ($v.StartsWith('"') -or $v.StartsWith("'")) {
        $end = $v.Substring(1).IndexOf($v.Substring(0, 1))
        if ($end -ge 0) { $v = $v.Substring(1, $end) } else { $v = $v.Substring(1) }
    } else {
        $v = ($v -creplace ';[ \t].*$', '') -creplace '[ \t]+#.*$', ''
        $v = (($v -creplace '[ \t]+$', '') -creplace '[;,]$', '') -creplace '[ \t]+$', ''
    }
    return $v.Replace("`t", ' ')
}

function Remove-EsXmlComments([hashtable]$State, [string]$Text) {
    # The line without XML comments, which may span lines ($State.incom).
    $s = $Text
    if ($State.incom) {
        $k = $s.IndexOf('-->')
        if ($k -lt 0) { return '' }
        $s = $s.Substring($k + 3)
        $State.incom = $false
    }
    for ($k = $s.IndexOf('<!--'); $k -ge 0; $k = $s.IndexOf('<!--')) {
        $rest = $s.Substring($k + 4)
        $end = $rest.IndexOf('-->')
        if ($end -lt 0) { $State.incom = $true; return $s.Substring(0, $k) }
        $s = $s.Substring(0, $k) + $rest.Substring($end + 3)
    }
    return $s
}

function Read-EsProxyKeyValue([string]$Text) {
    # key=value, key: value, key "value" (also export/set/setenv and a quoted key) as @{ key;
    # value; open; xml }: open when the value is empty or "{" (the key opens a block). $null
    # when the line has no key.
    $s = $Text -creplace '^(export|setenv|set)[ \t]+', ''
    if ($s -cmatch '^:[A-Za-z_]') { $s = $s.Substring(1) }
    $quote = ''
    if ($s.StartsWith('"') -or $s.StartsWith("'")) { $quote = $s.Substring(0, 1); $s = $s.Substring(1) }
    if ($s -cnotmatch $script:ES_PROXY_KEY_RE) { return $null }
    $key = $matches[0]
    $rest = $s.Substring($key.Length)
    if ($quote) {
        if (-not $rest.StartsWith($quote)) { return $null }
        $rest = $rest.Substring(1)
    }
    if ($rest -ne '' -and $rest -cnotmatch '^[ \t=:]') { return $null }
    $rest = $rest -creplace '^[ \t]*', ''
    if ($rest -cmatch '^[=:]') { $rest = $rest.Substring(1) }
    $value = Get-EsProxyClean $rest
    return @{ key = $key; value = $value; open = ($value -eq '' -or $value -eq '{'); xml = $false }
}

function Get-EsXmlAttribute([string]$Text, [string]$Name) {
    # The value of attribute $Name (any case) of an XML tag, '' when absent.
    $m = [regex]::Match($Text.ToLowerInvariant(), '[ \t]' + $Name + '[ \t]*=[ \t]*("[^"]*"|''[^'']*'')')
    if (-not $m.Success) { return '' }
    $r = $Text.Substring($m.Index, $m.Length) -creplace '^[^=]*=[ \t]*', ''
    return $r.Substring(1, $r.Length - 2)
}

function Read-EsProxyXml([hashtable]$State, [string]$Text) {
    # <name>value</name>, <name> alone on its line (opens a block) and NuGet's <add key=
    # value=> (only its proxy keys: in <packageSources> a key is a free source name), as
    # Read-EsProxyKeyValue returns them. A closing tag ends the block it closes.
    if ($Text.StartsWith('</')) {
        $name = (($Text -creplace '^</[ \t]*', '') -creplace '[^A-Za-z0-9_.:-].*$', '').ToLowerInvariant()
        $d = $State.depth
        if ($d -gt 0 -and $State.bx[$d] -and $name -ceq ($State.bk[$d].ToLowerInvariant() -creplace '^.*\.', '')) { Pop-EsProxyBlock $State }
        return $null
    }
    if ($Text.ToLowerInvariant() -cmatch '^<add[ \t]') {
        $key = Get-EsXmlAttribute $Text 'key'
        if ($key.ToLowerInvariant() -cnotmatch '^(http_proxy|https_proxy|no_proxy)$') { return $null }
        return @{ key = $key; value = (Get-EsProxyClean (Get-EsXmlAttribute $Text 'value')); open = $false; xml = $false }
    }
    if ($Text -cnotmatch '^<[A-Za-z_][A-Za-z0-9_.:-]*') { return $null }
    $name = $matches[0].Substring(1)
    $rest = $Text.Substring($matches[0].Length)
    $k = $rest.IndexOf('>')
    if ($k -lt 0 -or ($k -gt 0 -and $rest.Substring($k - 1, 1) -eq '/')) { return $null }
    $rest = $rest.Substring($k + 1)
    $end = $rest.IndexOf('<')
    $value = Get-EsProxyClean $(if ($end -ge 0) { $rest.Substring(0, $end) } else { $rest })
    $open = ($value -eq '' -and $end -lt 0)
    return @{ key = $name; value = $value; open = $open; xml = $open }
}

function Push-EsProxyBlock([hashtable]$State, [string]$Key, [int]$Indent, [bool]$Xml) {
    $d = $State.depth + 1
    $State.depth = $d
    $State.bk[$d] = $Key; $State.bi[$d] = $Indent; $State.bx[$d] = $Xml
    $State.bh[$d] = ''; $State.bp[$d] = ''; $State.bs[$d] = ''
}

function Pop-EsProxyBlock([hashtable]$State) {
    # Ends the innermost block: its host, port and protocol become one proxy setting.
    $d = $State.depth
    if ($State.bh[$d] -ne '') {
        $value = $State.bh[$d]
        if ($State.bp[$d] -ne '') { $value += ':' + $State.bp[$d] }
        if ($State.bs[$d] -ne '') { $value = $State.bs[$d].ToLowerInvariant() + '://' + $value }
        $key = [string]$State.bk[$d]
        Add-EsProxyRecord $State $key $key.ToLowerInvariant() $value
    }
    $State.depth = $d - 1
}

function Set-EsProxyFold([hashtable]$State, [hashtable]$Item, [string]$Last) {
    # A host, port or protocol child of a block is kept for the block's proxy (Pop-EsProxyBlock).
    if ($Item.open) { return $false }
    $d = $State.depth
    if ($Last -cmatch '^(host|hostname|server|address)$') { $State.bh[$d] = $Item.value; return $true }
    if ($Last -ceq 'port') { $State.bp[$d] = $Item.value; return $true }
    if ($Last -ceq 'protocol' -or $Last -ceq 'scheme') { $State.bs[$d] = $Item.value; return $true }
    return $false
}

function Get-EsProxyEndpoint([string]$Value) {
    # host:port of the URL or the host:port in a value, '' when none; default port by scheme.
    $m = [regex]::Match($Value, '[A-Za-z][A-Za-z0-9+.-]*://[^/ \t"''<>,;]+')
    if ($m.Success) {
        $j = $m.Value.IndexOf('://')
        $scheme = $m.Value.Substring(0, $j).ToLowerInvariant()
        $hostPort = $m.Value.Substring($j + 3)
        $hostPort = $hostPort.Substring($hostPort.LastIndexOf('@') + 1)
        $h = [regex]::Match($hostPort, $script:ES_PROXY_HOST_RE)
        if (-not $h.Success) { return '' }
        if ($h.Value -cmatch ':[0-9]+$') { return $h.Value }
        if ($scheme -ceq 'https') { return $h.Value + ':443' }
        if ($scheme -cmatch '^socks') { return $h.Value + ':1080' }
        return $h.Value + ':80'
    }
    # Without a scheme: less a user:password@ before the host (to the last "@").
    $hostPort = $Value.Substring($Value.LastIndexOf('@') + 1)
    if ($hostPort -cmatch '^[A-Za-z0-9.-]+:[0-9]+$') { return $hostPort }
    return ''
}

function Test-EsProxyBareHost([string]$HostName) {
    # A host name without a port; a single label needs a letter and is no keyword (null, off, ...).
    if ($HostName -cmatch $script:ES_PROXY_DOTTED_RE) { return $true }
    if ($HostName -cnotmatch $script:ES_PROXY_LABEL_RE) { return $false }
    return ($HostName.ToLowerInvariant() -cnotmatch $script:ES_PROXY_KEYWORD_RE)
}

function Add-EsProxyRecord([hashtable]$State, [string]$Key, [string]$LKey, [string]$Value) {
    # One setting of the current source; *.proxyHost and *.proxyPort are paired at the end. Under
    # a key ending in "proxy" a bare host (less any user:password@) gets port 80.
    $endpoint = Get-EsProxyEndpoint $Value
    $bare = $Value.Substring($Value.LastIndexOf('@') + 1)
    if ($endpoint -eq '' -and $LKey -cmatch 'proxy$' -and (Test-EsProxyBareHost $bare)) { $endpoint = $bare + ':80' }
    $n = $State.n + 1
    $State.n = $n
    $State.rkey[$n] = $Key; $State.rvalue[$n] = $Value; $State.rendpoint[$n] = $endpoint
    $State.rexclusion[$n] = ($LKey -cmatch $script:ES_PROXY_EXCLUDE_RE)
    if ($LKey -cmatch 'proxyhost$') { $State.jh[$LKey.Substring(0, $LKey.Length - 9)] = $n }
    if ($LKey -cmatch 'proxyport$') { $State.jp[$LKey.Substring(0, $LKey.Length - 9)] = $Value }
}

function Add-EsProxyConfLine([hashtable]$State, [string]$Line) {
    # One line of a configuration file. Indentation ends YAML-style blocks, closing tags XML ones.
    $s = Remove-EsXmlComments $State $Line
    if ($s -cmatch '^[ \t]*$' -or $s -cmatch '^[ \t]*(#|;|//|!)') { return }
    $trimmed = $s -creplace '^[ \t]+', ''
    $indent = $s.Length - $trimmed.Length
    if ($trimmed.StartsWith('<')) { $item = Read-EsProxyXml $State $trimmed }
    else {
        while ($State.depth -gt 0 -and -not $State.bx[$State.depth] -and $indent -le $State.bi[$State.depth]) { Pop-EsProxyBlock $State }
        $item = Read-EsProxyKeyValue $trimmed
    }
    if ($null -eq $item) { return }
    $d = $State.depth
    $full = [string]$item.key
    if ($d -gt 0) { $full = $State.bk[$d] + '.' + $full }
    $lkey = $full.ToLowerInvariant()
    $last = ([string]$item.key).ToLowerInvariant()
    if ($d -gt 0 -and (Set-EsProxyFold $State $item $last)) { return }
    if ((Test-EsProxySecret $last) -or (Test-EsProxyGoModule $last)) { return }
    $named = ($lkey -cmatch $script:ES_PROXY_NAME_RE)
    if ($item.open) {
        if ($d -gt 0 -or $named) { Push-EsProxyBlock $State $full $indent $item.xml }
        return
    }
    if ($d -eq 0 -and -not $named) { return }
    # In a block: a proxy key, a URL value or a scheme key (proxy_servers: http: ...).
    $other = ($last -cnotmatch $script:ES_PROXY_NAME_RE -and $item.value -cnotmatch '://')
    if ($d -gt 0 -and $other -and $last -cnotmatch '^(http|https|ftp|all|socks|socks4|socks5)$') { return }
    Add-EsProxyRecord $State $full $lkey $item.value
}

function Add-EsProxyGitLine([hashtable]$State, [string]$Text) {
    # One "key=value" of git config --list. The subsection (often a URL, as in
    # url.<url>.insteadOf or http.<url>.proxy) is left out of the name test.
    $k = $Text.IndexOf('=')
    if ($k -lt 1) { return }
    $key = $Text.Substring(0, $k)
    $lkey = $key.ToLowerInvariant()
    if ($lkey.IndexOf('.') -ge 0) { $lkey = ($lkey -creplace '\..*$', '') + '.' + ($lkey -creplace '^.*\.', '') }
    if ($lkey -cnotmatch $script:ES_PROXY_NAME_RE -or (Test-EsProxySecret $lkey) -or (Test-EsProxyGoModule $lkey)) { return }
    Add-EsProxyRecord $State $key $lkey (Get-EsProxyClean $Text.Substring($k + 1))
}

function Complete-EsProxySource([hashtable]$State) {
    # The settings of one source as @{ kind; endpoint; key; value } (kind proxy, exclusion or
    # other), after closing its open blocks and pairing *.proxyHost with *.proxyPort. Resets
    # $State for the next source.
    while ($State.depth -gt 0) { Pop-EsProxyBlock $State }
    foreach ($prefix in @($State.jh.PSBase.Keys)) {
        $i = $State.jh[$prefix]
        if ($State.rendpoint[$i] -ne '' -or $State.rvalue[$i] -cnotmatch '^[A-Za-z0-9._-]+$') { continue }
        $port = [string]$State.jp[$prefix]
        if ($port -cnotmatch '^[0-9]+$') { $port = $(if ($prefix -cmatch 'https') { '443' } elseif ($prefix -cmatch 'socks') { '1080' } else { '80' }) }
        $State.rendpoint[$i] = $State.rvalue[$i] + ':' + $port
    }
    $settings = @()
    for ($i = 1; $i -le $State.n; $i++) {
        $kind = $(if ($State.rexclusion[$i]) { 'exclusion' } elseif ($State.rendpoint[$i]) { 'proxy' } else { 'other' })
        $settings += @{ kind = $kind; endpoint = $State.rendpoint[$i]; key = $State.rkey[$i]; value = $State.rvalue[$i] }
    }
    $State.n = 0; $State.incom = $false; $State.jh = @{}; $State.jp = @{}
    $State.rkey = @{}; $State.rvalue = @{}; $State.rendpoint = @{}; $State.rexclusion = @{}
    return $settings
}

function ConvertTo-EsProxyUrls([object[]]$Settings) {
    # The URLs of proxy settings: scheme://host[:port] in lower case, never userinfo, a path or a
    # query; http://host:port for a bare host:port. Each once, in order.
    $urls = @()
    foreach ($setting in @($Settings)) {
        if ($setting.kind -ne 'proxy') { continue }
        $url = ''
        $m = [regex]::Match([string]$setting.value, '[A-Za-z][A-Za-z0-9+.-]*://[^/ \t"''<>,;?#]+')
        if ($m.Success) {
            $j = $m.Value.IndexOf('://')
            $hostPort = $m.Value.Substring($j + 3)
            $h = [regex]::Match($hostPort.Substring($hostPort.LastIndexOf('@') + 1), $script:ES_PROXY_HOST_RE)
            if ($h.Success) { $url = $m.Value.Substring(0, $j) + '://' + $h.Value }
        } elseif ($setting.endpoint) { $url = 'http://' + $setting.endpoint }
        if (-not $url) { continue }
        $url = $url.ToLowerInvariant()
        if ($urls -notcontains $url) { $urls += $url }
    }
    return $urls
}

function Get-EsConfigProxySettings([object[]]$Lines) {
    # The proxy settings of one configuration file (Complete-EsProxySource), from the raw lines
    # its configs entry keeps.
    $state = New-EsProxyState
    foreach ($line in @($Lines)) { Add-EsProxyConfLine $state ([string]$line).TrimEnd("`r") }
    return @(Complete-EsProxySource $state)
}

function Get-EsConfigProxyUrls([object[]]$Lines) {
    # The proxy URLs of one configuration file, from the raw lines its configs entry keeps.
    return @(ConvertTo-EsProxyUrls @(Get-EsConfigProxySettings $Lines))
}

# The settings found by name in the files pkg.sources read (net.proxy package_managers).
$script:ES_PKG_PROXY_SETTINGS = @()

function ConvertTo-EsProxySettingItems([object[]]$Settings, [string]$Tool, [string]$File) {
    # Settings (Complete-EsProxySource) as net.proxy lists them: @{ tool; setting = the key;
    # value = redacted (name and value rules); file }. Proxies, exclusions and the others.
    $items = @()
    foreach ($setting in @($Settings)) {
        if ($null -eq $setting) { continue }
        $key = [string]$setting.key
        $items += @{ tool = $Tool; setting = $key; value = (Protect-EsNamedValue $key ([string]$setting.value)); file = $File }
    }
    return $items
}
