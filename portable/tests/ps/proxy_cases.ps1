# Runs the proxy cases of tests/proxy_cases.py through the envscan library for
# tests/test_ps_proxy.py and prints one JSON object (case name -> @{ proxy_urls; urls }). A
# configuration file case gives the proxy_urls and urls (endpoint bases) of its configs entry
# (Read-EsConfigFile), a git case the URLs of git's proxy settings (Add-EsGitEntries). Runs in
# FullLanguage and in ConstrainedLanguage, so it may only use what the scanner itself may use.
param([string]$Lib, [string]$Cases)

. $Lib
Initialize-EsRedaction
$out = @{}
# The settings found by name (net.proxy package_managers: tool, setting, value redacted, file),
# kept apart: they name users (bob), the URL results never do.
$settings = @{}

# PS 5.1 ConvertFrom-Json emits a JSON array as one object; foreach enumerates it.
$parsed = Get-Content -LiteralPath $Cases -Raw | ConvertFrom-Json
foreach ($case in $parsed) {
    $name = [string]$case.name
    if ($case.kind -eq 'config') {
        $config = @{ id = [string]$case.config.id; tool = [string]$case.config.tool; scope = 'user'
            mode = [string]$case.config.mode; match = @($case.config.match); max_bytes = [int]$case.config.max_bytes }
        $entry = Read-EsConfigFile $config ([string]$case.path)
        $out[$name] = @{ proxy_urls = @($entry.proxy_urls); urls = @($entry.urls) }
        $settings[$name] = @($entry.proxy_settings)
    } else {
        $git = @{ items = @(); urls = @(); proxy_urls = @(); proxy_settings = @() }
        $text = (@($case.entries) | ForEach-Object { 'file:C:/h/.gitconfig' + "`t" + [string]$_ }) -join "`n"
        $null = Add-EsGitEntries $git $text '' $true
        $out[$name] = @{ proxy_urls = @($git.proxy_urls | ForEach-Object { [string]$_.url }) }
        $settings[$name] = @($git.proxy_settings)
    }
}

$out['language_mode'] = $script:ES_LANGUAGE_MODE
$out['settings'] = $settings
Write-Output (ConvertTo-EsJson $out)
