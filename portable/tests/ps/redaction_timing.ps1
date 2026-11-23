# Times the redaction functions on hostile input for tests/test_ps_redaction_hardening.py.
# Prints one JSON object: case name -> {ms, length, result_length, leaked}. Runs in FullLanguage
# and in ConstrainedLanguage, so it only uses what the scanner itself may use.
param([string]$Lib, [string]$Cases)

. $Lib
Initialize-EsRedaction
$out = @{}
$parsed = Get-Content -LiteralPath $Cases -Raw | ConvertFrom-Json
foreach ($case in $parsed) {
    $arguments = @($case.args)
    $start = [DateTime]::UtcNow
    $result = [string](& ([string]$case.fn) @arguments)
    $elapsed = [DateTime]::UtcNow - $start
    $out[[string]$case.name] = @{
        ms = [int]$elapsed.TotalMilliseconds
        length = ([string]$arguments[0]).Length
        result = $(if ($result.Length -gt 200) { $result.Substring(0, 200) } else { $result })
        result_length = $result.Length
    }
}
$out['language_mode'] = $script:ES_LANGUAGE_MODE
Write-Output (ConvertTo-EsJson $out)
