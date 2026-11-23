# Runs the redaction cases listed in a JSON file through the envscan library and prints one
# JSON object (case name -> result) for tests/test_ps_redaction.py. Runs in FullLanguage and
# in ConstrainedLanguage, so it may only use what the scanner itself may use.
param([string]$Lib, [string]$Cases)

. $Lib
Initialize-EsRedaction
$out = @{}

# Redaction runs more than once over the same text (line, value, data safety net): the second
# pass must not change what the first one produced.
function Protect-TwiceValue($Value) { Protect-EsValue (Protect-EsValue $Value) }
function Protect-TwiceLine($Value) { Protect-EsLine (Protect-EsLine $Value) }
function Protect-TwiceCommandLine($Value) { Protect-EsCommandLine (Protect-EsCommandLine $Value) }

# PS 5.1 ConvertFrom-Json emits a JSON array as one object; foreach enumerates it.
$parsed = Get-Content -LiteralPath $Cases -Raw | ConvertFrom-Json
foreach ($case in $parsed) {
    $arguments = @($case.args)
    $out[[string]$case.name] = & ([string]$case.fn) @arguments
}

# Structured data (the central safety net) and cases that need PowerShell values.
$out['data_safety_net'] = Protect-EsData @{
    conn = 'Server=x;Password=abc123;'
    opts = @('MAVEN -Dfoo.password=zzz999', 'plain value')
    nested = @{ header = 'X-Api-Key: key777key' }
}
$deep = 'Server=x;Password=deep555;'
for ($i = 0; $i -lt 35; $i++) { $deep = @{ next = $deep } }
$out['data_too_deep'] = ConvertTo-EsJson (Protect-EsData $deep)
Write-EsLog 'run tool --token log444secret'
$out['log_line'] = [string]$script:ES_LOG[$script:ES_LOG.Count - 1]

$out['language_mode'] = $script:ES_LANGUAGE_MODE
Write-Output (ConvertTo-EsJson $out)
