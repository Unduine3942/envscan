# Runs the findings of the envscan library on probe results given as JSON and prints one JSON
# object (case name -> finding ids) for tests/test_findings.py. FullLanguage only.
# Input: a JSON list of { name, full_language, results = { probe id = { status, data } } }.
param([string]$Lib, [string]$Cases)

. $Lib
Initialize-EsRedaction

function ConvertTo-Plain($Value) {
    # PSCustomObject -> hashtable, arrays stay arrays (an empty array stays empty).
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $table = @{}
        foreach ($p in $Value.PSObject.Properties) { $table[[string]$p.Name] = ConvertTo-Plain $p.Value }
        return $table
    }
    if ($Value -is [System.Array]) {
        $items = @()
        foreach ($item in $Value) { $items += , (ConvertTo-Plain $item) }
        return , $items
    }
    return $Value
}

$out = @{}
$parsed = Get-Content -LiteralPath $Cases -Raw | ConvertFrom-Json
foreach ($case in $parsed) {
    $script:ES_RESULTS = @{}
    foreach ($property in $case.results.PSObject.Properties) {
        $data = ConvertTo-Plain $property.Value.data
        if ($null -eq $data) { $data = @{} }
        $script:ES_RESULTS[[string]$property.Name] = @{ status = [string]$property.Value.status; data = $data; notes = @() }
    }
    $script:ES_FULL_LANGUAGE = [bool]$case.full_language
    $script:ES_LANGUAGE_MODE = $(if ($script:ES_FULL_LANGUAGE) { 'FullLanguage' } else { 'ConstrainedLanguage' })
    $ids = @(Get-EsFindings | ForEach-Object { [string]$_.id })
    $out[[string]$case.name] = $ids
}
Write-Output (ConvertTo-EsJson $out)
