# Runs one Exchange Online cmdlet. Reads a JSON request on stdin, writes exactly one JSON envelope line on stdout.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)

function ConvertTo-Param($v) {
    if ($null -eq $v) { return $null }
    if ($v -is [System.Management.Automation.PSCustomObject]) {
        $h = @{}
        foreach ($p in $v.PSObject.Properties) { $h[$p.Name] = ConvertTo-Param $p.Value }
        return $h
    }
    if ($v -is [System.Array]) {
        $items = @($v | ForEach-Object { ConvertTo-Param $_ })
        $allStrings = $true
        foreach ($i in $items) { if ($i -isnot [string]) { $allStrings = $false } }
        if ($allStrings) { return [string[]]$items }
        return [object[]]$items
    }
    return $v
}

$envelope = $null
try {
    $raw = [Console]::In.ReadToEnd()
    $req = $raw | ConvertFrom-Json
    $name = [string]$req.cmdlet

    try {
        Import-Module ExchangeOnlineManagement -ErrorAction Stop | Out-Null
    } catch {
        throw 'ExchangeOnlineManagement module not installed. Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser'
    }

    Connect-ExchangeOnline -AccessToken ([string]$req.token) -UserPrincipalName ([string]$req.upn) -Organization ([string]$req.organization) -ShowBanner:$false | Out-Null

    # Module-origin check: only Exchange Online cmdlets may run (refuses Get-Content, Get-ChildItem, Get-Process, ...).
    $cmd = Get-Command -Name $name -CommandType Cmdlet,Function -ErrorAction Stop
    $allowed = ($cmd.Source -like 'tmpEXO_*') -or ($cmd.ModuleName -like 'tmpEXO_*') -or
        ($cmd.Source -eq 'ExchangeOnlineManagement') -or ($cmd.ModuleName -eq 'ExchangeOnlineManagement')
    if (-not $allowed) {
        $envelope = @{ ok = $false; error = 'Cmdlet is not an Exchange Online cmdlet.' }
    } else {
        $params = @{}
        if ($null -ne $req.parameters) {
            foreach ($p in $req.parameters.PSObject.Properties) {
                $params[$p.Name] = ConvertTo-Param $p.Value
            }
        }
        $result = & $cmd @params 3>$null 4>$null 5>$null 6>$null
        $envelope = @{ ok = $true; result = $result }
    }
} catch {
    $envelope = @{ ok = $false; error = [string]$_.Exception.Message }
} finally {
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue 3>$null 4>$null 5>$null 6>$null | Out-Null } catch { }
}

try {
    $json = $envelope | ConvertTo-Json -Depth 6 -Compress
} catch {
    $json = (@{ ok = $false; error = 'Could not serialize result.' } | ConvertTo-Json -Compress)
}
[Console]::Out.WriteLine($json)
