# Runs one admin cmdlet for one Microsoft 365 service (exchange, compliance, teams, sharepoint).
# Reads a JSON request on stdin, writes exactly one JSON envelope line on stdout.
# Runs under Windows PowerShell 5.1 (exchange, compliance, teams) and PowerShell 7.4+ (sharepoint).
# Tokens arrive on stdin only; nothing here writes them anywhere.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'

$WinHint = 'Run in Windows PowerShell (powershell.exe), not PowerShell 7:'
$CoreHint = 'Run in PowerShell 7 (pwsh), not Windows PowerShell:'
$DefaultItems = 200
$script:failCode = $null

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
        if ($allStrings) { return ,([string[]]$items) }
        return ,$items
    }
    return $v
}

# The assistant never installs modules: a missing or old one is reported with the command for the user to run.
function Assert-Module([string]$name, [string]$min, [string]$hint) {
    $m = Get-Module -ListAvailable -Name $name | Sort-Object Version -Descending | Select-Object -First 1
    if ($null -eq $m) {
        $script:failCode = 'module_missing'
        throw "The $name PowerShell module is not installed. $hint Install-Module $name -Scope CurrentUser"
    }
    if ($m.Version -lt [version]$min) {
        $script:failCode = 'module_missing'
        throw "$name $min or later is required (found $($m.Version)). $hint Update-Module $name"
    }
    Import-Module $name -ErrorAction Stop 3>$null 4>$null 5>$null 6>$null | Out-Null
}

function Test-Simple($v) {
    return ($null -eq $v) -or ($v -is [string]) -or ($v -is [ValueType]) -or ($v -is [uri]) -or ($v -is [version])
}

function ConvertTo-Simple($v) {
    if ($v -is [enum]) { return [string]$v }
    if (($v -is [uri]) -or ($v -is [version]) -or ($v -is [guid])) { return [string]$v }
    return $v
}

# Simple (text, number, date, flag) properties only. Used for SharePoint objects, whose other properties
# throw until loaded or drag the whole connection along, and as a fallback when a result will not serialise.
function ConvertTo-Flat($o) {
    if (Test-Simple $o) { return ConvertTo-Simple $o }
    $out = [ordered]@{}
    foreach ($p in $o.PSObject.Properties) {
        $v = $null
        try { $v = $p.Value } catch { continue }
        if (Test-Simple $v) { $out[$p.Name] = ConvertTo-Simple $v; continue }
        if ($v -is [System.Array]) {
            $simple = $true
            foreach ($i in $v) { if (-not (Test-Simple $i)) { $simple = $false; break } }
            if ($simple) { $out[$p.Name] = @($v | ForEach-Object { ConvertTo-Simple $_ }) }
        }
    }
    return [pscustomobject]$out
}

# Reads "Owner.Email" by walking properties. No script blocks: names are data, never code.
function Get-PathValue($obj, [string]$path) {
    $cur = $obj
    foreach ($seg in $path.Split('.')) {
        if ($null -eq $cur) { return $null }
        if ($cur -is [System.Collections.IDictionary]) { $cur = $cur[$seg]; continue }
        $p = $cur.PSObject.Properties[$seg]
        if ($null -eq $p) { return $null }
        try { $cur = $p.Value } catch { return $null }
    }
    if (Test-Simple $cur) { return ConvertTo-Simple $cur }
    return $cur
}

function Select-Paths($obj, [string[]]$paths) {
    $out = [ordered]@{}
    foreach ($path in $paths) { $out[$path] = Get-PathValue $obj $path }
    return [pscustomobject]$out
}

$envelope = $null
$service = $null
try {
    [Console]::InputEncoding = [System.Text.Encoding]::UTF8
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $raw = [Console]::In.ReadToEnd()
    $req = $raw | ConvertFrom-Json
    $name = [string]$req.cmdlet
    $service = [string]$req.service
    $token = [string]$req.token
    $origins = @()

    switch ($service) {
        'exchange' {
            Assert-Module 'ExchangeOnlineManagement' '3.1.0' $WinHint
            Connect-ExchangeOnline -AccessToken $token -UserPrincipalName ([string]$req.upn) -Organization ([string]$req.organization) -ShowBanner:$false -ErrorAction Stop 6>$null | Out-Null
            $origins = @('tmpEXO_*', 'ExchangeOnlineManagement')
        }
        'compliance' {
            Assert-Module 'ExchangeOnlineManagement' '3.2.0' $WinHint
            Connect-IPPSSession -AccessToken $token -UserPrincipalName ([string]$req.upn) -Organization ([string]$req.organization) -ShowBanner:$false -ErrorAction Stop 6>$null | Out-Null
            $origins = @('tmpEXO_*', 'ExchangeOnlineManagement')
        }
        'teams' {
            Assert-Module 'MicrosoftTeams' '6.0.0' $WinHint
            # Graph token first, then the Teams ("Skype and Teams Tenant Admin API") token.
            Connect-MicrosoftTeams -AccessTokens @([string]$req.graphToken, $token) -ErrorAction Stop 6>$null | Out-Null
            $origins = @('MicrosoftTeams', 'Microsoft.Teams.*')
        }
        'sharepoint' {
            if ($PSVersionTable.PSVersion -lt [version]'7.4') {
                $script:failCode = 'module_missing'
                throw 'SharePoint needs PowerShell 7.4 or later. Install it yourself: winget install Microsoft.PowerShell'
            }
            Assert-Module 'PnP.PowerShell' '3.0.0' $CoreHint
            Connect-PnPOnline -Url ([string]$req.url) -AccessToken $token -ErrorAction Stop 6>$null | Out-Null
            $origins = @('PnP.PowerShell')
        }
        default { throw 'Unknown service.' }
    }

    # Module-origin check: only this service's own cmdlets may run (refuses Get-Content, Get-ChildItem, Get-Process, ...).
    $cmd = Get-Command -Name $name -CommandType Cmdlet,Function -ErrorAction Stop
    $allowed = $false
    foreach ($src in @($cmd.Source, $cmd.ModuleName)) {
        if (-not $src) { continue }
        foreach ($pattern in $origins) { if ($src -like $pattern) { $allowed = $true } }
    }
    if (-not $allowed) {
        $envelope = @{ ok = $false; error = "Cmdlet is not a $service cmdlet." }
    } else {
        $params = @{}
        if ($null -ne $req.parameters) {
            foreach ($p in $req.parameters.PSObject.Properties) {
                $params[$p.Name] = ConvertTo-Param $p.Value
            }
        }
        # $ErrorActionPreference does not reach module functions; force it per call.
        $params['ErrorAction'] = 'Stop'
        # The user already approved this change in the broker's dialog. Without this, ConfirmImpact=High
        # cmdlets (Remove-*) try to prompt and fail under -NonInteractive. The broker rejects a caller Confirm.
        if (($name -cnotlike 'Get-*') -and $cmd.Parameters.ContainsKey('Confirm')) {
            $params['Confirm'] = $false
        }
        # PnP asks "are you sure?" through -Force instead of -Confirm.
        if (($service -eq 'sharepoint') -and ($name -cnotlike 'Get-*') -and $cmd.Parameters.ContainsKey('Force') -and -not $params.ContainsKey('Force')) {
            $params['Force'] = $true
        }

        $all = @(& $cmd @params 3>$null 4>$null 5>$null 6>$null)
        $total = $all.Count
        $take = $DefaultItems
        if ($null -ne $req.first) { $take = [int]$req.first }
        $shown = @($all | Select-Object -First $take)
        $note = $null
        if ($null -ne $req.select) {
            $paths = [string[]]@($req.select)
            $shown = @($shown | ForEach-Object { Select-Paths $_ $paths })
        } elseif ($service -eq 'sharepoint') {
            $shown = @($shown | ForEach-Object { ConvertTo-Flat $_ })
            $note = 'Only simple properties are shown. Use select to pick specific properties.'
        }
        $envelope = @{ ok = $true; result = $shown; total = $total }
        if ($note) { $envelope['note'] = $note }
    }
} catch {
    $envelope = @{ ok = $false; error = [string]$_.Exception.Message }
    if ($script:failCode) { $envelope['code'] = $script:failCode }
} finally {
    try {
        switch ($service) {
            'exchange' { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue 3>$null 4>$null 5>$null 6>$null | Out-Null }
            'compliance' { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue 3>$null 4>$null 5>$null 6>$null | Out-Null }
            'teams' { Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue 3>$null 4>$null 5>$null 6>$null | Out-Null }
            'sharepoint' { Disconnect-PnPOnline -ErrorAction SilentlyContinue 3>$null 4>$null 5>$null 6>$null | Out-Null }
        }
    } catch { }
}

$json = $null
try {
    $json = $envelope | ConvertTo-Json -Depth 4 -Compress
} catch {
    # Some results will not serialise as they are; fall back to their simple properties.
    try {
        if (-not $envelope['ok']) { throw 'not a result' }
        $flat = @($envelope['result'] | ForEach-Object { ConvertTo-Flat $_ })
        $json = @{ ok = $true; result = $flat; total = $envelope['total']; note = 'Only simple properties are shown. Use select to pick specific properties.' } | ConvertTo-Json -Depth 4 -Compress
    } catch {
        $json = (@{ ok = $false; error = 'Could not serialize result.' } | ConvertTo-Json -Compress)
    }
}
[Console]::Out.WriteLine($json)
