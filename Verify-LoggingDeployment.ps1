# Part of ADHardenKit. Copyright (C) 2026 nopcap.tech
# Licensed under the GNU General Public License v3.0 or later. See LICENSE.

<#
    .SYNOPSIS
    Checks whether the ADHardenKit Logging GPO actually took effect on this domain controller.

    .DESCRIPTION
    A deployment that reports Created has written files and set attributes. That is not the same
    as the client having read them. This checks the four places where the chain can break, in the
    order it breaks:

        1. the CSE registration on the GPO object     - without it nothing is read at all
        2. the files in SYSVOL                        - written, and reachable from here
        3. the applied audit policy                   - what auditpol reports right now
        4. the registry policy values                 - script block logging and the log sizes

    Read-only. Run it on a domain controller after gpupdate /force.
#>
[CmdletBinding()]
param(
    [string]$GpoName = 'ADHardenKit-DC-Logging'
)

$ErrorActionPreference = 'Stop'
Import-Module GroupPolicy, ActiveDirectory

function Show([string]$Text, [bool]$Ok, [string]$Detail) {
    $mark = if ($Ok) { '[+]' } else { '[x]' }
    $colour = if ($Ok) { 'Green' } else { 'Red' }
    Write-Host ("  {0} {1}" -f $mark, $Text) -ForegroundColor $colour
    if ($Detail) { Write-Host ("      {0}" -f $Detail) -ForegroundColor DarkGray }
}

$gpo = Get-GPO -Name $GpoName
$domain = Get-ADDomain
$dn = "CN={$($gpo.Id.ToString().ToUpper())},CN=Policies,CN=System,$($domain.DistinguishedName)"

Write-Host "`n=== 1. Client side extensions on $GpoName ===" -ForegroundColor Cyan
$cse = [string](Get-ADObject -Identity $dn -Properties gPCMachineExtensionNames).gPCMachineExtensionNames
Write-Host "  $cse" -ForegroundColor Gray

$auditCse = $cse -match '\[\{F3CCC681-B74C-4060-9F26-CD84525DCA2A\}\{0F3F3735-573D-9804-99E4-AB2A69BA5FD4\}\]'
$secCse = $cse -match '\{827D319E-6EAC-11D2-A4EA-00C04F79F83A\}'
$dupes = ([regex]::Matches($cse, '827D319E')).Count

Show 'Audit CSE registered as its own group' $auditCse 'This is the fix. If false, auditcse.dll is never invoked and audit.csv is ignored.'
Show 'Security CSE present' $secCse ''
Show 'Security CSE appears exactly once' ($dupes -eq 1) "Found $dupes occurrence(s). More than one group with the same CSE GUID is malformed."

Write-Host "`n=== 2. Files in SYSVOL ===" -ForegroundColor Cyan
$base = "\\$($env:COMPUTERNAME)\SYSVOL\$($domain.DNSRoot)\Policies\{$($gpo.Id.ToString().ToUpper())}\Machine\Microsoft\Windows NT"
$csv = Join-Path $base 'Audit\audit.csv'
$inf = Join-Path $base 'SecEdit\GptTmpl.inf'

Show 'audit.csv exists' (Test-Path -LiteralPath $csv) $csv
if (Test-Path -LiteralPath $csv) {
    $bytes = [System.IO.File]::ReadAllBytes($csv)
    $bom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    $rows = (Get-Content -LiteralPath $csv | Where-Object { $_.Trim() }).Count - 1
    Show 'audit.csv has no byte order mark' (-not $bom) 'A BOM lands in front of the header and the audit CSE stops parsing.'
    # The upper bound is the real check. There are only about sixty subcategories in Windows, so
    # anything approaching a hundred means the rows were flattened into loose strings again.
    Show 'audit.csv row count is plausible' ($rows -ge 15 -and $rows -le 60) "$rows subcategory rows; over 100 would mean the array flattening is back"
    Write-Host "      first row: $((Get-Content -LiteralPath $csv)[1])" -ForegroundColor DarkGray
}
Show 'GptTmpl.inf exists' (Test-Path -LiteralPath $inf) $inf

Write-Host "`n=== 3. Audit policy as applied right now ===" -ForegroundColor Cyan

# "Some subcategories are on" proves nothing - a domain controller has several on by default and
# audit.csv never switches off what it does not mention. The question is whether every row of the
# deployed file made it through, so compare row by row. auditpol /r emits the same CSV shape.
$appliedCsv = & auditpol.exe /get /category:* /r 2>$null | ConvertFrom-Csv
$wanted = if (Test-Path -LiteralPath $csv) { Import-Csv -LiteralPath $csv } else { @() }

$missing = [System.Collections.Generic.List[string]]::new()
$wrong = [System.Collections.Generic.List[string]]::new()

foreach ($row in $wanted) {
    $guid = $row.'Subcategory GUID'
    $live = $appliedCsv | Where-Object { $_.'Subcategory GUID' -eq $guid } | Select-Object -First 1
    if (-not $live) { $missing.Add($row.Subcategory); continue }
    if ($live.'Inclusion Setting' -ne $row.'Inclusion Setting') {
        $wrong.Add("$($row.Subcategory): want '$($row.'Inclusion Setting')', have '$($live.'Inclusion Setting')'")
    }
}

Show "all $($wanted.Count) deployed subcategories are applied" ($missing.Count -eq 0 -and $wrong.Count -eq 0) `
    "$($appliedCsv.Count) subcategories exist in total; the rest are OS defaults or other GPOs and are left alone"
foreach ($m in $missing) { Write-Host "      not applied: $m" -ForegroundColor Yellow }
foreach ($w in $wrong) { Write-Host "      mismatch:    $w" -ForegroundColor Yellow }

if ($missing.Count -gt 0 -or $wrong.Count -gt 0) {
    Write-Host '      Run gpupdate /force first. If it persists, check the CSE registration above,' -ForegroundColor Yellow
    Write-Host '      then whether the Default Domain Policy still has its own audit.csv - a missing' -ForegroundColor Yellow
    Write-Host '      one there is known to stop advanced auditing domain wide.' -ForegroundColor Yellow
}

# Anything on that the baseline does not cover is worth seeing: it came from somewhere else, and
# on a domain controller that is usually the Default Domain Controllers Policy.
$extra = @($appliedCsv | Where-Object {
        $_.'Inclusion Setting' -notin 'No Auditing', '' -and
        $_.'Subcategory GUID' -notin @($wanted.'Subcategory GUID')
    })
if ($extra.Count -gt 0) {
    Write-Host "  [i] $($extra.Count) further subcategor(ies) are on but not in the baseline:" -ForegroundColor Cyan
    foreach ($e in $extra) { Write-Host "      $($e.Subcategory) - $($e.'Inclusion Setting')" -ForegroundColor DarkGray }
}

Write-Host "`n=== 4. Registry policy values ===" -ForegroundColor Cyan
$checks = @(
    @{ Path = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = 'EnableScriptBlockLogging'; Want = 1 }
    @{ Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name = 'ProcessCreationIncludeCmdLine_Enabled'; Want = 1 }
    @{ Path = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'; Name = 'MaxSize'; Want = 1024000 }
    @{ Path = 'HKLM:\System\CurrentControlSet\Control\Lsa'; Name = 'SCENoApplyLegacyAuditPolicy'; Want = 1 }
)
foreach ($c in $checks) {
    $v = (Get-ItemProperty -Path $c.Path -Name $c.Name -ErrorAction SilentlyContinue).$($c.Name)
    Show "$($c.Name) = $($c.Want)" ("$v" -eq "$($c.Want)") $(if ($null -eq $v) { 'not present' } else { "currently $v" })
}

Write-Host "`n=== 5. PowerShell operational log size ===" -ForegroundColor Cyan

# Two different things, and confusing them wastes an afternoon. The registry value is what policy
# wrote; the number Get-WinEvent reports is what the Event Log service is currently running with.
# The service reads channel configuration when it starts, so a freshly written value shows up in
# the registry immediately and in the running log only after a reboot.
$channelKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Operational'
$want = 268435456

$configured = $null
try { $configured = (Get-ItemProperty -LiteralPath $channelKey -Name MaxSize -ErrorAction Stop).MaxSize } catch { }

$live = (Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational').MaximumSizeInBytes
$liveMb = [math]::Round($live / 1MB, 0)

Show 'MaxSize written to the channel key' ($configured -eq $want) $(
    if ($null -eq $configured) { "not present under WINEVT\Channels - the policy did not land" }
    else { "$configured bytes ($([math]::Round($configured / 1MB, 0)) MB)" })

Show 'Event Log service is running with it' ($live -ge $want) "$liveMb MB in the running service"

if ($configured -eq $want -and $live -lt $want) {
    Write-Host '      Configured but not yet in force. The Event Log service reads channel sizes at' -ForegroundColor Yellow
    Write-Host '      startup and cannot be restarted on its own, so this needs a reboot. Until then' -ForegroundColor Yellow
    Write-Host '      the log still rolls at 15 MB. To confirm without rebooting:' -ForegroundColor Yellow
    Write-Host '          wevtutil gl Microsoft-Windows-PowerShell/Operational' -ForegroundColor Yellow
}
elseif ($null -eq $configured) {
    Write-Host '      Check that the GPO carries the value under Computer Configuration > Preferences' -ForegroundColor Yellow
    Write-Host '      is not where it lives - it is a registry.pol entry outside the Policies branch,' -ForegroundColor Yellow
    Write-Host '      so look at it with: Get-GPRegistryValue -Name ADHardenKit-DC-Logging -Key ' -ForegroundColor Yellow
    Write-Host "          '$($channelKey -replace '^HKLM:', 'HKLM')'" -ForegroundColor Yellow
}
Write-Host ''
