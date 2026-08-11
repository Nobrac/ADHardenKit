# Part of ADHardenKit. Copyright (C) 2026 nopcap.tech
# Licensed under the GNU General Public License v3.0 or later. See LICENSE.

<#
    .SYNOPSIS
    Checks what the ADHardenKit member server GPOs actually did on this machine.

    .DESCRIPTION
    Run this ON the member server, not on a domain controller. It answers, in the order things
    go wrong:

        1. is this machine even in scope   - the GPOs are linked to an OU; a server sitting
                                             somewhere else gets nothing and looks fine doing it
        2. did the policies arrive         - registry values, per group
        3. did the reboot-dependent ones take effect
        4. what is NOT covered             - the per-interface NetBIOS setting reaches domain
                                             controllers only

    Read-only. Run it after gpupdate /force and a reboot.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'

function Show([string]$Text, $Ok, [string]$Detail) {
    # $Ok -eq 'skip' would be TRUE for every $true value: PowerShell casts the right operand to
    # the type of the left one, and [bool]'skip' is $true. Every passing check rendered as
    # skipped. Test the type first.
    $isSkip = ($Ok -is [string]) -and ($Ok -eq 'skip')
    $mark = if ($isSkip) { '[~]' } elseif ($Ok) { '[+]' } else { '[x]' }
    $colour = if ($isSkip) { 'DarkGray' } elseif ($Ok) { 'Green' } else { 'Red' }
    Write-Host ("  {0} {1}" -f $mark, $Text) -ForegroundColor $colour
    if ($Detail) { Write-Host ("      {0}" -f $Detail) -ForegroundColor DarkGray }
}

function Get-Val([string]$Path, [string]$Name) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue).$Name
}

function Check([string]$Label, [string]$Path, [string]$Name, $Want) {
    $v = Get-Val $Path $Name
    $detail = if ($null -eq $v) { 'not present - the policy did not reach this machine' } else { "currently $($v -join ' ')" }
    Show "$Label ($Name = $Want)" ("$($v -join ' ')" -eq "$($Want -join ' ')") $detail
}

Write-Host "`n=== 1. Is this machine in scope? ===" -ForegroundColor Cyan

$dn = $null
try { $dn = ([ADSISearcher]"(&(objectCategory=computer)(cn=$env:COMPUTERNAME))").FindOne().Properties.distinguishedname[0] } catch { }
if ($dn) {
    Write-Host "  $dn" -ForegroundColor Gray
    Show 'Computer object found in the directory' $true ''
}
else {
    Show 'Computer object found in the directory' $false 'Could not query AD - run this as a domain user'
}

$applied = @()
try {
    $xml = [xml](gpresult /x - /scope computer 2>$null)
    $applied = @($xml.Rsop.ComputerResults.GPO | Where-Object { $_.Name -like 'ADHardenKit-*' } | ForEach-Object { $_.Name })
}
catch { }
if ($applied.Count -eq 0) {
    # gpresult /x needs a file on older builds; fall back to the readable form.
    $applied = @((gpresult /r /scope computer 2>$null) -match 'ADHardenKit-' | ForEach-Object { $_.Trim() })
}

Show "ADHardenKit GPOs are applied to this machine" ($applied.Count -gt 0) $(
    if ($applied.Count) { $applied -join ', ' }
    else { 'None found. Either this server is not under the OU the member GPOs are linked to, or gpupdate has not run yet.' })

Write-Host "`n=== 2. Protocols ===" -ForegroundColor Cyan
Check 'LLMNR off' 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0
Check 'NetBIOS off (policy)' 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' 'EnableNetbios' 0
Check 'mDNS off' 'HKLM:\System\CurrentControlSet\Services\Dnscache\Parameters' 'EnableMDNS' 0
Check 'SMBv1 client driver disabled' 'HKLM:\System\CurrentControlSet\Services\mrxsmb10' 'Start' 4
Check 'Workstation no longer depends on SMBv1' 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation' 'DependOnService' @('Bowser', 'MRxSmb20', 'NSI')
Check 'TLS 1.2 server on' 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' 'Enabled' 1
Check 'Point and Print restricted' 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint' 'RestrictDriverInstallationToAdministrators' 1
Check 'Point and Print warning not suppressed' 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint' 'NoWarningNoElevationOnInstall' 0
Check 'WinRM without basic auth' 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service' 'AllowBasic' 0

Write-Host "`n=== 3. Credential protection ===" -ForegroundColor Cyan
Check 'LSA protection (RunAsPPL)' 'HKLM:\System\CurrentControlSet\Control\Lsa' 'RunAsPPL' 1
# Software\Policies\...\System, not the Lsa control key - the ADMX behind "Allow Custom SSPs
# and APs to be loaded into LSASS" is LocalSecurityAuthority.admx and it writes here.
Check 'No custom security packages' 'HKLM:\Software\Policies\Microsoft\Windows\System' 'AllowCustomSSPsAPs' 0
Check 'Local accounts filtered remotely' 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy' 0
Check 'RDP requires NLA' 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' 'UserAuthentication' 1
Check 'RDP security layer is TLS' 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' 'SecurityLayer' 2

Write-Host "`n=== 4. In force, not just configured ===" -ForegroundColor Cyan

# LSA protection: the registry value is policy, the Wininit event is reality.
$ppl = $null
try { $ppl = Get-WinEvent -FilterHashtable @{LogName = 'System'; ProviderName = 'Microsoft-Windows-Wininit'; Id = 12 } -MaxEvents 1 -ErrorAction Stop } catch { }
Show 'LSASS started as a protected process' ($ppl -and $ppl.Message -match 'protected process') $(
    if ($ppl) { "$($ppl.TimeCreated): $($ppl.Message.Trim())" }
    else { 'No Wininit event 12 since the last boot. If RunAsPPL is set above, this machine has not rebooted since.' })

# Credential Guard: 1 = Credential Guard, 2 = HVCI, in the running/configured arrays.
$dg = $null
try { $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop } catch { }
if ($dg) {
    $running = @($dg.SecurityServicesRunning)
    $configured = @($dg.SecurityServicesConfigured)
    Show 'Credential Guard is running' ($running -contains 1) $(
        if ($running -contains 1) { 'Credential dumping from LSASS returns nothing useful' }
        elseif ($configured -contains 1) { 'Configured but not running - needs a reboot, or the hardware requirements are not met' }
        else { 'Not configured on this machine' })
    Show 'Virtualisation based security is running' ($dg.VirtualizationBasedSecurityStatus -eq 2) `
        "VirtualizationBasedSecurityStatus = $($dg.VirtualizationBasedSecurityStatus) (2 means running)"
}
else {
    Show 'Credential Guard state readable' $false 'Win32_DeviceGuard not available - not a supported platform?'
}

# Name resolution listeners - the only proof that matters for those three settings.
$ports = @(netstat -nao 2>$null | Select-String ':5353 |:5355 |:137 ')
Show 'No LLMNR, mDNS or NetBIOS listener' ($ports.Count -eq 0) $(
    if ($ports.Count) { ($ports | ForEach-Object { $_.ToString().Trim() }) -join ' | ' }
    else { 'Ports 137, 5353 and 5355 are all closed' })

Write-Host "`n=== 5. Not covered by Group Policy ===" -ForegroundColor Cyan

# The per-interface NetBIOS setting reaches domain controllers only - by design, because the
# interface keys are named after per-machine GUIDs and no GPO can address them.
$ifaces = @(Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue |
    ForEach-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).NetbiosOptions })
$allOff = $ifaces.Count -gt 0 -and @($ifaces | Where-Object { $_ -ne 2 }).Count -eq 0
Show "NetBIOS disabled on all $($ifaces.Count) interface(s)" $allOff $(
    if ($allOff) { 'Already done on this machine' }
    else { "NetbiosOptions per interface: $($ifaces -join ', ') - 2 means disabled. ADHardenKit only sets this on domain controllers." })
if (-not $allOff) {
    Write-Host '      Run this here, then reboot:' -ForegroundColor Yellow
    Write-Host "        Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object { Set-ItemProperty `$_.PSPath -Name NetbiosOptions -Value 2 }" -ForegroundColor Yellow
}

Write-Host "`n=== 6. Audit policy ===" -ForegroundColor Cyan
$auditRows = @(auditpol.exe /get /category:* /r 2>$null | ConvertFrom-Csv | Where-Object { $_.'Inclusion Setting' -notin 'No Auditing', '' })
Show "Advanced audit policy is active" ($auditRows.Count -ge 15) "$($auditRows.Count) subcategories with auditing on (the member baseline deploys 19)"
Write-Host ''
