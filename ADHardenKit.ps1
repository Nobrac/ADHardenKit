# ADHardenKit - hardens the protocol layer of an Active Directory domain.
# Copyright (C) 2026 nopcap.tech
#
# This program is free software: you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program.
# If not, see <https://www.gnu.org/licenses/>.

<#
    .SYNOPSIS
    Hardens the protocol layer of an Active Directory domain: signing, credential exposure,
    legacy authentication and audit logging.

    .DESCRIPTION
    A companion to ADTierKit. Where that one draws the tier boundary, this one hardens what sits
    underneath it - LDAP and SMB signing, NTLM, Kerberos encryption, LSA protection, Credential
    Guard, and an audit policy that actually records what happened.

    Settings are grouped by what they do, and every group becomes its own Group Policy object per
    role - so up to twelve small GPOs rather than two large ones:

        ADHardenKit-DC-Signing                  ADHardenKit-Member-Signing
        ADHardenKit-DC-LegacyAuth               ADHardenKit-Member-LegacyAuth
        ADHardenKit-DC-CredentialProtection     ADHardenKit-Member-CredentialProtection
        ADHardenKit-DC-Protocols                ADHardenKit-Member-Protocols
        ADHardenKit-DC-Logging                  ADHardenKit-Member-Logging
        ADHardenKit-DC-Services

    That is deliberate. When SMB signing turns out to have been holding up a NAS, you unlink one
    GPO named Signing and everything else stays in force. With one big GPO the only lever is all
    or nothing, and under pressure people pick nothing.

    Domain controllers and member servers get different GPOs because the roles need different
    settings - Credential Guard, for one, has no place on a domain controller.

    THE POINT OF THIS TOOL IS THE ORDER OF OPERATIONS

    Almost every setting here can break something that used to work, and the breakage tends to
    surface far away from the cause. Requiring LDAP signing and a print server stops finding the
    directory. Enforcing SMB signing and a NAS drops out. Restricting NTLM and some line-of-
    business application stalls.

    Every setting that carries that risk is marked as staged, and staged settings have two levels:

        -Level Audit      turn on the observation that shows you who would break
        -Level Enforce    actually require it

    Run Scan first. It reads what the domain is doing today - unsigned LDAP binds from the
    directory service log, NTLM usage from the operational log, current effective values - and
    tells you which settings are safe to enforce and which need watching.

    On a domain that has never been watched, the first Scan will mostly report that it cannot see
    anything, because the diagnostics that produce the evidence are off by default. That is what
    the Logging group is for, and why it is the one to deploy first:

        .\ADHardenKit.ps1 -Mode Deploy -Area Logging -Apply

    It turns on LDAP interface diagnostics, NTLM auditing in both directions, the advanced audit
    policy and the log sizes to hold the result. Every one of those only writes records - nothing
    in that group can refuse an authentication or block a connection, so it can be deployed on a
    Friday. Then wait. A full business cycle including month-end, because the client that only
    binds unsigned during the monthly billing run is exactly the one that will be missed.

    Only then does Scan have anything to report, and only then is Level Enforce a decision rather
    than a guess.

    .PARAMETER Mode
      Scan         read-only. Reads the current state, the event logs and the directory, and
                   reports what would break if the staged settings were enforced today.
      Deploy       creates and links the GPOs. Plans by default, writes only with -Apply.
      Audit        read-only drift report against the selected profile.
      Check        prerequisites only.

    .PARAMETER Profile
      Baseline     settings with little or no compatibility risk. The default.
      Strict       adds the ones that need a maintenance window and a rollback plan.

    .PARAMETER Level
      Audit        staged settings are deployed in their observation form. The default.
      Enforce      staged settings are deployed in their enforcing form.

    .PARAMETER Area
    Restrict the run to some of the setting groups: Signing, LegacyAuth, CredentialProtection,
    Protocols, PolicyIntegrity, Logging, Services. Each group becomes its own GPO per role, so a group that turns
    out to break something can be unlinked on its own without losing the rest.

    .PARAMETER Apply
    Deploy mode only. Without it nothing is written.

    .PARAMETER Interactive
    Present every setting before it is deployed - what it does, what it might break, and the
    Microsoft article or CVE number to look it up - and deploy only the ones confirmed. Answering
    A or S applies one decision to everything remaining, because a prompt nobody can dismiss is a
    prompt nobody reads. Without this switch the run is unattended, which is what a scheduled task
    needs.

    .PARAMETER HardeningProfile
    Baseline or Strict. Baseline carries little or no compatibility risk; Strict adds the settings
    that need a maintenance window - TLS 1.0/1.1 and the weak ciphers off, NTLM restriction, the
    Kerberos encryption types, cached logon counts. Aliased as -Profile.

    .PARAMETER Server
    Domain controller to read from and write to. Defaults to the PDC emulator, so a run that is
    interrupted and repeated targets the same server rather than whichever one answers.

    .PARAMETER GpoNamePattern
    Naming scheme for the GPOs, with the placeholders {ROLE} and {GROUP}. Default
    ADHardenKit-{ROLE}-{GROUP}, giving names like ADHardenKit-DC-Signing.

    .PARAMETER ScanDays
    How far back Scan reads the event logs. Default 30.

    .PARAMETER LogDirectory
    Where the per-run transcript goes. Default .\Logs

    .PARAMETER ReportDirectory
    Where the JSON and HTML reports go. Default .\Reports

    .PARAMETER NoEventLog
    Skip the event log analysis in Scan mode. Useful on a domain controller where the logs are
    large enough that reading them takes longer than the rest of the run.

    .PARAMETER MemberServerOu
    Distinguished name of the OU the member server GPOs are linked to. Without it they are created
    and fully populated but left unlinked, and the run says so. The domain controller GPOs always
    link to the Domain Controllers container, which the tool reads from the directory rather than
    assuming its name.

    .PARAMETER Force
    Proceed even when Scan found evidence that enforcing would break something, and skip the
    confirmation that an unattended -Apply otherwise asks for. Needed for a scheduled task that
    runs on a console-less host only if that host reports itself as interactive; otherwise the
    confirmation is skipped automatically.

    .PARAMETER NoMenu
    Started without any parameters on an interactive console, the script shows a menu instead of
    running a scan. This switch suppresses the menu for the one case that is otherwise ambiguous:
    a scheduled task or pipeline that deliberately runs the default scan with no other parameters.
    Every invocation that passes any parameter at all already behaves as before.

    .EXAMPLE
    .\ADHardenKit.ps1

    On a console with no parameters: the menu. Walks through what to do, which profile, level and
    groups, whether to confirm each topic, and plan versus apply - then prints the equivalent
    command line before running, so the menu doubles as a way of learning the parameters.

    .EXAMPLE
    .\ADHardenKit.ps1 -Mode Scan

    Reads the current state and the event logs. Changes nothing. Start here.

    .EXAMPLE
    .\ADHardenKit.ps1 -Mode Deploy -Apply

    Deploys the baseline with staged settings in observation mode.

    .EXAMPLE
    .\ADHardenKit.ps1 -Mode Deploy -Profile Strict -Level Enforce -Apply

    The full set, enforcing. Do this after Scan has been clean for a few weeks.

    .EXAMPLE
    .\ADHardenKit.ps1 -Mode Deploy -Interactive -Apply

    Walks through every setting one at a time with its explanation, its likely blast radius and a
    Microsoft article number, and deploys only what is confirmed. This is the one to use the first
    time, and the one to use when handing the change to someone who has to sign it off.

    .EXAMPLE
    .\ADHardenKit.ps1 -Mode Deploy -Area Logging -Apply

    Only the logging group. Useful as a first step: it changes what is recorded, not what is
    allowed, so nothing can stop working.

    Exit codes: 0 success, 1 failures, 2 drift found, 3 prerequisites failed,
    4 enforcing would break something that is still in use.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Scan', 'Deploy', 'Audit', 'Check')]
    [string]$Mode = 'Scan',

    # Not named -Profile: $PROFILE is a PowerShell automatic variable holding the path to the
    # user's profile script, and shadowing it inside a script is a debugging trap.
    [ValidateSet('Baseline', 'Strict')]
    [Alias('Profile')]
    [string]$HardeningProfile = 'Baseline',

    [ValidateSet('Audit', 'Enforce')]
    [string]$Level = 'Audit',

    [ValidateSet('Signing', 'LegacyAuth', 'CredentialProtection', 'Protocols', 'PolicyIntegrity', 'Logging', 'Services')]
    [string[]]$Area = @('Signing', 'LegacyAuth', 'CredentialProtection', 'Protocols', 'PolicyIntegrity', 'Logging', 'Services'),

    [string]$Server,

    # One GPO per group and role. {ROLE} becomes DC or Member, {GROUP} the setting group.
    [string]$GpoNamePattern = 'ADHardenKit-{ROLE}-{GROUP}',

    [string]$MemberServerOu,

    [ValidateRange(1, 365)]
    [int]$ScanDays = 30,

    [string]$LogDirectory,

    [string]$ReportDirectory,

    [switch]$Apply,

    [switch]$Interactive,

    [switch]$NoEventLog,

    [switch]$Force,

    [switch]$NoMenu
)

# Bumped whenever the baseline or a mechanism changes. Printed on every run and carried into the
# report, so "which version produced this" is answerable from a pasted log rather than guessed at.
$script:HardenKitVersion = '1.2.0'

$ErrorActionPreference = 'Stop'

# $PSScriptRoot is not reliably populated while parameter defaults are bound - under a scheduled
# task it comes out empty and Join-Path throws before anything has been logged.
$scriptRoot = $PSScriptRoot
if (-not $scriptRoot -and $MyInvocation.MyCommand.Path) { $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $scriptRoot) { $scriptRoot = (Get-Location).Path }
if (-not $LogDirectory) { $LogDirectory = Join-Path $scriptRoot 'Logs' }
if (-not $ReportDirectory) { $ReportDirectory = Join-Path $scriptRoot 'Reports' }

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

$script:LogFile = $null
$script:Actions = [System.Collections.Generic.List[object]]::new()
$script:Context = $null
# Not $script:Interactive: a script parameter lives in script scope, so that name would be the
# -Interactive switch itself and this line would silently overwrite whatever the caller passed.
$script:InteractiveMode = $false
$script:AutoDecision = $null
$script:DecisionCache = @{}
$script:LiveCache = @{}
$script:ScopeBaseline = @()
$script:ScopeAuditPolicy = @()

####################################################################################################
#region Core
####################################################################################################

function Initialize-HardenLog {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LogDirectory)

    if (-not (Test-Path -LiteralPath $LogDirectory)) {
        New-Item -Path $LogDirectory -ItemType Directory -Force -WhatIf:$false -Confirm:$false | Out-Null
    }
    $script:LogFile = Join-Path $LogDirectory ("ADHardenKit-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    Write-HardenLog -Message "Log started - $((Get-Date).ToString('o'))" -Level Info
    return $script:LogFile
}

function Write-HardenLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Skip', 'Header')][string]$Level = 'Info'
    )

    $prefix = switch ($Level) {
        'Success' { '  [+] ' }
        'Warning' { '  [!] ' }
        'Error' { '  [x] ' }
        'Skip' { '  [=] ' }
        'Header' { '' }
        default { '  [i] ' }
    }
    $colour = switch ($Level) {
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
        'Skip' { 'DarkGray' }
        'Header' { 'Cyan' }
        default { 'Gray' }
    }

    if ($Level -eq 'Header') {
        Write-Host ''
        Write-Host "=== $Message ===" -ForegroundColor $colour
    }
    else {
        Write-Host "$prefix$Message" -ForegroundColor $colour
    }

    if ($script:LogFile) {
        $line = '{0} [{1,-7}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level.ToUpper(), $Message
        Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 -WhatIf:$false -Confirm:$false
    }
}

function Add-HardenAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Setting,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][ValidateSet('Created', 'Updated', 'Compliant', 'Planned', 'Failed', 'Missing', 'Drift', 'Observed', 'Skipped')][string]$Result,
        [string]$Detail,
        [ValidateSet('High', 'Medium', 'Low', 'Info')][string]$Severity = 'Info'
    )

    $script:Actions.Add([pscustomobject]@{
            Timestamp = (Get-Date).ToString('o')
            Area      = $Area
            Setting   = $Setting
            Target    = $Target
            Result    = $Result
            Severity  = $Severity
            Detail    = $Detail
        })
}

function Initialize-HardenContext {
    [CmdletBinding()]
    param([string]$Server)

    $adParams = @{}
    if ($Server) { $adParams['Server'] = $Server }

    $domain = Get-ADDomain @adParams
    $dc = if ($Server) { $Server } else { (Get-ADDomainController -Discover -Service PrimaryDC).HostName[0] }

    $script:Context = [pscustomobject]@{
        Domain              = $domain
        DomainFqdn          = $domain.DNSRoot
        DomainDn            = $domain.DistinguishedName
        DomainNetBios       = $domain.NetBIOSName
        DomainSid           = $domain.DomainSID.Value
        DomainControllersDn = $domain.DomainControllersContainer
        Server              = $dc
        # Deliberately the server, not the domain namespace. The AD attributes are written to
        # one specific DC; if the files went to \\domain\SYSVOL the DFS referral could land on a
        # different one, and until replication catches up the GPO has a version number pointing
        # at files that are not there yet.
        SysvolPolicyPath    = "\\$dc\SYSVOL\$($domain.DNSRoot)\Policies"
    }
    return $script:Context
}

function Get-HardenContext {
    if (-not $script:Context) { throw 'Context not initialised.' }
    return $script:Context
}

function Get-HardenAdParameter {
    $ctx = Get-HardenContext
    $p = @{}
    if ($ctx.Server) { $p['Server'] = $ctx.Server }
    return $p
}

function Test-HardenPrerequisite {
    <#
        .SYNOPSIS
        Verifies everything the deployment depends on, and returns whether it is safe to proceed.
    #>
    [CmdletBinding()]
    param()

    Write-HardenLog -Message 'Prerequisite check' -Level Header

    $checks = [System.Collections.Generic.List[object]]::new()

    $checks.Add([pscustomobject]@{
            Name = 'PowerShell version'
            Pass = $PSVersionTable.PSVersion.Major -ge 5
            Detail = "Running PowerShell $($PSVersionTable.PSVersion)"
        })

    foreach ($m in 'ActiveDirectory', 'GroupPolicy') {
        $mod = Get-Module -Name $m
        $checks.Add([pscustomobject]@{
                Name = "Module $m"
                Pass = $null -ne $mod
                Detail = if ($mod) { "Version $($mod.Version)" } else { 'not loaded' }
            })
    }

    $identity = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    $elevated = $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $checks.Add([pscustomobject]@{
            Name = 'Elevation'
            Pass = $elevated
            Detail = if ($elevated) { 'Session is elevated' } else { 'Run as administrator' }
        })

    try {
        $ctx = Get-HardenContext
        $checks.Add([pscustomobject]@{ Name = 'Directory connectivity'; Pass = $true; Detail = "Connected to $($ctx.Server)" })
        $sysvol = Test-Path -LiteralPath $ctx.SysvolPolicyPath
        $checks.Add([pscustomobject]@{ Name = 'SYSVOL access'; Pass = $sysvol; Detail = $ctx.SysvolPolicyPath })

        # Functional level and schema, because a registry value is not the only thing a setting
        # can depend on. Almost everything here is delivered as policy and works at any level,
        # but Kerberos armoring is negotiated by the directory: below domain functional level
        # 2012 the KDC accepts the setting and behaves as though it were Supported, whichever
        # level is configured. Reported rather than enforced - a domain that cannot raise its
        # level still benefits from the other ninety settings.
        $ad = Get-HardenAdParameter
        $domain = Get-ADDomain @ad -ErrorAction Stop
        $forest = Get-ADForest @ad -ErrorAction SilentlyContinue

        $schema = 'unknown'
        try {
            $sv = (Get-ADObject -Identity "CN=Schema,CN=Configuration,$($domain.DistinguishedName -replace '^.*?(DC=.*)$', '$1')" -Properties objectVersion @ad -ErrorAction Stop).objectVersion
            $schema = switch ([int]$sv) {
                87 { "$sv (Server 2016)" }
                88 { "$sv (Server 2019 or 2022)" }
                90 { "$sv (Server 2025)" }
                default { "$sv" }
            }
        }
        catch { }

        $levelText = "Domain $($domain.DomainMode), forest $(if ($forest) { $forest.ForestMode } else { 'unknown' }), schema $schema"

        # Everything from Windows2012Domain upward sorts after Windows2008R2Domain as a string,
        # which is not something to rely on - match the known older names instead.
        $preArmoring = "$($domain.DomainMode)" -in 'Windows2000Domain', 'Windows2003Domain', 'Windows2008Domain', 'Windows2008R2Domain'
        $checks.Add([pscustomobject]@{
                Name = 'Functional level'
                Pass = $true
                Detail = if ($preArmoring) { "$levelText - below 2012, so Kerberos armoring will deploy but stay at Supported whatever level is set" }
                else { $levelText }
            })
    }
    catch {
        $checks.Add([pscustomobject]@{ Name = 'Directory connectivity'; Pass = $false; Detail = $_.Exception.Message })
    }

    foreach ($c in $checks) {
        Write-HardenLog -Message "$($c.Name) - $($c.Detail)" -Level $(if ($c.Pass) { 'Success' } else { 'Error' })
    }

    # One expression decides the outcome, rather than a flag written from three different scopes.
    return -not ($checks | Where-Object { -not $_.Pass })
}

#endregion Core

####################################################################################################
#region Baseline
####################################################################################################

function Get-HardenBaseline {
    <#
        .SYNOPSIS
        The curated list of settings, as data.

        .DESCRIPTION
        Each entry carries what it is, where it applies, how risky it is, and - for the staged
        ones - both an observation value and an enforcing value. Nothing here is invented on the
        fly; changing the hardening means changing this table.

        Type
            SecurityOption  written into GptTmpl.inf [Registry Values]. This is the mechanism the
                            GPMC calls Security Options, and it is what these settings expect.
            AdminTemplate   written through Set-GPRegistryValue. Ordinary policy registry values.
            AuditPolicy     written into audit.csv as Advanced Audit Policy Configuration.
            Service         written into GptTmpl.inf [Service General Setting].

        Target      DC, Member or Both
        Profile     Baseline or Strict
        Staged      the setting carries risk and is rolled out in two steps. AuditValue holds the
                    observation form where one exists. Where it does not - SMB signing is either
                    required or it is not - AuditValue is $null and the setting is left out
                    entirely at Level Audit. It must never hold the off value: writing that would
                    turn a machine that is already correct into one that is not, and call it a
                    staged rollout.
        Observe     where to look to see whether enforcing would break something
        Topic       the question a person is actually deciding - "SMB signing", not four registry
                    values. Interactive mode asks once per topic; entries sharing one live or die
                    together, which matches how they behave anyway.
        Reference   Microsoft article, advisory or CVE number to search for. Numbers only and no
                    links, because links rot and a number can be pasted into any search box years
                    from now.
        MinOS       the oldest Windows version that reads this value. Older systems accept the
                    policy, apply it, and ignore it - no error anywhere, which is the failure mode
                    this tool exists to catch rather than produce. Stated so the card and the
                    report can say it out loud.
        NeedsReboot the value is written immediately but the component only reads it at startup,
                    so the setting is not in force until the machine restarts. Worth stating,
                    because verifying such a setting on the running system shows the old value and
                    looks exactly like a failed deployment.
        DefaultWhenUnset
                    what Windows does when the value is absent from the registry. Only present
                    where the behaviour is documented. Deploying the setting anyway is still
                    worthwhile - it makes the intent explicit and survives someone changing it -
                    but a Scan must not report an absent value as a gap when the platform default
                    already matches, or the report fills with findings nobody needs to act on.
    #>
    [CmdletBinding()]
    param()

    $s = [System.Collections.Generic.List[object]]::new()

    # -- Signing and channel binding ------------------------------------------------------------
    $s.Add([ordered]@{
            Id = 'LDAP-ServerSigning'; Topic = 'LDAP signing and channel binding'; Reference = 'KB4520412, ADV190023, CVE-2017-8563'; Group = 'Signing'; Name = 'LDAP server requires signing'
            Type = 'SecurityOption'; Target = 'DC'; Profile = 'Baseline'; Staged = $true
            Key = 'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity'
            ValueType = 4; AuditValue = 1; EnforceValue = 2
            Why = 'An unsigned LDAP bind can be relayed. Requiring signing closes that, but any client that binds without signing stops working.'
            Observe = 'Directory Service log, event 2889 names every client that bound without signing. 2886 and 2887 summarise.'
        })

    $s.Add([ordered]@{
            Id = 'LDAP-ChannelBinding'; Topic = 'LDAP signing and channel binding'; Reference = 'KB4520412, KB4563239, ADV190023'; Group = 'Signing'; Name = 'LDAP channel binding'
            Type = 'SecurityOption'; Target = 'DC'; Profile = 'Baseline'; Staged = $true
            Key = 'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding'
            ValueType = 4; AuditValue = 1; EnforceValue = 2
            Why = 'Binds LDAPS to the TLS channel so a relayed authentication cannot be reused. Value 1 requires it only from clients that support it, 2 from everyone.'
            Observe = 'Directory Service log, event 3039 names clients that failed channel binding.'
        })

    $s.Add([ordered]@{
            Id = 'SMB-AuditServerSigning'; MinOS = 'Server 2008 R2'; Topic = 'SMB audit'; Group = 'Signing'
            Name = 'Log clients that connect without signing'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows\LanmanServer'
            Values = @(
                @{ Name = 'AuditClientDoesNotSupportSigning'; Type = 'DWord'; Value = 1 }
                @{ Name = 'AuditClientDoesNotSupportEncryption'; Type = 'DWord'; Value = 1 }
            )
            Why = 'This is the missing half of the SMB signing story. Requiring signing is the setting that can take a NAS or an appliance off the network, and until now the only way to find out in advance was a manual Set-SmbServerConfiguration on every server. There is a policy for it, and it belongs in the same GPO as the thing it observes: every client that connects to this machine without signing is written to SMBServer/Audit as event 3000, by name.'
            Observe = 'Records only, refuses nothing - safe to deploy anywhere at any time, and the right first step before the required-signing settings in this group. The encryption half needs Server 2025 or Windows 11 and is ignored on older builds; the signing half works back to Server 2008 R2.'
        })

    $s.Add([ordered]@{
            Id = 'SMB-AuditClientSigning'; MinOS = 'Server 2025'; Topic = 'SMB audit'; Group = 'Signing'
            Name = 'Log servers reached that cannot sign'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation'
            Values = @(
                @{ Name = 'AuditServerDoesNotSupportSigning'; Type = 'DWord'; Value = 1 }
                @{ Name = 'AuditServerDoesNotSupportEncryption'; Type = 'DWord'; Value = 1 }
            )
            Why = 'The outbound direction. Every server this machine connected to that could not sign lands in SMBClient/Connectivity as event 31998 - which is how a backup job pointed at an old appliance is found before, rather than after, client signing is required.'
        })

    $s.Add([ordered]@{
            Id = 'SMB-AuditGuest'; MinOS = 'Server 2025'; Topic = 'SMB audit'; Group = 'Signing'
            Name = 'Log insecure guest logons'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation'
            Values = @(@{ Name = 'AuditInsecureGuestLogon'; Type = 'DWord'; Value = 1 })
            Why = 'Guest access to SMB is unauthenticated and unsigned, so anything relying on it can be redirected. The guest fallback is already refused elsewhere in this baseline; this records who was still trying, which is the list of shares that need fixing rather than blaming.'
            Observe = 'Server 2025 and Windows 11 only.'
        })

    $s.Add([ordered]@{
            Id = 'SMB-ServerSigningRequired'; Topic = 'SMB signing'; Group = 'Signing'; Name = 'SMB server requires signing'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $true
            Key = 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature'
            # No AuditValue: SMB signing has no observation form in this key - it is either
            # required or it is not. A zero here would not observe anything, it would switch off
            # signing that is already required, which on a domain controller is a regression
            # dressed up as a staged rollout. Absent means the setting is simply not deployed at
            # Level Audit; the observation happens in the SMBServer audit log instead.
            ValueType = 4; AuditValue = $null; EnforceValue = 1
            Why = 'Without server-side signing an SMB session can be relayed. Domain controllers require it by default; member servers usually do not.'
            Observe = 'The observation form is a separate policy, deployed by the SMB audit topic in this same group: it logs every client that connected without signing, to SMBServer/Audit event 3000. Deploy that, read the log for a cycle, then come back here. Old NAS devices and appliances are the usual casualties.'
        })

    $s.Add([ordered]@{
            Id = 'SMB-ClientSigningRequired'; Topic = 'SMB signing'; Group = 'Signing'; Name = 'SMB client requires signing'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Strict'; Staged = $true
            Key = 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature'
            # Same reasoning as the server side: absent rather than zero.
            ValueType = 4; AuditValue = $null; EnforceValue = 1
            Why = 'Stops the server from talking to a file server that will not sign - which is also how it breaks a backup job pointed at an old appliance.'
            Observe = 'The observation form is a separate policy, deployed by the SMB audit topic in this same group - it records every server this machine reached that could not sign, to SMBClient/Connectivity event 31998. A backup job pointed at an old appliance is the classic find.'
        })

    $s.Add([ordered]@{
            Id = 'SMB-ServerSigningEnabled'; Topic = 'SMB signing'; Group = 'Signing'; Name = 'SMB server signing offered'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature'
            ValueType = 4; EnforceValue = 1
            Why = 'Offering signing costs nothing and breaks nothing. It only means signing is used when the other side also wants it.'
        })

    $s.Add([ordered]@{
            Id = 'Netlogon-RequireSignOrSeal'; Topic = 'Netlogon secure channel'; Reference = 'CVE-2020-1472, KB4557222'; Group = 'Signing'; Name = 'Netlogon secure channel: sign or seal'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal'
            ValueType = 4; EnforceValue = 1
            Why = 'The secure channel between a member and its DC must be signed or sealed. Enforced by default since the Zerologon patches; setting it explicitly means a rebuilt machine cannot end up without it.'
        })

    # -- Legacy authentication ------------------------------------------------------------------
    $s.Add([ordered]@{
            Id = 'LM-CompatibilityLevel'; Topic = 'NTLM version and session security'; Group = 'LegacyAuth'; Name = 'NTLMv2 only, refuse LM and NTLM'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel'
            ValueType = 4; EnforceValue = 5
            Why = 'LM and NTLMv1 responses are trivially crackable. Level 5 sends NTLMv2 only and refuses the older ones. Anything still using NTLMv1 in 2026 needs replacing, not accommodating.'
            Observe = 'Scan reports accounts still authenticating with NTLMv1.'
        })

    $s.Add([ordered]@{
            Id = 'NoLMHash'; Topic = 'NTLM version and session security'; Reference = 'KB299656'; DefaultWhenUnset = 1; Group = 'LegacyAuth'; Name = 'Do not store the LM hash'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash'
            ValueType = 4; EnforceValue = 1
            Why = 'Default since Server 2008, but a domain upgraded from further back can still carry stored LM hashes.'
        })

    $s.Add([ordered]@{
            Id = 'NTLM-AuditIncoming'; Topic = 'NTLM auditing'; Group = 'Logging'; Name = 'Audit incoming NTLM traffic'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\AuditReceivingNTLMTraffic'
            ValueType = 4; EnforceValue = 2
            Why = 'Pure observation, no enforcement. Writes every incoming NTLM authentication to the NTLM operational log so you can find out who still needs it.'
            Observe = 'Applications and Services > Microsoft > Windows > NTLM > Operational, event 8004.'
        })

    $s.Add([ordered]@{
            Id = 'NTLM-AuditDomainTraffic'; Topic = 'NTLM auditing'; Group = 'Logging'; Name = 'Audit NTLM authentication in this domain'
            Type = 'SecurityOption'; Target = 'DC'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\AuditNTLMInDomain'
            ValueType = 4; EnforceValue = 7
            Why = 'The domain controller side of the same observation. Records NTLM authentication attempts that pass through this DC.'
            Observe = 'NTLM operational log on the domain controllers, event 8004.'
        })

    $s.Add([ordered]@{
            Id = 'NTLM-RestrictOutgoing'; Topic = 'NTLM restriction'; Group = 'LegacyAuth'; Name = 'Deny outgoing NTLM to remote servers'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Strict'; Staged = $true
            Key = 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic'
            ValueType = 4; AuditValue = 1; EnforceValue = 2
            Why = 'The single most effective control against relay, and the single most likely to break a line-of-business application. Value 1 audits, 2 denies.'
            Observe = 'NTLM operational log, event 8001 lists every outgoing NTLM authentication that would be blocked.'
        })

    $s.Add([ordered]@{
            Id = 'Kerberos-ArmoringKdc'; MinOS = 'Server 2012'; Topic = 'Kerberos armoring'; Group = 'LegacyAuth'
            Name = 'KDC advertises claims and armoring'
            Type = 'AdminTemplate'; Target = 'DC'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters'
            Values = @(
                @{ Name = 'EnableCbacAndArmor'; Type = 'DWord'; Value = 1 }
                @{ Name = 'CbacAndArmorLevel'; Type = 'DWord'; Value = 0 }
            )
            Why = 'Kerberos armoring is Microsoft implementation of FAST: it encrypts the Kerberos exchange itself and signs the errors, which removes the offline attack on AS-REP material. On its own that is worth having. The larger reason to turn it on early is that Authentication Policies - the mechanism that says a tier 0 account may only obtain a ticket from a tier 0 machine - do not work without it. Enabling armoring is the cheap step; needing it later and not having it is the expensive one.'
            Observe = 'Deployed at level 0, Supported: the KDC advertises the capability and uses it with clients that can, and nothing is refused. That is enough for Authentication Policies and breaks nothing. Level 1, Always provide claims, adds claims to every ticket and grows them - check MaxTokenSize before going there. Level 2, Fail unarmored authentication requests, is the end state and refuses any client that cannot armor; below domain functional level 2012 both behave as Supported anyway. Raise the level by hand once the client side below is deployed everywhere and the Kerberos operational log stays quiet.'
        })

    $s.Add([ordered]@{
            Id = 'Kerberos-ArmoringClient'; MinOS = 'Server 2012'; Topic = 'Kerberos armoring'; Group = 'LegacyAuth'
            Name = 'Kerberos client supports claims and armoring'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
            Values = @(@{ Name = 'EnableCbacAndArmor'; Type = 'DWord'; Value = 1 })
            Why = 'The other half. A KDC that offers armoring and clients that never ask for it is the same as no armoring at all - the KDC setting alone changes nothing.'
            Observe = 'Target is Both, and the domain controllers are deliberately included: a DC is also a Kerberos client, and leaving this off there is the mistake that gets made most often. Needs Windows 8 or Server 2012 and later; older systems ignore it.'
        })

    $s.Add([ordered]@{
            Id = 'Kerberos-AesOnly'; Topic = 'Kerberos encryption types'; Reference = 'KB5021131, CVE-2022-37966, CVE-2026-20833'; Group = 'LegacyAuth'; Name = 'Kerberos: AES only, no RC4'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Strict'; Staged = $true
            Key = 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes'
            ValueType = 4; AuditValue = 2147483644; EnforceValue = 2147483640
            Why = '0x7FFFFFF8 is AES128, AES256 and the reserved future types, with DES and RC4 left out. Plain 0x18 would also work today but drops the future bits, so a machine that learns a new encryption type in a later build would refuse to use it. The audit form 0x7FFFFFFC keeps RC4 available while the AES rollout is verified.'
            Observe = 'Changing this does not take effect until the password changes: the keys are derived from the cleartext password when it is set, so an account whose password predates the change still only has the old key material. Plan a password rotation for service accounts alongside it, and note that an account left with only RC4 keys cannot obtain a ticket at all once RC4 is disallowed. Windows also translates the registry value back when it writes msDS-SupportedEncryptionTypes into the directory, so 0x7FFFFFF8 on the machine shows up as 0x18 on the object - that is expected. Scan lists accounts whose msDS-SupportedEncryptionTypes still allows RC4. Note that this is only the member-side policy; since the January 2026 update the KDC side is governed by DefaultDomainSupportedEncTypes, which now defaults to 0x18, and RC4DefaultDisablementPhase stopped being read with the July 2026 updates.'
        })

    $s.Add([ordered]@{
            Id = 'Kdc-StrongCertificateBinding'; Topic = 'Certificate binding for Kerberos'; Reference = 'KB5014754, CVE-2022-26931, CVE-2022-26923'; Group = 'LegacyAuth'; Name = 'Strong certificate binding for Kerberos'
            Type = 'SecurityOption'; Target = 'DC'; Profile = 'Baseline'; Staged = $true
            Key = 'MACHINE\System\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement'
            ValueType = 4; AuditValue = 1; EnforceValue = 2
            Why = 'Weak certificate mapping lets a certificate be bound to the wrong account. Value 1 is compatibility mode with logging, 2 is full enforcement.'
            Observe = 'System log on the domain controllers, events 39, 40 and 41 name certificates with a weak mapping.'
        })

    # -- Credential exposure --------------------------------------------------------------------
    $s.Add([ordered]@{
            Id = 'LSA-RunAsPPL'; Topic = 'LSA protection'; NeedsReboot = $true; Group = 'CredentialProtection'; Name = 'LSA protection (RunAsPPL)'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Control\Lsa\RunAsPPL'
            ValueType = 4; EnforceValue = 1
            Why = 'Runs LSASS as a protected process so ordinary credential dumping fails. This is the domain controller equivalent of Credential Guard, which is not appropriate on a DC.'
            Observe = 'Requires a reboot. A driver or security agent that hooks LSASS may stop loading - check the System log for event 3033 or 3063 afterwards.'
        })

    $s.Add([ordered]@{
            Id = 'WDigest-Disabled'; Topic = 'Credential caching'; Reference = 'KB2871997'; DefaultWhenUnset = 0; Group = 'CredentialProtection'; Name = 'WDigest does not cache plaintext'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
            ValueType = 4; EnforceValue = 0
            Why = 'WDigest kept the plaintext password in memory. Off by default since 2012 R2, but an inherited registry value can switch it back on and nobody notices.'
        })

    $s.Add([ordered]@{
            Id = 'Anon-RestrictAnonymous'; Topic = 'Anonymous access'; Group = 'CredentialProtection'; Name = 'No anonymous enumeration of shares'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous'
            ValueType = 4; EnforceValue = 1
            Why = 'Blocks a null session from listing shares and account policy.'
        })

    $s.Add([ordered]@{
            Id = 'Anon-RestrictAnonymousSAM'; Topic = 'Anonymous access'; Group = 'CredentialProtection'; Name = 'No anonymous enumeration of SAM accounts'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM'
            ValueType = 4; EnforceValue = 1
            Why = 'Stops a null session enumerating account names, which is the first step of a password spray with a valid user list.'
        })

    $s.Add([ordered]@{
            Id = 'Anon-EveryoneIncludesAnonymous'; Topic = 'Anonymous access'; DefaultWhenUnset = 0; Group = 'CredentialProtection'; Name = 'Anonymous is not Everyone'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous'
            ValueType = 4; EnforceValue = 0
            Why = 'Without this, an anonymous session inherits everything granted to Everyone.'
        })

    $s.Add([ordered]@{
            Id = 'Anon-RestrictRemoteSam'; Topic = 'Anonymous access'; Group = 'CredentialProtection'; Name = 'Restrict remote SAM enumeration'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSam'
            ValueType = 1
            EnforceValue = 'O:BAG:BAD:(A;;RC;;;BA)'
            Why = 'Only administrators may query the SAM remotely. This is what stops a normal user enumerating local group membership across the estate, which is how attack paths get mapped.'
            Observe = 'A domain controller restricts remote SAM to administrators regardless - the DISA STIG marks this check not applicable on DCs for that reason. Setting it explicitly still has value on member servers, where an absent value means no restriction at all.'
        })

    # -- Administrative templates (registry policy) ---------------------------------------------
    $s.Add([ordered]@{
            Id = 'CredentialGuard'; MinOS = 'Server 2016'; Topic = 'Credential Guard and VBS'; NeedsReboot = $true; Group = 'CredentialProtection'; Name = 'Credential Guard with VBS'
            Type = 'AdminTemplate'; Target = 'Member'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows\DeviceGuard'
            Values = @(
                @{ Name = 'EnableVirtualizationBasedSecurity'; Type = 'DWord'; Value = 1 }
                @{ Name = 'RequirePlatformSecurityFeatures'; Type = 'DWord'; Value = 1 }
                @{ Name = 'LsaCfg'; Type = 'DWord'; Value = 1 }
            )
            Why = 'Isolates NTLM hashes and Kerberos tickets from LSASS so credential dumping returns nothing useful. Member servers only - Microsoft documents that it adds no security on a domain controller and can cause compatibility problems there.'
            Observe = 'Needs virtualisation support and Secure Boot. Verify afterwards with Get-CimInstance Win32_DeviceGuard.'
        })

    $s.Add([ordered]@{
            Id = 'LLMNR-Disabled'; Topic = 'Name resolution poisoning'; Group = 'Protocols'; Name = 'LLMNR off'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient'
            Values = @(@{ Name = 'EnableMulticast'; Type = 'DWord'; Value = 0 })
            Why = 'LLMNR answers any name the DNS server did not resolve, which is how responder-style poisoning gets its first hash. Nothing legitimate needs it in a domain.'
        })

    $s.Add([ordered]@{
            Id = 'PowerShell-ScriptBlockLogging'; Topic = 'PowerShell logging'; Group = 'Logging'; Name = 'PowerShell script block logging'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            Values = @(@{ Name = 'EnableScriptBlockLogging'; Type = 'DWord'; Value = 1 })
            Why = 'Records what PowerShell actually executed, including code that was decoded or built at runtime. Without it an incident investigation has almost nothing to work with.'
            Observe = 'PowerShell/Operational log, event 4104. Watch the log size - see the log size setting.'
        })

    $s.Add([ordered]@{
            Id = 'PowerShell-ModuleLogging'; Topic = 'PowerShell logging'; Group = 'Logging'; Name = 'PowerShell module logging'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Strict'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
            Values = @(@{ Name = 'EnableModuleLogging'; Type = 'DWord'; Value = 1 })
            Why = 'Pipeline-level detail on top of script block logging. Verbose - only worth it if something collects and rotates the logs.'
        })

    $s.Add([ordered]@{
            Id = 'Audit-CommandLine'; Topic = 'Process command line auditing'; Reference = 'KB3004375'; Group = 'Logging'; Name = 'Command line in process creation events'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            Values = @(@{ Name = 'ProcessCreationIncludeCmdLine_Enabled'; Type = 'DWord'; Value = 1 })
            Why = 'Event 4688 without the command line tells you a process ran. With it, you know what it was told to do. This is the single highest-value logging change available.'
            Observe = 'Passwords passed on a command line end up in the event log. Worth knowing before enabling.'
        })

    $s.Add([ordered]@{
            Id = 'EventLog-Sizes'; Topic = 'Event log sizes'; Group = 'Logging'; Name = 'Larger security log'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows\EventLog\Security'
            Values = @(@{ Name = 'MaxSize'; Type = 'DWord'; Value = 1024000 })
            Why = 'MaxSize is in kilobytes, so this is roughly one gigabyte. The default holds a few hours on a busy domain controller, and turning on more auditing without enlarging the log means the evidence is gone before anyone looks. Check the free space on the system volume before deploying this to every server.'
        })

    $s.Add([ordered]@{
            Id = 'Diagnostics-LdapInterface'; Topic = 'LDAP bind diagnostics'; Reference = 'KB314980, KB4520412'; Group = 'Logging'; Name = 'LDAP interface diagnostics on domain controllers'
            Type = 'AdminTemplate'; Target = 'DC'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\System\CurrentControlSet\Services\NTDS\Diagnostics'
            Values = @(@{ Name = '16 LDAP Interface Events'; Type = 'DWord'; Value = 2 })
            Why = 'This is what makes event 2889 appear, and 2889 is the only record naming which client bound to LDAP without signing. Without it a scan reporting no unsigned binds is reporting an empty log, not a clean domain - which is the most dangerous kind of green result, because it invites someone to enforce LDAP signing on the strength of it. Nothing is enforced here; the diagnostic only writes events.'
            Observe = 'On a domain controller with many unsigned binds this can fill the Directory Service log quickly, which is why the log size below travels with it. Takes effect at once, no restart. Turning it off again means setting the value to 0 explicitly - it sits outside the Policies branch and so is not removed when the GPO is unlinked.'
        })

    $s.Add([ordered]@{
            Id = 'EventLog-DirectoryServiceSize'; Topic = 'LDAP bind diagnostics'; NeedsReboot = $true; Group = 'Logging'; Name = 'Larger Directory Service log'
            Type = 'AdminTemplate'; Target = 'DC'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\System\CurrentControlSet\Services\EventLog\Directory Service'
            Values = @(@{ Name = 'MaxSize'; Type = 'DWord'; Value = 134217728 })
            Why = 'Pairs with the LDAP diagnostic above. Event 2889 is written once per unsigned bind, so the default log can wrap within hours on a busy directory and take the evidence with it. 128 MB, in bytes.'
        })

    $s.Add([ordered]@{
            Id = 'EventLog-PowerShellSize'; Topic = 'Event log sizes'; NeedsReboot = $true; Group = 'Logging'; Name = 'Larger PowerShell operational log'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Operational'
            Values = @(@{ Name = 'MaxSize'; Type = 'DWord'; Value = 268435456 })
            Why = 'Script block logging fills the default 15 MB PowerShell log in hours on a server that runs any automation at all, and event 4104 is the one record an investigation actually wants. 256 MB is a reasonable floor.'
            Observe = 'Two things differ from the security log setting above and both are easy to get wrong. The Policies\...\EventLog\<name> branch only backs the four logs that have an ADMX behind them - Application, Security, Setup, System - so a channel under Applications and Services Logs has to be addressed at its WINEVT\Channels key instead. And MaxSize there is in bytes, not kilobytes, so the number is a thousand times larger for the same size. Because this key sits outside Policies it tattoos: unlinking the GPO leaves the value behind, and reverting means setting it back explicitly.'
        })

    $s.Add([ordered]@{
            Id = 'SMB-MinDialectServer'; MinOS = 'Server 2022'; Topic = 'SMB dialect'; Group = 'Protocols'
            Name = 'Server refuses anything below SMB 3.0'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Strict'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows\LanmanServer'
            Values = @(@{ Name = 'MinSmb2Dialect'; Type = 'DWord'; Value = 768 })
            Why = 'Disabling the SMBv1 driver elsewhere in this baseline stops the worst dialect. This sets a floor under the rest: 768 is 0x300, SMB 3.0.0, the first dialect with encryption and a signed negotiation that cannot be downgraded. SMB 2.0.2 and 2.1 negotiate happily and offer neither.'
            Observe = 'Windows 7 and Server 2008 R2 speak SMB 2.1 and stop reaching this machine after it. So do a number of NAS firmwares and older Linux Samba builds. Deploy the SMB audit topic first and read what actually connects - this is Strict for a reason.'
        })

    $s.Add([ordered]@{
            Id = 'SMB-MinDialectClient'; MinOS = 'Server 2022'; Topic = 'SMB dialect'; Group = 'Protocols'
            Name = 'Client refuses anything below SMB 3.0'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Strict'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation'
            Values = @(@{ Name = 'MinSmb2Dialect'; Type = 'DWord'; Value = 768 })
            Why = 'The outbound half - this machine will not connect to a file server that cannot speak SMB 3.0 either.'
        })

    $s.Add([ordered]@{
            Id = 'SMB-RateLimiter'; MinOS = 'Server 2025'; Topic = 'SMB brute force protection'; Group = 'Protocols'
            Name = 'Delay after a failed SMB authentication'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows\LanmanServer'
            Values = @(
                @{ Name = 'EnableAuthRateLimiter'; Type = 'DWord'; Value = 1 }
                @{ Name = 'InvalidAuthenticationDelayTimeInMs'; Type = 'DWord'; Value = 2000 }
            )
            Why = 'Two seconds after every failed SMB logon. That turns password spraying over SMB from thousands of attempts per minute into a handful, which is the difference between a weak password being found and not. On by default in Server 2025; stating it explicitly pins the delay and catches a machine where someone turned it off to speed up a migration.'
            Observe = 'Server 2025 and Windows 11 only. Harmless to a legitimate client, which does not fail authentication repeatedly - but a service account with a stale password in a loop will now retry more slowly, and that shows up as slowness rather than as an error.'
        })

    $s.Add([ordered]@{
            Id = 'SMB-NoMailslotsServer'; MinOS = 'Server 2025'; Topic = 'Legacy SMB discovery'; Group = 'Protocols'
            Name = 'Browser service without remote mailslots'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows\Bowser'
            Values = @(@{ Name = 'EnableMailslots'; Type = 'DWord'; Value = 0 })
            Why = 'Remote mailslots are an unauthenticated, unsigned datagram mechanism from the original browser protocol, still reachable over SMB. Nothing written this century needs them, and they belong to the same family as the name resolution protocols this baseline already switches off.'
            Observe = 'Server 2025 and Windows 11 only. Anything relying on the legacy Computer Browser service - a NET VIEW listing, some very old backup software - loses it.'
        })

    $s.Add([ordered]@{
            Id = 'SMB-NoMailslotsClient'; MinOS = 'Server 2025'; Topic = 'Legacy SMB discovery'; Group = 'Protocols'
            Name = 'Network provider without remote mailslots'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows\NetworkProvider'
            Values = @(@{ Name = 'EnableMailslots'; Type = 'DWord'; Value = 0 })
            Why = 'The client half of the same thing.'
        })

    $s.Add([ordered]@{
            Id = 'SMBv1-Client-Disabled'; Topic = 'SMBv1'; Reference = 'KB2696547'; Group = 'Protocols'; Name = 'SMBv1 client driver disabled'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\System\CurrentControlSet\Services\mrxsmb10'
            Values = @(@{ Name = 'Start'; Type = 'DWord'; Value = 4 })
            Why = 'SMBv1 has no signing worth the name and no way to make it safe. The server component should be removed as a feature; this disables the client driver.'
            Observe = 'Check for SMBv1 use first with Get-SmbServerConfiguration and the SMBServer/Audit log. Disabling the driver alone leaves LanmanWorkstation depending on a service that no longer starts - the companion setting below rewrites that dependency list, and both have to land together.'
        })

    $s.Add([ordered]@{
            Id = 'SMBv1-WorkstationDependency'; Topic = 'SMBv1'; Reference = 'KB2696547'; Group = 'Protocols'; Name = 'Workstation service no longer depends on SMBv1'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\System\CurrentControlSet\Services\LanmanWorkstation'
            Values = @(@{ Name = 'DependOnService'; Type = 'MultiString'; Value = @('Bowser', 'MRxSmb20', 'NSI') })
            Why = 'The default dependency list still names MRxSmb10. Disable that driver without removing it from here and the Workstation service fails to start on the next reboot, which takes the machine off the domain in every way that matters. Microsoft documents this pair together; they must never be deployed apart.'
        })

    # -- Schannel: the channel everything else rides on -----------------------------------------
    # LDAPS, RDP and WinRM all terminate in Schannel, so hardening the protocols above it while
    # leaving TLS 1.0 enabled underneath is a gap rather than a layering choice.
    #
    # These keys sit outside the Policies branch and therefore TATTOO: unlinking the GPO leaves
    # them behind and reverting means writing the old values back explicitly.

    $s.Add([ordered]@{
            Id = 'Schannel-Tls10-Server'; NeedsReboot = $true; Topic = 'TLS versions and cipher suites'; Group = 'Protocols'
            Reference = 'KB245030, RFC 8996'; Name = 'TLS 1.0 server off'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Strict'; Staged = $false
            RegKey = 'HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'
            Values = @(
                @{ Name = 'Enabled'; Type = 'DWord'; Value = 0 }
                @{ Name = 'DisabledByDefault'; Type = 'DWord'; Value = 1 }
            )
            Why = 'TLS 1.0 and 1.1 have no safe cipher suite left and are deprecated by RFC 8996, and RC4 and Triple DES are broken independently of the protocol carrying them. This matters more than it looks: LDAPS, RDP and WinRM all terminate in Schannel, so hardening those protocols while leaving TLS 1.0 enabled underneath secures the door and leaves the wall open. Server and client sides are separate keys because a machine can be strict about what it offers and still be talked down when it connects outward.'
            Observe = 'Old appliances, scanners, printers and management agents are the usual casualties, and the failure looks like a network problem rather than a policy one. Check what still negotiates TLS 1.0 first - Schannel event 36880 in the System log records the protocol of every handshake once informational Schannel logging is on.'
        })

    $s.Add([ordered]@{
            Id = 'Schannel-Tls10-Client'; NeedsReboot = $true; Topic = 'TLS versions and cipher suites'; Group = 'Protocols'
            Name = 'TLS 1.0 client off'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Strict'; Staged = $false
            RegKey = 'HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'
            Values = @(
                @{ Name = 'Enabled'; Type = 'DWord'; Value = 0 }
                @{ Name = 'DisabledByDefault'; Type = 'DWord'; Value = 1 }
            )
            Why = 'The outgoing side. A server that will still speak TLS 1.0 to a remote endpoint can be downgraded into it.'
        })

    $s.Add([ordered]@{
            Id = 'Schannel-Tls11-Server'; NeedsReboot = $true; Topic = 'TLS versions and cipher suites'; Group = 'Protocols'
            Name = 'TLS 1.1 server off'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Strict'; Staged = $false
            RegKey = 'HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'
            Values = @(
                @{ Name = 'Enabled'; Type = 'DWord'; Value = 0 }
                @{ Name = 'DisabledByDefault'; Type = 'DWord'; Value = 1 }
            )
            Why = 'Deprecated alongside TLS 1.0 and offering nothing TLS 1.2 does not.'
        })

    $s.Add([ordered]@{
            Id = 'Schannel-Tls11-Client'; NeedsReboot = $true; Topic = 'TLS versions and cipher suites'; Group = 'Protocols'
            Name = 'TLS 1.1 client off'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Strict'; Staged = $false
            RegKey = 'HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'
            Values = @(
                @{ Name = 'Enabled'; Type = 'DWord'; Value = 0 }
                @{ Name = 'DisabledByDefault'; Type = 'DWord'; Value = 1 }
            )
            Why = 'The outgoing side of the same.'
        })

    $s.Add([ordered]@{
            Id = 'Schannel-Tls12-Server'; NeedsReboot = $true; Topic = 'TLS versions and cipher suites'; Group = 'Protocols'
            Name = 'TLS 1.2 server on'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
            Values = @(
                @{ Name = 'Enabled'; Type = 'DWord'; Value = 1 }
                @{ Name = 'DisabledByDefault'; Type = 'DWord'; Value = 0 }
            )
            Why = 'Stated explicitly and deployed before the older versions are switched off, so a machine can never end up with every protocol disabled at once. On its own this changes nothing - TLS 1.2 is already on - which is exactly why it belongs in the Baseline profile while the removals sit in Strict.'
        })

    $s.Add([ordered]@{
            Id = 'Schannel-Tls12-Client'; NeedsReboot = $true; Topic = 'TLS versions and cipher suites'; Group = 'Protocols'
            Name = 'TLS 1.2 client on'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
            Values = @(
                @{ Name = 'Enabled'; Type = 'DWord'; Value = 1 }
                @{ Name = 'DisabledByDefault'; Type = 'DWord'; Value = 0 }
            )
            Why = 'The outgoing side.'
        })

    foreach ($rc4 in '40/128', '56/128', '64/128', '128/128') {
        $s.Add([ordered]@{
                Id = "Schannel-Rc4-$($rc4 -replace '/', '-')"; NeedsReboot = $true; Topic = 'TLS versions and cipher suites'; Group = 'Protocols'
                Name = "RC4 $rc4 cipher off"
                Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Strict'; Staged = $false
                RegKey = "HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 $rc4"
                Values = @(@{ Name = 'Enabled'; Type = 'DWord'; Value = 0 })
                Why = 'RC4 is broken as a stream cipher and there is no configuration that makes it safe. Four separate keys because Schannel treats each key length as its own cipher, and disabling only the shortest leaves the others available.'
            })
    }

    $s.Add([ordered]@{
            Id = 'Schannel-TripleDes'; NeedsReboot = $true; Topic = 'TLS versions and cipher suites'; Group = 'Protocols'
            Reference = 'CVE-2016-2183'; Name = 'Triple DES cipher off'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Strict'; Staged = $false
            RegKey = 'HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168'
            Values = @(@{ Name = 'Enabled'; Type = 'DWord'; Value = 0 })
            Why = 'A 64-bit block cipher, which is what makes the Sweet32 birthday attack practical on long-lived connections.'
        })

    # -- The Schannel half of the certificate binding story -------------------------------------
    $s.Add([ordered]@{
            Id = 'Schannel-CertificateMapping'; DefaultWhenUnset = 24
            Topic = 'Certificate binding for Kerberos'; Group = 'LegacyAuth'
            Reference = 'KB5014754, CVE-2022-26931, CVE-2022-26923'
            Name = 'Strong certificate mapping for Schannel'
            Type = 'SecurityOption'; Target = 'DC'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel\CertificateMappingMethods'
            ValueType = 4; EnforceValue = 24
            Why = 'The companion to strong certificate binding on the KDC, which covers Kerberos only. This is the Schannel side, and 0x18 leaves just the two strong mapping methods - S4U2Self and its explicit form - with subject, issuer and UPN mapping switched off. Those three can be spoofed by anyone able to request a certificate with a chosen subject.'
            Observe = 'Already the default since KB5014754, so this normally changes nothing. It is here because the value that gets set back to 0x1F to work around a certificate problem is the one nobody remembers to undo, and nothing in the directory reports it.'
        })

    # -- Remote Desktop -------------------------------------------------------------------------
    $s.Add([ordered]@{
            Id = 'CredSsp-EncryptionOracle'; Topic = 'Remote Desktop'; Group = 'CredentialProtection'
            Reference = 'CVE-2018-0886, KB4093492'
            Name = 'CredSSP refuses unpatched peers'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'
            Values = @(@{ Name = 'AllowEncryptionOracle'; Type = 'DWord'; Value = 0 })
            Why = 'CVE-2018-0886 let an attacker in the middle of a CredSSP exchange relay the session and run code with the credentials being delegated - which for RDP means the credentials of whoever was connecting. Value 0, Force Updated Clients, refuses any peer that has not been patched. The vulnerability is from 2018 and the patch is long since installed everywhere; what is often missing is this setting, which is what makes the machine actually refuse the vulnerable path.'
            Observe = 'A client or server that genuinely has not been patched since 2018 can no longer connect over RDP. If something breaks, the answer is to patch it, not to lower this.'
        })

    $s.Add([ordered]@{
            Id = 'Rdp-SecureTransport'; Topic = 'Remote Desktop'; Group = 'CredentialProtection'
            Name = 'RDP requires NLA, TLS and high encryption'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services'
            Values = @(
                @{ Name = 'UserAuthentication'; Type = 'DWord'; Value = 1 }
                @{ Name = 'SecurityLayer'; Type = 'DWord'; Value = 2 }
                @{ Name = 'MinEncryptionLevel'; Type = 'DWord'; Value = 3 }
                @{ Name = 'fEncryptRPCTraffic'; Type = 'DWord'; Value = 1 }
                @{ Name = 'fPromptForPassword'; Type = 'DWord'; Value = 1 }
            )
            Why = 'Network Level Authentication makes the client authenticate before a session is created, which removes the pre-authentication attack surface and the resource exhaustion that goes with it. The security layer forces TLS rather than the legacy RDP protocol, and prompting for the password stops a saved credential being replayed into a server that turns out not to be the one expected.'
            Observe = 'NLA needs CredSSP on the client. Anything connecting with a very old or non-Windows RDP client may stop working - most modern clients handle it.'
        })

    $s.Add([ordered]@{
            Id = 'Rdp-NoOutboundCreds'; Topic = 'Remote Desktop'; Group = 'CredentialProtection'
            Name = 'No credential delegation out of a Restricted Admin session'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\System\CurrentControlSet\Control\Lsa'
            Values = @(@{ Name = 'DisableRestrictedAdminOutboundCreds'; Type = 'DWord'; Value = 1 })
            Why = 'Stops a session that was established without sending credentials from handing them onward to the next hop anyway, which would defeat the point of connecting that way.'
            Observe = 'This does not turn Restricted Admin on - deliberately. Restricted Admin protects the credentials of the person connecting, but it also makes a network logon with a stolen hash sufficient to reach the server, so switching it on is a trade rather than an improvement. Remote Credential Guard is the better answer where it is available; the setting below prepares the client side for it.'
        })

    $s.Add([ordered]@{
            Id = 'Rdp-AllowProtectedCreds'; Topic = 'Remote Desktop'; Group = 'CredentialProtection'
            Name = 'Remote Credential Guard permitted'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows\CredentialsDelegation'
            Values = @(@{ Name = 'AllowProtectedCreds'; Type = 'DWord'; Value = 1 })
            Why = 'Lets an administrator connect with Remote Credential Guard, where the Kerberos requests are sent back to the originating machine instead of the credentials being placed on the target. An administrative session on a server then leaves nothing behind that is worth stealing.'
        })

    # -- Point and Print ------------------------------------------------------------------------
    # The spooler is disabled outright on domain controllers further down. On member servers it
    # usually has to keep running, and this is what makes that survivable.
    $s.Add([ordered]@{
            Id = 'PointAndPrint-RestrictDrivers'; Topic = 'Point and Print'; Group = 'Protocols'
            Reference = 'KB5005652, CVE-2021-34527'
            Name = 'Only administrators may install printer drivers'
            Type = 'AdminTemplate'; Target = 'Member'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
            Values = @(
                @{ Name = 'RestrictDriverInstallationToAdministrators'; Type = 'DWord'; Value = 1 }
                @{ Name = 'NoWarningNoElevationOnInstall'; Type = 'DWord'; Value = 0 }
                @{ Name = 'UpdatePromptSettings'; Type = 'DWord'; Value = 0 }
            )
            Why = 'This is the actual PrintNightmare mitigation, and the reason the vulnerability kept coming back: a printer driver runs as SYSTEM, and without this any user who can reach the spooler can install one. The two zeroes matter as much as the one - a warning that has been suppressed is how the restriction gets worked around.'
            Observe = 'Users who currently install printers themselves will need a driver already present, deployed centrally, or an administrator. Plan the driver deployment before this, not after.'
        })

    $s.Add([ordered]@{
            Id = 'Spooler-NoRemoteRpc'; Topic = 'Point and Print'; Group = 'Protocols'
            Reference = 'CVE-2021-34527'
            Name = 'Spooler does not accept remote print jobs'
            Type = 'AdminTemplate'; Target = 'Member'; Profile = 'Strict'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows NT\Printers'
            Values = @(@{ Name = 'RegisterSpoolerRemoteRpcEndPoint'; Type = 'DWord'; Value = 2 })
            Why = 'A server that prints does not have to be a print server. Closing the remote RPC endpoint keeps local printing working while removing the interface that the printer bugs are reached through.'
            Observe = 'Do not deploy this to an actual print server - it is exactly the function that machine exists to provide. Scope it with a separate OU or exclude the print servers from the link.'
        })

    # -- Services -------------------------------------------------------------------------------
    $s.Add([ordered]@{
            Id = 'Service-Spooler-DC'; Topic = 'Print spooler on domain controllers'; Group = 'Services'; Name = 'Print Spooler disabled on domain controllers'
            Type = 'Service'; Target = 'DC'; Profile = 'Baseline'; Staged = $false
            ServiceName = 'Spooler'; StartupMode = 4
            Why = 'The spooler is a remote code execution surface and the entry point for several printer bug abuses. A domain controller has no business printing.'
            Observe = 'Only breaks things if someone genuinely prints from a DC, which they should not.'
        })

    # -- Additions after reading HardenAD's shipped policy templates ---------------------------
    # Their GPO backups set a number of things this baseline had missed. These are the ones worth
    # having; the rest were workstation concerns or risk without much return.

    $s.Add([ordered]@{
            Id = 'LDAP-ClientIntegrity'; Topic = 'LDAP signing and channel binding'; Reference = 'KB4563239'; Group = 'Signing'; Name = 'LDAP client requires signing'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $true
            Key = 'MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity'
            ValueType = 4; AuditValue = 1; EnforceValue = 2
            Why = 'The other half of LDAP signing. Requiring it on the server does nothing for a client that never asks - this makes the machine refuse to bind without signing at all. 1 negotiates, 2 requires.'
            Observe = 'Breaks a local tool that binds to LDAP without signing, which is usually old monitoring or a backup agent.'
        })

    $s.Add([ordered]@{
            Id = 'SMB-ClientSigningEnabled'; Topic = 'SMB signing'; Group = 'Signing'; Name = 'SMB client signing offered'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature'
            ValueType = 4; EnforceValue = 1
            Why = 'Offers signing when talking to a file server. Costs nothing and breaks nothing.'
        })

    $s.Add([ordered]@{
            Id = 'Netlogon-SignSecureChannel'; Topic = 'Netlogon secure channel'; Reference = 'CVE-2020-1472, KB4557222'; Group = 'Signing'; Name = 'Netlogon: sign secure channel'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel'
            ValueType = 4; EnforceValue = 1
            Why = 'Part of the secure channel trio. RequireSignOrSeal decides that one of them is mandatory; this one says signing is always attempted.'
        })

    $s.Add([ordered]@{
            Id = 'Netlogon-SealSecureChannel'; Topic = 'Netlogon secure channel'; Reference = 'CVE-2020-1472, KB4557222'; Group = 'Signing'; Name = 'Netlogon: seal secure channel'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel'
            ValueType = 4; EnforceValue = 1
            Why = 'Encrypts the secure channel rather than only signing it.'
        })

    $s.Add([ordered]@{
            Id = 'Netlogon-RequireStrongKey'; Topic = 'Netlogon secure channel'; Reference = 'CVE-2020-1472, KB4557222'; Group = 'Signing'; Name = 'Netlogon: strong session key'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey'
            ValueType = 4; EnforceValue = 1
            Why = 'Requires a 128-bit session key for the secure channel. Only an issue with pre-2000 domain members, which should not exist.'
        })

    $s.Add([ordered]@{
            Id = 'NTLM-MinClientSec'; Topic = 'NTLM version and session security'; Group = 'LegacyAuth'; Name = 'NTLM client: NTLMv2 session security and 128-bit'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec'
            ValueType = 4; EnforceValue = 537395200
            Why = 'LmCompatibilityLevel decides which response is sent; this decides the session security around it. 0x20080000 is NTLMv2 session security plus 128-bit encryption. Without it a downgraded session is still possible.'
        })

    $s.Add([ordered]@{
            Id = 'NTLM-MinServerSec'; Topic = 'NTLM version and session security'; Group = 'LegacyAuth'; Name = 'NTLM server: NTLMv2 session security and 128-bit'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec'
            ValueType = 4; EnforceValue = 537395200
            Why = 'The receiving side of the same requirement.'
        })

    $s.Add([ordered]@{
            Id = 'NTLM-RestrictIncoming'; Topic = 'NTLM restriction'; Group = 'LegacyAuth'; Name = 'Deny incoming NTLM'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Strict'; Staged = $true
            Key = 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictReceivingNTLMTraffic'
            # Zero is "no restriction", not "observe". The observation is a separate setting -
            # Audit incoming NTLM traffic in the Logging group - so this one is simply absent
            # until Level Enforce.
            ValueType = 4; AuditValue = $null; EnforceValue = 2
            Why = 'The inbound counterpart to denying outgoing NTLM. 2 refuses every incoming NTLM authentication, which is the end state but rarely the starting one.'
            Observe = 'NTLM operational log event 8004 on this machine lists what would be refused. Turn the auditing on and read it before setting this.'
        })

    $s.Add([ordered]@{
            Id = 'NTLM-NoNullSessionFallback'; Topic = 'NTLM version and session security'; DefaultWhenUnset = 0; Group = 'LegacyAuth'; Name = 'No NTLM null session fallback'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback'
            ValueType = 4; EnforceValue = 0
            Why = 'Stops NTLM falling back to an anonymous session when authentication fails, which is a quiet way around the anonymous restrictions.'
        })

    $s.Add([ordered]@{
            Id = 'SMB-NoPlainTextPassword'; Topic = 'SMB legacy authentication'; DefaultWhenUnset = 0; Group = 'LegacyAuth'; Name = 'No plaintext password to third-party SMB servers'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword'
            ValueType = 4; EnforceValue = 0
            Why = 'Off by default, but worth stating. Some SMB implementations will ask for the password in the clear if allowed to.'
        })

    $s.Add([ordered]@{
            Id = 'Creds-DisableDomainCreds'; Topic = 'Credential caching'; Group = 'CredentialProtection'; Name = 'Do not store domain credentials'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Strict'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds'
            ValueType = 4; EnforceValue = 1
            Why = 'Stops Credential Manager holding domain credentials for network authentication - one less place to steal them from.'
            Observe = 'Breaks anything relying on a saved credential, including some scheduled tasks and mapped drives with stored passwords.'
        })

    $s.Add([ordered]@{
            Id = 'Creds-CachedLogons'; Topic = 'Credential caching'; Group = 'CredentialProtection'; Name = 'No cached interactive logons'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Strict'; Staged = $false
            Key = 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount'
            ValueType = 1; EnforceValue = '0'
            Why = 'Cached credentials survive on disk and can be cracked offline. A server that always has a DC in reach does not need them.'
            Observe = 'A machine that loses contact with every DC can then not be logged into with a domain account at all. Keep local break-glass access in mind.'
        })

    $s.Add([ordered]@{
            Id = 'Netlogon-UseMachineId'; Topic = 'Computer identity for NTLM'; Group = 'CredentialProtection'; Name = 'Use computer identity for NTLM'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId'
            ValueType = 4; EnforceValue = 1
            Why = 'Services running as Local System authenticate as the computer account rather than anonymously.'
        })

    $s.Add([ordered]@{
            Id = 'MachineAccount-PasswordAge'; Topic = 'Machine account password'; DefaultWhenUnset = 30; Group = 'CredentialProtection'; Name = 'Computer account password rotates every 30 days'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge'
            ValueType = 4; EnforceValue = 30
            Why = 'The default is 30 already, but plenty of estates have this raised or the rotation disabled outright, and a stale machine password is a long-lived credential.'
        })

    $s.Add([ordered]@{
            Id = 'MachineAccount-PasswordChangeEnabled'; Topic = 'Machine account password'; DefaultWhenUnset = 0; Group = 'CredentialProtection'; Name = 'Computer account password change enabled'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange'
            ValueType = 4; EnforceValue = 0
            Why = 'Explicitly re-enables rotation where someone turned it off to work around a broken image.'
        })

    $s.Add([ordered]@{
            Id = 'Account-NoConnectedUser'; Topic = 'Microsoft accounts'; Group = 'CredentialProtection'; Name = 'No Microsoft accounts'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser'
            ValueType = 4; EnforceValue = 3
            Why = 'Blocks adding or logging on with a Microsoft account. On a server there is no reason for one.'
        })

    $s.Add([ordered]@{
            Id = 'Session-InactivityTimeout'; Topic = 'Session lock'; Group = 'CredentialProtection'; Name = 'Lock the session after 15 minutes'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs'
            ValueType = 4; EnforceValue = 900
            Why = 'An unlocked administrative session on a domain controller is an open door. Fifteen minutes is the usual compromise.'
        })

    $s.Add([ordered]@{
            Id = 'Audit-ForceAdvancedPolicy'; Topic = 'Advanced audit policy'; Group = 'Logging'; Name = 'Advanced audit policy overrides the legacy one'
            Type = 'SecurityOption'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            Key = 'MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy'
            ValueType = 4; EnforceValue = 1
            Why = 'Without this a legacy audit category set anywhere in the estate silently overrides the whole advanced audit policy, and the careful subcategory list deploys to nothing. This is the setting that makes the rest of the logging group actually take effect.'
        })

    # -- Second pass over HardenAD, this time the registry.pol files in their GPO backups -------
    # The security templates only carry Security Options. The administrative templates sat in the
    # policy files next to them and had a good deal that this baseline was missing.

    $s.Add([ordered]@{
            Id = 'UNC-HardenedPaths'; Topic = 'UNC hardened paths'; Reference = 'MS15-011, KB3000483'; Group = 'PolicyIntegrity'; Name = 'UNC hardened paths for SYSVOL and NETLOGON'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            Values = @(
                @{ Name = '\\*\SYSVOL'; Type = 'String'; Value = 'RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1' }
                @{ Name = '\\*\NETLOGON'; Type = 'String'; Value = 'RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1' }
            )
            Why = 'Group Policy and logon scripts are fetched from these two shares. Without mutual authentication and integrity a machine in the middle can serve modified policy or a modified script to every client that asks. This is the fix for MS15-011 and it is still not on by default. RequirePrivacy adds SMB encryption on top, so the policy content is not readable in transit either - a GPO reveals a good deal about how an estate is built.'
            Observe = 'The first two parameters are what MS15-011 and the CIS benchmark ask for; the third needs Server 2012 or later on both ends, which every system this tool supports is. Anything reading SYSVOL that is not a modern Windows client - a Linux box mounting it, an appliance, a backup agent using SMB - fails after this, and the error will talk about access rather than encryption.'
        })

    $s.Add([ordered]@{
            Id = 'Gpo-NoCaching'; Topic = 'Policy reapplication'; Group = 'PolicyIntegrity'
            Name = 'No Group Policy caching'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows\System'
            Values = @(
                @{ Name = 'EnableLogonOptimization'; Type = 'DWord'; Value = 0 }
                @{ Name = 'EnableLogonOptimizationOnServerSKU'; Type = 'DWord'; Value = 0 }
            )
            Why = 'With caching on, a synchronous foreground refresh reads the cached copy of the policy rather than fetching the current one. Change a setting, reboot the machine to make it take effect, and the machine applies the version from before the change - the opposite of what was intended, and it looks like the deployment simply did not work. On a server the caching only buys a slightly faster boot, which is not worth an hour of chasing a setting that did apply.'
            Observe = 'Two value names because the client and server SKUs read different ones; setting both covers either. Pairs with the reapplication setting above - that one makes the security policy reapply every cycle, this one makes sure what gets reapplied is current.'
        })

    $s.Add([ordered]@{
            Id = 'Gpo-AlwaysReapplySecurity'; Topic = 'Policy reapplication'; Group = 'PolicyIntegrity'; Name = 'Reapply security policy even when unchanged'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'
            Values = @(
                @{ Name = 'NoBackgroundPolicy'; Type = 'DWord'; Value = 0 }
                @{ Name = 'NoGPOListChanges'; Type = 'DWord'; Value = 0 }
            )
            Why = 'By default the security extension only runs when a GPO has changed - otherwise it waits out its own sixteen-hour cycle. Someone who edits a value locally therefore keeps it until the next policy edit, which may be never. With these two at zero the security settings reapply on every background refresh instead, which is every five minutes on a domain controller and every ninety on a member server. Measured in a lab: a hand-edited LDAPServerIntegrity was back at its policy value three minutes later, with no gpupdate and no restart.'
            Observe = 'This is what turns the rest of the tool from a one-time deployment into something that holds. It also means a deliberate local exception will be undone - if a machine genuinely needs a different value, it needs its own GPO or an OU outside the link, not a registry edit.'
        })

    $s.Add([ordered]@{
            Id = 'NetBIOS-Disabled'; MinOS = 'Server 2025'; Topic = 'Name resolution poisoning'; Group = 'Protocols'; Name = 'NetBIOS over TCP/IP off'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient'
            Values = @(@{ Name = 'EnableNetbios'; Type = 'DWord'; Value = 0 })
            Why = 'The other half of the name poisoning problem. Turning off LLMNR and leaving NBT-NS on just moves the attack one protocol along.'
            Observe = 'Anything genuinely relying on NetBIOS name resolution is old enough to be worth finding. Note that the policy that backs this value only exists on Windows 11 22H2 and Server 2025 and later - it appears in the Server 2025 baseline. Older servers ignore it silently, so they still need the per-adapter NetbiosOptions setting or DHCP option 001.'
        })

    $s.Add([ordered]@{
            Id = 'mDNS-Disabled'; MinOS = 'Server 2019'; NeedsReboot = $true; Topic = 'Name resolution poisoning'; Group = 'Protocols'
            Name = 'mDNS off'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\System\CurrentControlSet\Services\Dnscache\Parameters'
            Values = @(@{ Name = 'EnableMDNS'; Type = 'DWord'; Value = 0 })
            Why = 'The third of the three protocols Windows falls back to when DNS does not resolve a name, and the one that gets forgotten. Responder answers all three. Turning off LLMNR and NetBIOS while leaving mDNS listening on UDP 5353 moves the attack one protocol along rather than stopping it - which is the same reason NetBIOS is in this topic and not on its own.'
            Observe = 'Read at service start only, so it needs a reboot. The value sits outside the Policies branch and therefore tattoos. Microsoft points at a Defender Firewall rule as the supported way to do this; the registry value is what actually stops the listener, and the two are complementary rather than alternatives. Only present on Windows Server 2019 and Windows 10 1703 and later - older builds have no mDNS to switch off. Wireless displays and network projectors are the things that notice.'
        })

    $s.Add([ordered]@{
            Id = 'NetBIOS-PerInterface'; NeedsReboot = $true; Topic = 'Name resolution poisoning'; Group = 'Protocols'
            Name = 'NetBIOS off on every interface'
            Type = 'StartupScript'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            ScriptName = 'ADHardenKit-DisableNetbios.ps1'
            ScriptBody = @'
# Deployed by ADHardenKit. Sets NetbiosOptions to 2 (disabled) on every network interface.
# A GPO cannot address these keys directly: each is named after a per-machine interface GUID.
# Idempotent - it writes only what differs, and runs at every boot so a rebuilt machine is caught.
$key = 'HKLM:\System\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
foreach ($iface in (Get-ChildItem -LiteralPath $key -ErrorAction SilentlyContinue)) {
    $current = (Get-ItemProperty -LiteralPath $iface.PSPath -Name NetbiosOptions -ErrorAction SilentlyContinue).NetbiosOptions
    if ($current -ne 2) {
        Set-ItemProperty -LiteralPath $iface.PSPath -Name NetbiosOptions -Value 2 -Type DWord
    }
}
'@
            Why = 'The policy version of this setting only reaches interfaces that take their configuration from DHCP, which a server with a static address does not. On such a machine the policy is written, reports as applied, and NBT-NS keeps listening on UDP 137 anyway. This is the same setting one level down, delivered as a startup script because each interface key is named after a per-machine GUID and no policy can name a key it cannot know in advance.'
            Observe = 'The only setting here delivered as a script rather than a value, and the only one that needs two restarts: the script runs after NetBT has already started, so it writes the value at one boot and the listener goes away at the next. Check for a second interface on a cluster or heartbeat network before assuming all of them should change, and remember that anything still resolving names over NetBIOS - old scanners, label printers, software using \\SERVERNAME without a DNS suffix - fails afterwards without an error that says NetBIOS. Removing the GPO link stops the script running but does not put the value back; that is a manual step with value 0.'
        })

    $s.Add([ordered]@{
            Id = 'WinRM-NoWeakAuth'; Topic = 'WinRM authentication'; Group = 'Protocols'; Name = 'WinRM without basic, digest or plaintext'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows\WinRM\Service'
            Values = @(
                @{ Name = 'AllowBasic'; Type = 'DWord'; Value = 0 }
                @{ Name = 'AllowUnencryptedTraffic'; Type = 'DWord'; Value = 0 }
                @{ Name = 'DisableRunAs'; Type = 'DWord'; Value = 1 }
            )
            Why = 'Basic authentication over WinRM hands the password to whatever answers. DisableRunAs stops a stored credential being configured for a listener.'
        })

    $s.Add([ordered]@{
            Id = 'WinRM-ClientNoWeakAuth'; Topic = 'WinRM authentication'; Group = 'Protocols'; Name = 'WinRM client without basic, digest or plaintext'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows\WinRM\Client'
            Values = @(
                @{ Name = 'AllowBasic'; Type = 'DWord'; Value = 0 }
                @{ Name = 'AllowUnencryptedTraffic'; Type = 'DWord'; Value = 0 }
                @{ Name = 'AllowDigest'; Type = 'DWord'; Value = 0 }
            )
            Why = 'The outgoing side. A client that will fall back to basic can be talked into it.'
        })

    $s.Add([ordered]@{
            Id = 'SMB-NoInsecureGuest'; Topic = 'SMB legacy authentication'; Reference = 'KB4046019'; Group = 'LegacyAuth'; Name = 'No insecure guest logon to SMB'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation'
            Values = @(@{ Name = 'AllowInsecureGuestAuth'; Type = 'DWord'; Value = 0 })
            Why = 'Guest fallback means the client silently connects unauthenticated when credentials are rejected - to a share that may not be the one it thinks. No signing, no integrity, no warning.'
        })

    $s.Add([ordered]@{
            Id = 'LSA-NoCustomSSP'; Topic = 'LSA protection'; Group = 'CredentialProtection'; Name = 'No custom security packages in LSASS'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows\System'
            Values = @(@{ Name = 'AllowCustomSSPsAPs'; Type = 'DWord'; Value = 0 })
            Why = 'Registering a custom security support provider is a documented persistence technique that also reads every credential passing through LSASS. Pairs with LSA protection.'
        })

    $s.Add([ordered]@{
            Id = 'LocalAccountTokenFilter'; Topic = 'Local account remote token'; Reference = 'KB951016'; Group = 'CredentialProtection'; Name = 'Local accounts get a filtered token remotely'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System'
            Values = @(@{ Name = 'LocalAccountTokenFilterPolicy'; Type = 'DWord'; Value = 0 })
            Why = 'With this at 1 - which plenty of remote management tools set - a local administrator account can be used remotely with full rights. That is exactly how a shared local password turns into lateral movement across the estate. Zero is the safe value and worth stating explicitly.'
        })

    $s.Add([ordered]@{
            Id = 'VBS-CodeIntegrity'; MinOS = 'Server 2016'; Topic = 'Credential Guard and VBS'; NeedsReboot = $true; Group = 'CredentialProtection'; Name = 'Hypervisor enforced code integrity'
            Type = 'AdminTemplate'; Target = 'Member'; Profile = 'Strict'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows\DeviceGuard'
            Values = @(
                @{ Name = 'HypervisorEnforcedCodeIntegrity'; Type = 'DWord'; Value = 1 }
                @{ Name = 'HVCIMATRequired'; Type = 'DWord'; Value = 1 }
                @{ Name = 'ConfigureSystemGuardLaunch'; Type = 'DWord'; Value = 1 }
            )
            Why = 'Runs alongside Credential Guard on the same virtualisation stack: kernel code has to be signed and validated in the isolated environment. Test it - an unsigned or badly behaved driver will refuse to load afterwards.'
            Observe = 'Check for driver compatibility first. Failures show up in the System log at boot.'
        })

    $s.Add([ordered]@{
            Id = 'PowerShell-Transcription'; Topic = 'PowerShell logging'; Group = 'Logging'; Name = 'PowerShell transcription'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Strict'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
            Values = @(
                @{ Name = 'EnableTranscripting'; Type = 'DWord'; Value = 1 }
                @{ Name = 'EnableInvocationHeader'; Type = 'DWord'; Value = 1 }
            )
            Why = 'Writes the full session, input and output, to a file. Script block logging tells you what ran; transcription tells you what came back. Set an OutputDirectory on a write-only share, otherwise the transcript sits next to whoever might want to delete it.'
            Observe = 'Produces a lot of files. Only worth turning on if something collects and rotates them.'
        })

    $s.Add([ordered]@{
            Id = 'PowerShell-InvocationLogging'; Topic = 'PowerShell logging'; Group = 'Logging'; Name = 'Script block invocation logging'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Strict'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            Values = @(@{ Name = 'EnableScriptBlockInvocationLogging'; Type = 'DWord'; Value = 1 })
            Why = 'Adds a start and stop record around each script block. Useful for timing and correlation, noisy on its own.'
        })

    $s.Add([ordered]@{
            Id = 'EventLog-Retention'; Topic = 'Event log sizes'; Group = 'Logging'; Name = 'Logs overwrite rather than stop'
            Type = 'AdminTemplate'; Target = 'Both'; Profile = 'Baseline'; Staged = $false
            RegKey = 'HKLM\Software\Policies\Microsoft\Windows\EventLog\Security'
            Values = @(@{ Name = 'Retention'; Type = 'String'; Value = '0' })
            Why = 'A full security log that refuses to overwrite stops recording, and with CrashOnAuditFail set it stops the machine. Overwriting oldest is the sane default once the size is large enough.'
        })

    return $s.ToArray()
}

function Get-HardenAuditPolicy {
    <#
        .SYNOPSIS
        The Advanced Audit Policy baseline, as subcategory GUIDs.

        .DESCRIPTION
        Subcategories are addressed by GUID rather than by name, because the names are localised
        and a German or French system reports them differently. The GUIDs are stable everywhere.

        Setting values: 0 = no auditing, 1 = success, 2 = failure, 3 = success and failure.

        The DC list deliberately includes Directory Service Changes, which is what makes SACLs on
        the directory produce events at all - a SACL without it records nothing.
    #>
    [CmdletBinding()]
    param()

    # Subcategory, GUID, DC value, Member value, why.
    # The leading comma on every row is load-bearing: @() flattens nested arrays, so without
    # it this becomes 125 loose strings rather than 25 rows of five.
    $rows = @(
        , @('Credential Validation', '{0CCE923F-69AE-11D9-BED3-505054503030}', 3, 3, 'Every NTLM authentication attempt against the domain, success and failure.')
        , @('Kerberos Authentication Service', '{0CCE9242-69AE-11D9-BED3-505054503030}', 3, 0, 'TGT requests. Failures here are password spraying.')
        , @('Kerberos Service Ticket Operations', '{0CCE9240-69AE-11D9-BED3-505054503030}', 3, 0, 'Service ticket requests. RC4 requests for user accounts are Kerberoasting.')
        , @('User Account Management', '{0CCE9235-69AE-11D9-BED3-505054503030}', 3, 3, 'Account creation, password resets, enabling and disabling.')
        , @('Security Group Management', '{0CCE9237-69AE-11D9-BED3-505054503030}', 3, 3, 'Membership changes on security groups, including the privileged ones.')
        , @('Computer Account Management', '{0CCE9236-69AE-11D9-BED3-505054503030}', 3, 0, 'Computer objects created or changed - relevant with machine account quota abuse.')
        , @('Other Account Management Events', '{0CCE923A-69AE-11D9-BED3-505054503030}', 3, 3, 'Password policy changes and similar.')
        , @('Directory Service Access', '{0CCE923B-69AE-11D9-BED3-505054503030}', 2, 0, 'Failed access to directory objects. Success would flood the log.')
        , @('Directory Service Changes', '{0CCE923C-69AE-11D9-BED3-505054503030}', 1, 0, 'What actually changed in the directory, with old and new value. SACLs produce nothing without this.')
        , @('Logon', '{0CCE9215-69AE-11D9-BED3-505054503030}', 3, 3, 'Interactive and network logons - the raw material for tier separation checks.')
        , @('Logoff', '{0CCE9216-69AE-11D9-BED3-505054503030}', 1, 1, 'Pairs with logon for session reconstruction.')
        , @('Account Lockout', '{0CCE9217-69AE-11D9-BED3-505054503030}', 3, 3, 'Lockouts, which are either a user or an attack.')
        , @('Special Logon', '{0CCE921B-69AE-11D9-BED3-505054503030}', 3, 3, 'Logon by an account holding sensitive privileges. Event 4672.')
        , @('Other Logon/Logoff Events', '{0CCE921C-69AE-11D9-BED3-505054503030}', 3, 3, 'Includes RDP session events and authentication policy silo denials.')
        , @('Process Creation', '{0CCE922B-69AE-11D9-BED3-505054503030}', 3, 3, 'Event 4688. Combine with the command line setting or it is half useful.')
        , @('Audit Policy Change', '{0CCE922F-69AE-11D9-BED3-505054503030}', 3, 3, 'Someone turning the auditing back off.')
        , @('Authentication Policy Change', '{0CCE9230-69AE-11D9-BED3-505054503030}', 3, 3, 'Trust and authentication policy changes.')
        , @('Authorization Policy Change', '{0CCE9231-69AE-11D9-BED3-505054503030}', 3, 0, 'User rights assignment changes.')
        , @('Sensitive Privilege Use', '{0CCE9228-69AE-11D9-BED3-505054503030}', 2, 2, 'Failure only. Success on this subcategory is famously noisy.')
        , @('Security System Extension', '{0CCE9211-69AE-11D9-BED3-505054503030}', 3, 3, 'Services and drivers being installed, which is how persistence looks.')
        , @('System Integrity', '{0CCE9212-69AE-11D9-BED3-505054503030}', 3, 3, 'Integrity violations reported by the OS.')
        , @('Security State Change', '{0CCE9210-69AE-11D9-BED3-505054503030}', 3, 3, 'Startup, shutdown and system time changes.')
        , @('File Share', '{0CCE9224-69AE-11D9-BED3-505054503030}', 3, 0, 'Access to shares including SYSVOL and NETLOGON.')
        , @('SAM', '{0CCE9220-69AE-11D9-BED3-505054503030}', 2, 0, 'Failed SAM access.')
        , @('Group Membership', '{0CCE9249-69AE-11D9-BED3-505054503030}', 1, 1, 'Event 4627 lists the group membership of a logon token, which makes tier violations visible.')
        , @('Other System Events', '{0CCE9214-69AE-11D9-BED3-505054503030}', 3, 3, 'Windows turns this on by itself on a domain controller. Stating it means the audit mode can tell an intended setting from one that merely happens to be on, and notices if someone turns it off.')
        , @('Other Object Access Events', '{0CCE9227-69AE-11D9-BED3-505054503030}', 3, 3, 'Scheduled task creation and changes to them. A task is one of the quieter ways to hold persistence on a domain controller.')
        , @('Distribution Group Management', '{0CCE9238-69AE-11D9-BED3-505054503030}', 3, 0, 'Distribution groups are not security principals, but they are used for mail routing and are worth a record when they change.')
    )

    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $rows) {
        $out.Add([pscustomobject]@{
                Subcategory = $r[0]; Guid = $r[1]
                DcValue     = $r[2]; MemberValue = $r[3]; Why = $r[4]
            })
    }
    return $out.ToArray()
}

#endregion Baseline

####################################################################################################
#region Interactive
####################################################################################################

function Format-HardenWrapped {
    <#
        .SYNOPSIS
        Wraps a paragraph to the console width so explanations stay readable.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][string]$Text,
        [string]$Indent = '       ',
        [int]$Width = 0
    )

    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }

    if ($Width -le 0) {
        $Width = 78
        try { if ($Host.UI.RawUI.WindowSize.Width -gt 40) { $Width = $Host.UI.RawUI.WindowSize.Width - 2 } } catch { }
    }
    $room = [Math]::Max(30, $Width - $Indent.Length)

    $lines = [System.Collections.Generic.List[string]]::new()
    $line = ''
    foreach ($word in ($Text -split '\s+' | Where-Object { $_ })) {
        if ($line.Length -eq 0) { $line = $word }
        elseif (($line.Length + 1 + $word.Length) -le $room) { $line = "$line $word" }
        else { $lines.Add($Indent + $line); $line = $word }
    }
    if ($line) { $lines.Add($Indent + $line) }
    return $lines
}

function Get-HardenLiveValue {
    <#
        .SYNOPSIS
        Reads what a setting is on the directory server right now.

        .DESCRIPTION
        The question "should SMB signing be enabled" is only answerable next to "and what is it
        today". Values are read remotely from the context DC and cached for the run; a host that
        cannot be reached yields "unknown" rather than a guess, because a wrong current value is
        worse than an absent one.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Item)

    $ctx = Get-HardenContext

    $read = {
        param($regPath, $valueName)
        $key = "$($ctx.Server)|$regPath|$valueName"
        if ($script:LiveCache.ContainsKey($key)) { return $script:LiveCache[$key] }
        $result = 'unknown'
        try {
            $v = Invoke-Command -ComputerName $ctx.Server -ArgumentList $regPath, $valueName -ScriptBlock {
                param($p, $n)
                (Get-ItemProperty -Path $p -Name $n -ErrorAction SilentlyContinue).$n
            } -ErrorAction Stop
            $result = if ($null -eq $v) { 'not set' } else { "$v" }
        }
        catch { }
        $script:LiveCache[$key] = $result
        return $result
    }

    switch ($Item.Type) {
        'SecurityOption' {
            $path = 'HKLM:\' + (($Item.Key -replace '^MACHINE\\', '') | Split-Path -Parent)
            $name = Split-Path ($Item.Key) -Leaf
            return & $read $path $name
        }
        'AdminTemplate' {
            $path = $Item.RegKey -replace '^HKLM\\', 'HKLM:\'
            $parts = foreach ($v in $Item.Values) {
                $cur = & $read $path $v.Name
                if ($Item.Values.Count -eq 1) { $cur } else { "$($v.Name)=$cur" }
            }
            return ($parts -join ', ')
        }
        'StartupScript' {
            # There is no single registry value to read, so report what the machine looks like
            # today - the state the script would correct. Read from the directory server; a
            # member server's own state is only visible once the script has run there.
            $key = "$($ctx.Server)|netbt"
            if ($script:LiveCache.ContainsKey($key)) { return $script:LiveCache[$key] }
            $result = 'unknown'
            try {
                $vals = @(Invoke-Command -ComputerName $ctx.Server -ScriptBlock {
                        foreach ($i in (Get-ChildItem -LiteralPath 'HKLM:\System\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue)) {
                            $v = (Get-ItemProperty -LiteralPath $i.PSPath -Name NetbiosOptions -ErrorAction SilentlyContinue).NetbiosOptions
                            if ($null -eq $v) { 'not set' } else { "$v" }
                        }
                    } -ErrorAction Stop)
                if ($vals.Count -eq 0) { $result = 'no interfaces' }
                else {
                    $distinct = @($vals | Sort-Object -Unique)
                    $result = if ($distinct.Count -eq 1 -and $distinct[0] -eq '2') { 'startup script in the GPO' }
                    elseif ($distinct.Count -eq 1) { "DC interfaces at $($distinct[0])" }
                    else { "DC interfaces mixed: $($distinct -join '/')" }
                }
            }
            catch { }
            $script:LiveCache[$key] = $result
            return $result
        }

        'Service' {
            $key = "$($ctx.Server)|svc|$($Item.ServiceName)"
            if ($script:LiveCache.ContainsKey($key)) { return $script:LiveCache[$key] }
            $result = 'unknown'
            try {
                $svc = Invoke-Command -ComputerName $ctx.Server -ArgumentList $Item.ServiceName -ScriptBlock {
                    param($n) Get-Service -Name $n -ErrorAction SilentlyContinue
                } -ErrorAction Stop
                if ($svc) { $result = "$($svc.StartType), $($svc.Status)" }
            }
            catch { }
            $script:LiveCache[$key] = $result
            return $result
        }
        default { return '' }
    }
}

function Get-HardenTargetLabel {
    <#
        .SYNOPSIS
        What this run would set an item to, as text - or that it would not touch it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Item,
        [Parameter(Mandatory)][string]$Level
    )

    switch ($Item.Type) {
        'SecurityOption' {
            $v = if ($Item.Staged -and $Level -eq 'Audit') { $Item.AuditValue } else { $Item.EnforceValue }
            if ($null -eq $v) { return $null }
            $stage = if ($Item.Staged) { if ($Level -eq 'Audit') { ' (observing)' } else { ' (enforcing)' } } else { '' }
            return "$v$stage"
        }
        'AdminTemplate' {
            if ($Item.Values.Count -eq 1) { return "$($Item.Values[0].Value)" }
            $joined = ($Item.Values | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ', '
            # Five registry values spelled out push the line off the right of the console and make
            # the card harder to read than saying nothing. The names are in the report; here the
            # count plus the explanation is what the decision needs.
            if ($joined.Length -gt 42) { return "$($Item.Values.Count) values" }
            return $joined
        }
        'Service' {
            # Startup modes as the security template writes them: 2 automatic, 3 manual, 4 disabled.
            return $(switch ([int]$Item.StartupMode) {
                    2 { 'Automatic' }
                    3 { 'Manual' }
                    4 { 'Disabled' }
                    default { "startup mode $($Item.StartupMode)" }
                })
        }
        # Value only, no name prefix: the row already carries the setting name, and the live
        # reader has to produce a string that matches this one exactly for "already there" to work.
        'StartupScript' { return 'startup script in the GPO' }
        'AuditCsv' { return "$($Item.EnforceValue) subcategories" }
        default { return "$($Item.EnforceValue)" }
    }
}

function Request-HardenTopicDecision {
    <#
        .SYNOPSIS
        Asks whether one topic - SMB signing, Credential Guard - should be deployed, showing what
        each setting in it is today and what it would become.

        .DESCRIPTION
        One question per thing a person actually decides about, not per registry value. Credential
        Guard is three values that only make sense together; the topic is the unit of consent.

        The answer is cached by topic for the whole run, so the member-server pass reuses the
        domain-controller answer. Y and Enter deploy, N skips, A and S decide everything
        remaining, Q throws and the caller stops cleanly.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TopicName,
        [Parameter(Mandatory)][object[]]$Items,
        [Parameter(Mandatory)][string]$Role,
        [Parameter(Mandatory)][string]$GpoName,
        [Parameter(Mandatory)][string]$Level
    )

    if (-not $script:InteractiveMode) { return $true }
    if ($script:AutoDecision -eq 'All') { return $true }
    if ($script:AutoDecision -eq 'None') { return $false }

    if ($script:DecisionCache.ContainsKey($TopicName)) {
        $cached = $script:DecisionCache[$TopicName]
        Write-HardenLog -Message "$TopicName : $(if ($cached) { 'deploying' } else { 'skipping' }) - same answer as earlier in this run" -Level $(if ($cached) { 'Info' } else { 'Skip' })
        return $cached
    }

    # Rows first, so a topic where nothing would change at this level is not asked about at all.
    $rows = foreach ($item in $Items) {
        [pscustomobject]@{
            Item    = $item
            Target  = Get-HardenTargetLabel -Item $item -Level $Level
            Current = Get-HardenLiveValue -Item $item
        }
    }
    $active = @($rows | Where-Object { $null -ne $_.Target })
    if ($active.Count -eq 0) { return $true }

    $deployedItems = @($active | ForEach-Object { $_.Item })
    $risk = if (@($deployedItems | Where-Object { $_.Staged }).Count -gt 0) { 'STAGED' }
    elseif (@($deployedItems | Where-Object { $_.Profile -eq 'Strict' }).Count -gt 0) { 'STRICT' }
    else { 'BASELINE' }
    $riskColour = switch ($risk) { 'STAGED' { 'Yellow' } 'STRICT' { 'Magenta' } default { 'Green' } }

    Write-Host ''
    Write-Host ('  ' + ('-' * 74)) -ForegroundColor DarkGray
    Write-Host '   ' -NoNewline
    Write-Host $TopicName -ForegroundColor White -NoNewline
    Write-Host '  [' -ForegroundColor DarkGray -NoNewline
    Write-Host $risk -ForegroundColor $riskColour -NoNewline
    Write-Host ']' -ForegroundColor DarkGray
    $roleLabel = if ($Role -eq 'DC') { 'domain controllers' } else { 'member servers' }
    Write-Host ("       {0}  ->  {1}" -f $roleLabel, $GpoName) -ForegroundColor DarkGray
    Write-Host ''

    # Column width is a floor, not a ceiling: -f pads a short value but never truncates a long one,
    # so a service state like "Automatic, Running" would run straight into the arrow. One trailing
    # space guarantees the separation whatever the value turns out to be.
    $currentWidth = [Math]::Max(12, (($rows | ForEach-Object { "$($_.Current)".Length }) | Measure-Object -Maximum).Maximum)

    # Counted while rendering so the summary line below can say whether this topic does anything.
    $alreadyCount = 0
    $changeCount = 0

    foreach ($row in $rows) {
        $name = $row.Item.Name
        if ($name.Length -gt 40) { $name = $name.Substring(0, 39) + '~' }
        Write-Host ('       {0,-41}' -f $name) -ForegroundColor Gray -NoNewline
        Write-Host 'now: ' -ForegroundColor DarkGray -NoNewline

        if ($null -eq $row.Target) {
            Write-Host ("{0,-$currentWidth} " -f $row.Current) -ForegroundColor DarkGray -NoNewline
            Write-Host "not touched at Level $Level (Enforce: $($row.Item.EnforceValue))" -ForegroundColor DarkGray
        }
        elseif ($(
                $targetPlain = "$($row.Target)" -replace ' \((observing|enforcing)\)$', ''
                # (comparison below)
                $same = "$($row.Current)" -eq $targetPlain
                # A multi-string value like DependOnService compares by content, not order:
                # "MRxSmb20 NSI Bowser" and "Bowser MRxSmb20 NSI" are the same dependency list,
                # and showing that as a pending change makes the card cry wolf forever. Tokens are
                # atomic name=value or single words, so set equality cannot confuse two different
                # value assignments.
                if (-not $same -and $row.Current -ne 'not set' -and $row.Current -ne 'unknown' -and $targetPlain -match '\s') {
                    $a = @("$($row.Current)" -split '[,\s]+' | Where-Object { $_ }) | Sort-Object
                    $b = @($targetPlain -split '[,\s]+' | Where-Object { $_ }) | Sort-Object
                    $same = ($a.Count -eq $b.Count) -and (@(Compare-Object $a $b).Count -eq 0)
                }
                $same
            )) {
            # Deliberately dimmed, with only the verdict in colour. When three of four rows are
            # already correct, painting them all green makes the one row that needs a decision
            # look like just another line. The eye should land on the cyan.
            $alreadyCount++
            Write-Host ("{0,-$currentWidth} " -f $row.Current) -ForegroundColor DarkGray -NoNewline
            Write-Host "-> $($row.Target)   " -ForegroundColor DarkGray -NoNewline
            Write-Host 'already secure, no change' -ForegroundColor Green
        }
        else {
            $changeCount++
            Write-Host ("{0,-$currentWidth} " -f $row.Current) -ForegroundColor White -NoNewline
            Write-Host '-> ' -ForegroundColor DarkGray -NoNewline
            Write-Host $row.Target -ForegroundColor Cyan -NoNewline
            # An der Zeile, nicht im Fliesstext: eine Einstellung, die auf dieser Maschine gar
            # nicht gelesen wird, sieht sonst aus wie jede andere Aenderung.
            if ($row.Item.MinOS) { Write-Host "  [$($row.Item.MinOS)+]" -ForegroundColor DarkYellow } else { Write-Host '' }
        }
    }

    # Eine Zeile pro Thema statt pro Einstellung: bei fuenf SMB-Werten mit derselben
    # Mindestversion ist die Wiederholung Laerm, die Aussage aber wichtig.
    # Sorted by release, not alphabetically, and only the highest requirement is named: a topic
    # where one setting needs 2008 R2 and another needs 2025 is a 2025 topic for anyone deciding
    # whether it will do anything, and listing both reads as a choice between them.
    $osRank = @{ 'Server 2008 R2' = 1; 'Server 2012' = 2; 'Server 2016' = 3; 'Server 2019' = 4; 'Server 2022' = 5; 'Server 2025' = 6 }
    $osItems = @($deployedItems | Where-Object { $_.MinOS })
    if ($osItems.Count -gt 0) {
        $highest = ($osItems | Sort-Object { $osRank[[string]$_.MinOS] } -Descending | Select-Object -First 1).MinOS
        $atHighest = @($osItems | Where-Object { $_.MinOS -eq $highest }).Count
        Write-Host ''
        Write-Host ("       $atHighest of these need $highest or later. An older machine takes the policy, applies it and ignores it - nothing fails, nothing happens.") -ForegroundColor DarkYellow
    }

    $untouched = $rows.Count - $alreadyCount - $changeCount
    if ($rows.Count -gt 1) {
        Write-Host ''
        Write-Host '       ' -NoNewline
        if ($changeCount -eq 0) {
            Write-Host "Nothing to do - all $($rows.Count) already at the target value." -ForegroundColor Green
        }
        else {
            Write-Host "$changeCount of $($rows.Count) would change" -ForegroundColor Cyan -NoNewline
            $rest = @(
                if ($alreadyCount -gt 0) { "$alreadyCount already secure" }
                if ($untouched -gt 0) { "$untouched not touched at this level" }
            ) -join ', '
            if ($rest) { Write-Host ", $rest." -ForegroundColor DarkGray } else { Write-Host '.' -ForegroundColor DarkGray }
        }
    }

    # One intro, not one per value - and it has to be about the part that is actually going to
    # change. On a machine where three of four settings are already correct, leading with the
    # explanation of one of those three describes work that is not happening and buries the one
    # thing the person is being asked to approve.
    $changingItems = @($active | Where-Object {
            "$($_.Current)" -ne ("$($_.Target)" -replace ' \((observing|enforcing)\)$', '')
        } | ForEach-Object { $_.Item })
    $preferred = if ($changingItems.Count -gt 0) { $changingItems } else { $deployedItems }

    # Select-Object, never [0]: a baseline entry is an OrderedDictionary, and when a collection
    # holds exactly one of them PowerShell unwraps it - so [0] stops meaning "the first item" and
    # starts meaning "the first value inside that item", silently returning a string.
    $lead = ($preferred | Where-Object { $_.Staged } | Select-Object -First 1)
    if (-not $lead) { $lead = @($preferred) | Select-Object -First 1 }
    if ($lead.Why) {
        Write-Host ''
        foreach ($l in (Format-HardenWrapped -Text $lead.Why)) { Write-Host $l -ForegroundColor Gray }
    }

    # Same ordering for the caveats, so a two-item cap never drops the caveat that matters.
    $observes = @(
        @($preferred | Where-Object { $_.Observe } | ForEach-Object { $_.Observe })
        @($deployedItems | Where-Object { $_.Observe } | ForEach-Object { $_.Observe })
    ) | Select-Object -Unique | Select-Object -First 2
    if ($observes.Count -gt 0) {
        Write-Host ''
        Write-Host '       Watch out' -ForegroundColor Yellow
        foreach ($o in $observes) {
            foreach ($l in (Format-HardenWrapped -Text $o)) { Write-Host $l -ForegroundColor DarkYellow }
        }
    }

    if (@($deployedItems | Where-Object { $_.NeedsReboot }).Count -gt 0) {
        Write-Host ''
        Write-Host '       Takes effect at the next reboot, not immediately.' -ForegroundColor DarkYellow
    }

    $refs = @($deployedItems | Where-Object { $_.Reference } | ForEach-Object { $_.Reference -split ',\s*' } | Sort-Object -Unique)
    if ($refs.Count -gt 0) {
        Write-Host ''
        Write-Host '       Read more: ' -ForegroundColor DarkGray -NoNewline
        Write-Host (($refs | Select-Object -First 6) -join ', ') -ForegroundColor DarkCyan
    }

    while ($true) {
        Write-Host ''
        Write-Host '   [' -ForegroundColor DarkGray -NoNewline
        Write-Host 'Y' -ForegroundColor Green -NoNewline
        Write-Host ']es  [' -ForegroundColor DarkGray -NoNewline
        Write-Host 'N' -ForegroundColor Yellow -NoNewline
        Write-Host ']o  [' -ForegroundColor DarkGray -NoNewline
        Write-Host 'A' -ForegroundColor Green -NoNewline
        Write-Host ']ll remaining  [' -ForegroundColor DarkGray -NoNewline
        Write-Host 'S' -ForegroundColor Yellow -NoNewline
        Write-Host ']kip all remaining  [' -ForegroundColor DarkGray -NoNewline
        Write-Host 'Q' -ForegroundColor Red -NoNewline
        Write-Host ']uit' -ForegroundColor DarkGray

        $answer = (Read-Host "   Deploy $($TopicName)? (default Y)").Trim()
        if ([string]::IsNullOrEmpty($answer)) { $answer = 'Y' }

        switch ($answer.Substring(0, 1).ToUpper()) {
            'Y' { $script:DecisionCache[$TopicName] = $true; return $true }
            'N' { $script:DecisionCache[$TopicName] = $false; Write-HardenLog -Message "$TopicName : skipped on request" -Level Skip; return $false }
            'A' { $script:AutoDecision = 'All'; return $true }
            'S' { $script:AutoDecision = 'None'; Write-HardenLog -Message 'Skipping all remaining topics on request' -Level Skip; return $false }
            'Q' { throw 'HardenAbort' }
            default { Write-Host '   Not one of the options.' -ForegroundColor Red }
        }
    }
}

function Test-HardenTopicApproved {
    <#
        .SYNOPSIS
        Whether the topic an item belongs to was approved. True outside interactive mode.
    #>
    [CmdletBinding()]
    param(
        [object]$Item,
        [string]$Topic
    )

    if (-not $script:InteractiveMode) { return $true }
    if ($script:AutoDecision -eq 'All') { return $true }
    if ($script:AutoDecision -eq 'None') { return $false }

    $key = if ($Topic) { $Topic } else { $Item.Topic }
    if ($key -and $script:DecisionCache.ContainsKey($key)) { return $script:DecisionCache[$key] }
    return $true
}

#endregion Interactive

####################################################################################################
#region Gpo
####################################################################################################

function New-HardenGpoIfMissing {
    <#
        .SYNOPSIS
        Creates the GPO if it does not exist yet and returns it together with what happened.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Comment,
        [switch]$AuditOnly
    )

    $ctx = Get-HardenContext
    $gpo = Get-GPO -Name $Name -Domain $ctx.DomainFqdn -Server $ctx.Server -ErrorAction SilentlyContinue

    if ($gpo) { return [pscustomobject]@{ Gpo = $gpo; Result = 'Compliant' } }
    if ($AuditOnly) { return [pscustomobject]@{ Gpo = $null; Result = 'Missing' } }

    if ($PSCmdlet.ShouldProcess($Name, 'Create Group Policy Object')) {
        $gpo = New-GPO -Name $Name -Comment $Comment -Domain $ctx.DomainFqdn -Server $ctx.Server -ErrorAction Stop
        return [pscustomobject]@{ Gpo = $gpo; Result = 'Created' }
    }
    return [pscustomobject]@{ Gpo = $null; Result = 'Planned' }
}

function Get-HardenGpoPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][guid]$GpoId)
    $ctx = Get-HardenContext
    return Join-Path $ctx.SysvolPolicyPath ("{" + $GpoId.ToString().ToUpper() + "}")
}

function Set-HardenSecurityTemplate {
    <#
        .SYNOPSIS
        Writes the Security Options and service settings into the GPO's GptTmpl.inf.

        .DESCRIPTION
        The GroupPolicy module cannot set Security Options, so the security template is written
        into SYSVOL directly and the security client side extension is registered on the GPO.

        The file has to be UTF-16. Section order follows what secedit itself writes.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object]$Gpo,
        [hashtable]$RegistryValues = @{},
        [hashtable]$Services = @{},
        [switch]$AuditOnly
    )

    $gpoPath = Get-HardenGpoPath -GpoId $Gpo.Id
    $secDir = Join-Path $gpoPath 'Machine\Microsoft\Windows NT\SecEdit'
    $tmplPath = Join-Path $secDir 'GptTmpl.inf'

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('[Unicode]')
    [void]$sb.AppendLine('Unicode=yes')
    [void]$sb.AppendLine('[Version]')
    [void]$sb.AppendLine('signature="$CHICAGO$"')
    [void]$sb.AppendLine('Revision=1')

    if ($Services.Count -gt 0) {
        [void]$sb.AppendLine('[Service General Setting]')
        foreach ($name in ($Services.Keys | Sort-Object)) {
            # Name,startup mode,SDDL. An empty SDDL leaves the existing permissions alone.
            [void]$sb.AppendLine(('"{0}",{1},""' -f $name, $Services[$name]))
        }
    }

    if ($RegistryValues.Count -gt 0) {
        [void]$sb.AppendLine('[Registry Values]')
        foreach ($key in ($RegistryValues.Keys | Sort-Object)) {
            $entry = $RegistryValues[$key]
            [void]$sb.AppendLine(('{0}={1},{2}' -f $key, $entry.Type, $entry.Value))
        }
    }

    $content = $sb.ToString()

    if (Test-Path -LiteralPath $tmplPath) {
        $existing = Get-Content -LiteralPath $tmplPath -Raw -Encoding Unicode -ErrorAction SilentlyContinue
        if ($existing -and $existing.Trim() -eq $content.Trim()) { return 'Compliant' }
    }

    if ($AuditOnly) { return $(if (Test-Path -LiteralPath $tmplPath) { 'Drift' } else { 'Missing' }) }

    if (-not $PSCmdlet.ShouldProcess($Gpo.DisplayName, 'Write the security template')) { return 'Planned' }

    if (-not (Test-Path -LiteralPath $secDir)) {
        New-Item -Path $secDir -ItemType Directory -Force | Out-Null
    }
    if (Test-Path -LiteralPath $tmplPath) {
        Copy-Item -LiteralPath $tmplPath -Destination "$tmplPath.bak-$(Get-Date -Format 'yyyyMMddHHmmss')" -Force
    }

    # secedit reads UTF-16 and nothing else.
    Set-Content -LiteralPath $tmplPath -Value $content -Encoding Unicode -Force

    Add-HardenGpoExtension -Gpo $Gpo -CseGuid '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}' -ToolGuid '{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}'
    Update-HardenGpoVersion -Gpo $Gpo

    return 'Created'
}

function Set-HardenAuditCsv {
    <#
        .SYNOPSIS
        Writes the Advanced Audit Policy into the GPO as audit.csv.

        .DESCRIPTION
        Subcategories are written by GUID, so the file is identical on a localised system. The
        header line is fixed and the machine name column stays empty, which is what the policy
        engine expects for a GPO-delivered file.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object]$Gpo,
        [Parameter(Mandatory)][object[]]$Subcategories,
        [Parameter(Mandatory)][ValidateSet('DC', 'Member')][string]$Role,
        [switch]$AuditOnly
    )

    $gpoPath = Get-HardenGpoPath -GpoId $Gpo.Id
    $auditDir = Join-Path $gpoPath 'Machine\Microsoft\Windows NT\Audit'
    $csvPath = Join-Path $auditDir 'audit.csv'

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value')

    foreach ($sub in $Subcategories) {
        $value = if ($Role -eq 'DC') { $sub.DcValue } else { $sub.MemberValue }
        if ($value -eq 0) { continue }
        $inclusion = switch ($value) {
            1 { 'Success' }
            2 { 'Failure' }
            3 { 'Success and Failure' }
        }
        $lines.Add((',System,{0},{1},{2},,{3}' -f $sub.Subcategory, $sub.Guid.ToLower(), $inclusion, $value))
    }

    $content = ($lines -join "`r`n") + "`r`n"

    if (Test-Path -LiteralPath $csvPath) {
        $existing = Get-Content -LiteralPath $csvPath -Raw -ErrorAction SilentlyContinue
        if ($existing -and $existing.Trim() -eq $content.Trim()) { return 'Compliant' }
    }

    if ($AuditOnly) { return $(if (Test-Path -LiteralPath $csvPath) { 'Drift' } else { 'Missing' }) }
    if (-not $PSCmdlet.ShouldProcess($Gpo.DisplayName, 'Write the advanced audit policy')) { return 'Planned' }

    if (-not (Test-Path -LiteralPath $auditDir)) {
        New-Item -Path $auditDir -ItemType Directory -Force | Out-Null
    }
    # ASCII, not UTF8: Set-Content's UTF8 in PowerShell 5.1 writes a byte order mark, and the
    # mark lands in front of the header the audit CSE parses.
    Set-Content -LiteralPath $csvPath -Value $content -Encoding ASCII -Force

    # {F3CCC681-...} is the audit CSE itself (auditcse.dll); {0F3F3735-...} is its tool GUID.
    # Filing it as a tool GUID under the security CSE means auditcse never runs and the file is
    # ignored - see [MS-GPOD] on the CSE/tool GUID pair.
    Add-HardenGpoExtension -Gpo $Gpo -CseGuid '{F3CCC681-B74C-4060-9F26-CD84525DCA2A}' -ToolGuid '{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}'
    Update-HardenGpoVersion -Gpo $Gpo

    return 'Created'
}

function Add-HardenGpoExtension {
    <#
        .SYNOPSIS
        Registers a client side extension on the GPO so the client actually processes the file.

        .DESCRIPTION
        Without the entry in gPCMachineExtensionNames the file sits in SYSVOL and nothing reads it.

        The attribute is a list of bracketed groups, and each group is one CSE GUID followed by
        every tool GUID belonging to it - [{CSE}{tool}{tool}], not [{CSE}{tool}][{CSE}{tool}].
        Two groups carrying the same CSE GUID is malformed and breaks policy processing on the
        client with errors that name no useful cause, so a CSE that is already present has its
        tool GUID merged into the existing group instead of getting a second one.

        Groups are sorted by CSE GUID and tool GUIDs within a group are sorted too, which is what
        the GPMC itself writes and what avoids duplicates when someone later edits the GPO by hand.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Gpo,
        [Parameter(Mandatory)][string]$CseGuid,
        [Parameter(Mandatory)][string]$ToolGuid
    )

    $ctx = Get-HardenContext
    $ad = Get-HardenAdParameter
    $dn = "CN={$($Gpo.Id.ToString().ToUpper())},CN=Policies,CN=System,$($ctx.DomainDn)"

    $obj = Get-ADObject -Identity $dn -Properties gPCMachineExtensionNames @ad -ErrorAction Stop
    $current = [string]$obj.gPCMachineExtensionNames

    $cse = $CseGuid.ToUpper()
    $tool = $ToolGuid.ToUpper()

    # CSE GUID -> set of tool GUIDs
    $groups = [ordered]@{}
    foreach ($m in [regex]::Matches($current, '\[([^\]]+)\]')) {
        $guids = @([regex]::Matches($m.Groups[1].Value, '\{[^}]+\}') | ForEach-Object { $_.Value.ToUpper() })
        if ($guids.Count -eq 0) { continue }
        $head = $guids[0]
        $tail = @($guids | Select-Object -Skip 1)
        if ($groups.Contains($head)) { $groups[$head] = @($groups[$head] + $tail) }
        else { $groups[$head] = $tail }
    }

    if ($groups.Contains($cse)) {
        if ($groups[$cse] -contains $tool) { return }
        $groups[$cse] = @($groups[$cse] + $tool)
    }
    else {
        $groups[$cse] = @($tool)
    }

    $merged = ''
    foreach ($head in ($groups.Keys | Sort-Object)) {
        $tail = @($groups[$head] | Sort-Object -Unique)
        $merged += '[' + $head + ($tail -join '') + ']'
    }

    if ([string]::IsNullOrEmpty($current)) {
        Set-ADObject -Identity $dn -Add @{ gPCMachineExtensionNames = $merged } @ad -ErrorAction Stop
    }
    else {
        Set-ADObject -Identity $dn -Replace @{ gPCMachineExtensionNames = $merged } @ad -ErrorAction Stop
    }
}

function Set-HardenStartupScript {
    <#
        .SYNOPSIS
        Puts a startup script into the GPO, for the few settings Group Policy cannot express as a
        registry value.

        .DESCRIPTION
        Some settings live under a key whose name is a per-machine GUID. NetBIOS over TCP/IP is
        the example: it is configured per network interface under
        Services\NetBT\Parameters\Interfaces\Tcpip_{guid}, and no policy can name a key it cannot
        know in advance.

        The obvious workaround is to have the tool write to the machines directly. This does not,
        deliberately - it stays a tool that only makes GPOs, because that is what gives every
        other setting here its two best properties: it reaches whatever the OU contains without
        an inventory, and it survives a rebuild. A machine reinstalled next year picks the script
        up at its first boot with no one remembering to do anything.

        Mechanically this is the same shape as the security template and the audit policy: write
        the file into SYSVOL, register the client side extension, bump the version. Three details
        that are easy to get wrong and silent when wrong:

          - PowerShell scripts are listed in psscripts.ini, not scripts.ini, and that file must be
            UTF-16. GPMC also marks it hidden; the client does not care but an administrator
            comparing folders will.
          - The CSE pair is {42B5FAAE-...}{40B6664F-...} for machine scripts. The 40B66650 variant
            is the user half and registering that one instead means the script never runs.
          - Entries are numbered. Appending a second script with index 0 replaces the first
            rather than adding to it, so the existing file is read and the next free index used.

        The timing is worth stating plainly: a startup script runs after the services it might
        want to influence have already started. For NetBIOS that means the value is written at
        one boot and takes effect at the next. Two restarts, not one.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object]$Gpo,
        [Parameter(Mandatory)][object]$Item,
        [switch]$AuditOnly
    )

    # -GpoId, not -Gpo: PowerShell would bind -Gpo to -GpoId by prefix match and then fail to
    # convert the GPO object into a Guid, with an error naming this function rather than the call.
    $gpoPath = Get-HardenGpoPath -GpoId $Gpo.Id
    $scriptDir = Join-Path $gpoPath 'Machine\Scripts\Startup'
    $iniPath = Join-Path $gpoPath 'Machine\Scripts\psscripts.ini'
    $scriptPath = Join-Path $scriptDir $Item.ScriptName

    $existing = if (Test-Path -LiteralPath $scriptPath) { Get-Content -LiteralPath $scriptPath -Raw } else { $null }
    $iniText = if (Test-Path -LiteralPath $iniPath) { Get-Content -LiteralPath $iniPath -Raw } else { '' }
    $listed = $iniText -match [regex]::Escape($Item.ScriptName)

    if ($existing -and $existing.Trim() -eq $Item.ScriptBody.Trim() -and $listed) {
        Write-HardenLog -Message "Startup script $($Item.ScriptName): already in place" -Level Skip
        Add-HardenAction -Area $Item.Group -Setting $Item.Id -Target $Gpo.DisplayName -Result 'Compliant'
        return 'Compliant'
    }

    if ($AuditOnly) {
        Write-HardenLog -Message "Startup script $($Item.ScriptName): missing" -Level Info
        Add-HardenAction -Area $Item.Group -Setting $Item.Id -Target $Gpo.DisplayName -Result 'Missing'
        return 'Missing'
    }

    if (-not $PSCmdlet.ShouldProcess($Gpo.DisplayName, "Write the startup script $($Item.ScriptName)")) {
        Add-HardenAction -Area $Item.Group -Setting $Item.Id -Target $Gpo.DisplayName -Result 'Planned'
        return 'Planned'
    }

    $result = if ($existing -or $listed) { 'Updated' } else { 'Created' }

    New-Item -Path $scriptDir -ItemType Directory -Force -WhatIf:$false -Confirm:$false | Out-Null
    # ASCII: the script is plain PowerShell and a BOM in front of the first line has caused
    # enough grief elsewhere in this tool already.
    Set-Content -LiteralPath $scriptPath -Value $Item.ScriptBody -Encoding ASCII -Force -WhatIf:$false -Confirm:$false

    # Next free index under [Startup], so an existing script in the same GPO is not overwritten.
    # Built by walking the lines rather than slicing them: $lines[1..0] on a one-element array is
    # a descending range, which silently duplicates the section header instead of appending
    # nothing.
    $lines = if ($iniText) { @($iniText -split "`r?`n") } else { @() }
    if (-not $listed) {
        $used = @($lines | ForEach-Object { if ($_ -match '^\s*(\d+)CmdLine\s*=') { [int]$Matches[1] } })
        $next = if ($used.Count -gt 0) { ($used | Measure-Object -Maximum).Maximum + 1 } else { 0 }
        $entry = @("${next}CmdLine=$($Item.ScriptName)", "${next}Parameters=")

        $out = [System.Collections.Generic.List[string]]::new()
        $inserted = $false
        foreach ($line in $lines) {
            $out.Add($line)
            if (-not $inserted -and $line.Trim() -eq '[Startup]') {
                foreach ($x in $entry) { $out.Add($x) }
                $inserted = $true
            }
        }
        if (-not $inserted) {
            $out.Insert(0, '[Startup]')
            for ($i = 0; $i -lt $entry.Count; $i++) { $out.Insert($i + 1, $entry[$i]) }
        }
        $lines = $out.ToArray()
    }

    # Trailing blank lines accumulate on every rewrite otherwise.
    $text = (($lines | Where-Object { $null -ne $_ }) -join "`r`n").TrimEnd("`r", "`n")

    # UTF-16, which is what the scripts CSE reads - the same requirement as GptTmpl.inf.
    Set-Content -LiteralPath $iniPath -Value $text -Encoding Unicode -Force -WhatIf:$false -Confirm:$false
    try { (Get-Item -LiteralPath $iniPath -Force).Attributes = 'Hidden' } catch { }

    Add-HardenGpoExtension -Gpo $Gpo -CseGuid '{42B5FAAE-6536-11D2-AE5A-0000F87571E3}' -ToolGuid '{40B6664F-4972-11D1-A7CA-0000F87571E3}'
    Update-HardenGpoVersion -Gpo $Gpo

    Write-HardenLog -Message "Startup script $($Item.ScriptName): $result" -Level Success
    Add-HardenAction -Area $Item.Group -Setting $Item.Id -Target $Gpo.DisplayName -Result $result -Detail $Item.ScriptName
    return $result
}

function Update-HardenGpoVersion {
    <#
        .SYNOPSIS
        Bumps the machine half of the GPO version so clients notice the change.

        .DESCRIPTION
        versionNumber packs the user version in the high 16 bits and the machine version in the
        low 16. Writing files into SYSVOL without raising this leaves clients believing they are
        already up to date. GPT.INI has to match.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Gpo)

    $ctx = Get-HardenContext
    $ad = Get-HardenAdParameter
    $dn = "CN={$($Gpo.Id.ToString().ToUpper())},CN=Policies,CN=System,$($ctx.DomainDn)"

    $obj = Get-ADObject -Identity $dn -Properties versionNumber @ad -ErrorAction Stop
    $version = [int]$obj.versionNumber
    $user = ($version -shr 16) -band 0xFFFF
    # The machine half is 16 bits. Rolling over rather than spilling into the user half, which is
    # what a plain +1 would eventually do on a GPO that has been edited 65535 times.
    $machine = (($version -band 0xFFFF) + 1) -band 0xFFFF
    $new = ($user -shl 16) -bor $machine

    Set-ADObject -Identity $dn -Replace @{ versionNumber = $new } @ad -ErrorAction Stop

    $gptIni = Join-Path (Get-HardenGpoPath -GpoId $Gpo.Id) 'GPT.INI'
    if (Test-Path -LiteralPath $gptIni) {
        $content = Get-Content -LiteralPath $gptIni
        $content = $content -replace '^Version=\d+', "Version=$new"
        Set-Content -LiteralPath $gptIni -Value $content -Force
    }
    else {
        Set-Content -LiteralPath $gptIni -Value @('[General]', "Version=$new") -Force
    }
}

function Set-HardenRegistrySetting {
    <#
        .SYNOPSIS
        Sets one registry policy value in the GPO through the GroupPolicy module.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$GpoName,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$ValueName,
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)]$Value,
        [switch]$AuditOnly
    )

    $ctx = Get-HardenContext
    $existing = Get-GPRegistryValue -Name $GpoName -Key $Key -ValueName $ValueName `
        -Domain $ctx.DomainFqdn -Server $ctx.Server -ErrorAction SilentlyContinue

    if ($existing -and "$($existing.Value)" -eq "$Value") { return 'Compliant' }
    if ($AuditOnly) { return $(if ($existing) { 'Drift' } else { 'Missing' }) }

    if ($PSCmdlet.ShouldProcess("$GpoName : $ValueName", "Set to $Value")) {
        Set-GPRegistryValue -Name $GpoName -Key $Key -ValueName $ValueName -Type $Type -Value $Value `
            -Domain $ctx.DomainFqdn -Server $ctx.Server -ErrorAction Stop | Out-Null
        return $(if ($existing) { 'Updated' } else { 'Created' })
    }
    return 'Planned'
}

function Set-HardenGpoLink {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$GpoName,
        [Parameter(Mandatory)][string]$TargetDn,
        [switch]$AuditOnly
    )

    $ctx = Get-HardenContext
    $inheritance = Get-GPInheritance -Target $TargetDn -Domain $ctx.DomainFqdn -Server $ctx.Server -ErrorAction Stop
    $link = $inheritance.GpoLinks | Where-Object { $_.DisplayName -eq $GpoName }

    if ($link -and $link.Enabled) { return 'Compliant' }
    if ($AuditOnly) { return $(if ($link) { 'Drift' } else { 'Missing' }) }

    if ($PSCmdlet.ShouldProcess("$GpoName -> $TargetDn", 'Link GPO')) {
        if ($link) {
            Set-GPLink -Name $GpoName -Target $TargetDn -LinkEnabled Yes -Domain $ctx.DomainFqdn -Server $ctx.Server -ErrorAction Stop | Out-Null
            return 'Updated'
        }
        New-GPLink -Name $GpoName -Target $TargetDn -LinkEnabled Yes -Domain $ctx.DomainFqdn -Server $ctx.Server -ErrorAction Stop | Out-Null
        return 'Created'
    }
    return 'Planned'
}

#endregion Gpo

####################################################################################################
#region Scan
####################################################################################################

function Invoke-HardenScan {
    <#
        .SYNOPSIS
        Reads what the domain is doing today and says which settings are safe to enforce.

        .DESCRIPTION
        This is the mode to run first, and the reason the tool exists in this shape. Enforcing
        signing or restricting NTLM without knowing who relies on them is how a maintenance window
        turns into an outage.

        Four sources are read, all read-only:

          the domain controllers' Directory Service log   unsigned LDAP binds, weak certificate mapping
          the NTLM operational log                        who still authenticates with NTLM
          the directory                                   accounts that cannot do AES, stale objects
          the current registry state on the DCs           what is already set

        Nothing here changes anything.
    #>
    [CmdletBinding()]
    param(
        [int]$Days = 30,
        [ValidateSet('Audit', 'Enforce')][string]$Level = 'Audit',
        [ValidateSet('Baseline', 'Strict')][string]$HardeningProfile = 'Baseline',
        [string[]]$Area = @('Signing', 'LegacyAuth', 'CredentialProtection', 'Protocols', 'PolicyIntegrity', 'Logging', 'Services')
    )

    $ctx = Get-HardenContext
    $ad = Get-HardenAdParameter
    $blockers = [System.Collections.Generic.List[string]]::new()

    Write-HardenLog -Message "Scan over the last $Days day(s)" -Level Header

    $dcs = @(Get-ADDomainController -Filter * @ad -ErrorAction SilentlyContinue)
    Write-HardenLog -Message "$($dcs.Count) domain controller(s) in $($ctx.DomainFqdn)" -Level Info

    # -- unsigned LDAP binds -------------------------------------------------------------------
    Write-HardenLog -Message 'Unsigned and unsealed LDAP binds' -Level Header
    $ldapTotal = 0
    foreach ($dc in $dcs) {
        try {
            # Get-WinEvent throws rather than returning nothing when a filter matches no events,
            # so an empty log has to be told apart from a log that could not be read at all.
            # Reporting "not readable" for a clean DC would be exactly the wrong way round.
            $events = @()
            try {
                $events = @(Get-WinEvent -ComputerName $dc.HostName -FilterHashtable @{
                        LogName = 'Directory Service'; Id = 2889; StartTime = (Get-Date).AddDays(-$Days)
                    } -ErrorAction Stop)
            }
            catch [System.Exception] {
                if ($_.Exception.Message -notmatch 'No events were found') { throw }
            }
            $ldapTotal += $events.Count

            if ($events.Count -eq 0) {
                Write-HardenLog -Message "$($dc.HostName): none" -Level Success
                continue
            }

            # Event 2889 carries the client address and the account in the message body.
            $clients = $events | ForEach-Object {
                ($_.Message -split "`n" | Where-Object { $_ -match ':\s*\d+\.\d+\.\d+\.\d+' } | Select-Object -First 1)
            } | Where-Object { $_ } | ForEach-Object { $_.Trim() }

            Write-HardenLog -Message "$($dc.HostName): $($events.Count) unsigned bind(s) from $((@($clients | Sort-Object -Unique)).Count) client(s)" -Level Warning
            foreach ($c in ($clients | Group-Object | Sort-Object Count -Descending | Select-Object -First 10)) {
                Write-HardenLog -Message "    $($c.Count)x  $($c.Name)" -Level Info
            }
            Add-HardenAction -Area 'Scan' -Setting 'LDAP-ServerSigning' -Target $dc.HostName -Result 'Observed' `
                -Detail "$($events.Count) unsigned binds in $Days days" -Severity 'High'
        }
        catch {
            Write-HardenLog -Message "$($dc.HostName): log not readable - $($_.Exception.Message)" -Level Warning
            Add-HardenAction -Area 'Scan' -Setting 'LDAP-ServerSigning' -Target $dc.HostName -Result 'Failed' -Detail $_.Exception.Message
        }
    }

    if ($ldapTotal -gt 0) {
        $blockers.Add("LDAP signing: $ldapTotal unsigned bind(s) recorded. Enforcing now would break those clients.")
    }
    else {
        Write-HardenLog -Message 'No unsigned binds recorded. Note that this only counts if event 2889 logging was already on - see LDAP diagnostics below.' -Level Info
    }

    # -- is the diagnostic even enabled? -------------------------------------------------------
    Write-HardenLog -Message 'LDAP interface diagnostics' -Level Header
    foreach ($dc in $dcs) {
        try {
            $val = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\NTDS\Diagnostics' -Name '16 LDAP Interface Events' -ErrorAction SilentlyContinue).'16 LDAP Interface Events'
            } -ErrorAction Stop

            if ($val -ge 2) {
                Write-HardenLog -Message "$($dc.HostName): diagnostics level $val - unsigned binds are being recorded" -Level Success
            }
            else {
                Write-HardenLog -Message "$($dc.HostName): diagnostics level $(if ($null -eq $val) { 0 } else { $val }) - event 2889 is NOT being written, so an empty result above means nothing" -Level Warning
                $blockers.Add("$($dc.HostName): LDAP interface diagnostics off, so the clean LDAP result above is meaningless. Deploy it with -Mode Deploy -Area Logging -Apply, which enforces nothing, then leave it running for a full business cycle including month-end before trusting the count.")
            }
        }
        catch {
            Write-HardenLog -Message "$($dc.HostName): could not read diagnostics - $($_.Exception.Message)" -Level Warning
        }
    }

    # -- NTLM usage ----------------------------------------------------------------------------
    Write-HardenLog -Message 'NTLM authentication' -Level Header
    $ntlmTotal = 0
    $ntlmByEvent = @{}
    foreach ($dc in $dcs) {
        try {
            $events = @()
            try {
                $events = @(Get-WinEvent -ComputerName $dc.HostName -FilterHashtable @{
                        LogName = 'Microsoft-Windows-NTLM/Operational'; StartTime = (Get-Date).AddDays(-$Days)
                    } -ErrorAction Stop)
            }
            catch [System.Exception] {
                if ($_.Exception.Message -notmatch 'No events were found') { throw }
            }
            # Not $level: this function has a -Level parameter with a ValidateSet, and assigning
            # a log severity to it fails validation at runtime. PowerShell variable names are case
            # insensitive, so $level and $Level are the same variable.
            $logLevel = if ($events.Count -gt 0) { 'Warning' } else { 'Info' }
            Write-HardenLog -Message "$($dc.HostName): $($events.Count) NTLM event(s)" -Level $logLevel

            if ($events.Count -gt 0) {
                # A bare count says nothing about what would break, and the directions are easy
                # to get backwards - this classification follows the Microsoft assessment guide:
                # 8001 is written on the machine that went OUT with NTLM, 8002 on the machine
                # that RECEIVED it, 8003/8004 are the domain-wide audit as seen by a member and
                # the DC respectively. The 40xx series is the Server 2025 / Win11 24H2 enhanced
                # auditing (KB5064479) - richer detail, same story.
                foreach ($g in ($events | Group-Object Id | Sort-Object Count -Descending)) {
                    $id = [int]$g.Name
                    $meaning = switch ($id) {
                        8001 { 'outgoing NTLM from this machine' }
                        8002 { 'incoming NTLM to this machine' }
                        8003 { 'NTLM in this domain, member server view' }
                        8004 { 'NTLM in this domain, seen by the DC - names user and workstation' }
                        4001 { 'outgoing NTLM that was blocked' }
                        4002 { 'incoming NTLM that was blocked' }
                        4003 { 'domain NTLM that was blocked, member view' }
                        4004 { 'domain NTLM that was blocked, DC view' }
                        4014 { 'per-authentication NTLM detail (Server 2025 enhanced auditing) - includes why NTLM was chosen' }
                        4024 { 'NTLMv1-derived credentials used - remediate before October 2026 enforcement' }
                        4025 { 'NTLMv1-derived credentials blocked' }
                        default {
                            if ($id -in 4020..4023) { 'enhanced NTLM audit, client and server side (KB5064479)' }
                            elseif ($id -in 4030..4033) { 'enhanced NTLM audit on the DC (KB5064479) - 4032 names the NTLM version' }
                            else { 'other NTLM activity' }
                        }
                    }
                    if (-not $ntlmByEvent.ContainsKey($id)) { $ntlmByEvent[$id] = 0 }
                    $ntlmByEvent[$id] = $ntlmByEvent[$id] + $g.Count
                    Write-HardenLog -Message "    $($g.Count)x  event $($g.Name) - $meaning" -Level Info
                }

                # The account and workstation names sit in the message body. Pulling the most
                # frequent ones out is the difference between "91 events" and a name to call.
                $names = $events | ForEach-Object {
                    $_.Message -split "`n" | Where-Object { $_ -match '^\s*(User Name|Workstation Name|Secure Channel Name|Domain Name)\s*:' }
                } | Where-Object { $_ } | ForEach-Object { $_.Trim() }

                foreach ($n in ($names | Group-Object | Sort-Object Count -Descending | Select-Object -First 8)) {
                    Write-HardenLog -Message "    $($n.Count)x  $($n.Name)" -Level Info
                }

                Add-HardenAction -Area 'Scan' -Setting 'NTLM-Usage' -Target $dc.HostName -Result 'Observed' `
                    -Detail "$($events.Count) NTLM events in $Days days" -Severity 'High'
            }

            # Counted last, so a failure part way through does not leave a total that the
            # per-event breakdown cannot account for - which reads as "events with no direction"
            # and sends someone looking in the wrong place.
            $ntlmTotal += $events.Count
        }
        catch {
            Write-HardenLog -Message "$($dc.HostName): NTLM operational log not readable - $($_.Exception.Message)" -Level Warning
        }
    }

    if ($ntlmTotal -eq 0) {
        Write-HardenLog -Message 'No NTLM events. Turn on NTLM auditing first (it is in the Baseline profile) and come back in a few weeks - a silent log here is not evidence of absence.' -Level Info
    }
    else {
        # This is the whole point of the scan: NTLM in the log means the restricting settings
        # have something to refuse. Which one is at risk depends on the direction, and each
        # direction maps to exactly one policy.
        $get = { param($k) if ($ntlmByEvent.ContainsKey($k)) { $ntlmByEvent[$k] } else { 0 } }
        $outbound = (& $get 8001) + (& $get 4001)
        $inbound = (& $get 8002) + (& $get 4002)
        $domain = (& $get 8003) + (& $get 8004) + (& $get 4003) + (& $get 4004)
        $detail = (& $get 4014)
        $v1 = (& $get 4024) + (& $get 4025)

        if ($outbound -gt 0) {
            $blockers.Add("NTLM outbound: $outbound authentication(s) left this machine. Deny outgoing NTLM at 2 refuses every one - the 8001 events name the target servers.")
        }
        if ($inbound -gt 0) {
            $blockers.Add("NTLM inbound: $inbound authentication(s) reached this machine. Deny incoming NTLM at 2 refuses every one - the 8002 events name the calling process.")
        }
        if ($domain -gt 0) {
            $blockers.Add("NTLM in the domain: $domain authentication(s) observed by the domain audit. The 8004 events on the DC name user, workstation and target - this list is the migration worklist.")
        }
        if ($v1 -gt 0) {
            $blockers.Add("NTLMv1-derived credentials: $v1 event(s). These stop working with the October 2026 enforcement regardless of anything this tool does - remediate first.")
        }
        if ($outbound -eq 0 -and $inbound -eq 0 -and $domain -eq 0 -and $v1 -eq 0) {
            if ($detail -gt 0) {
                Write-HardenLog -Message "NTLM detail events only (4014): usage records with the reason NTLM was chosen - missing SPNs and IP-address access are the usual ones. Worth reading, but nothing here blocks enforcement by itself." -Level Info
            }
            else {
                $blockers.Add("NTLM: $ntlmTotal event(s) recorded that carry no direction this tool recognises. Read the NTLM operational log before restricting anything.")
            }
        }
    }

    # -- accounts that cannot do AES -----------------------------------------------------------
    Write-HardenLog -Message 'Kerberos encryption support' -Level Header
    try {
        # msDS-SupportedEncryptionTypes: bit 0x4 is RC4, 0x8 and 0x10 are AES128 and AES256.
        # An account with the attribute unset falls back to whatever the DC allows.
        # Bitwise AND (1.2.840.113556.1.4.803), not equality: an account at 0x7 or 0x4 both allow
        # RC4 and only the first matches =4. What matters is RC4 on and no AES bit set at all.
        $rc4Only = @(Get-ADObject -LDAPFilter '(&(|(objectClass=user)(objectClass=computer))(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.803:=4)(!(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.803:=24)))' `
                -Properties samAccountName, msDS-SupportedEncryptionTypes @ad -ErrorAction Stop)
        $unset = @(Get-ADUser -LDAPFilter '(&(servicePrincipalName=*)(!(msDS-SupportedEncryptionTypes=*)))' @ad -ErrorAction SilentlyContinue)

        if ($rc4Only.Count -gt 0) {
            Write-HardenLog -Message "$($rc4Only.Count) object(s) explicitly limited to RC4 - these stop authenticating if AES is enforced" -Level Warning
            foreach ($o in ($rc4Only | Select-Object -First 15)) { Write-HardenLog -Message "    $($o.Name)" -Level Info }
            $blockers.Add("Kerberos AES: $($rc4Only.Count) object(s) are set to RC4 only.")
        }
        else {
            Write-HardenLog -Message 'No object is explicitly limited to RC4' -Level Success
        }

        if ($unset.Count -gt 0) {
            Write-HardenLog -Message "$($unset.Count) service account(s) have no encryption type set at all - they inherit the DC setting, so test before enforcing AES" -Level Info
        }
    }
    catch {
        Write-HardenLog -Message "Encryption type check failed - $($_.Exception.Message)" -Level Warning
    }

    # -- krbtgt password age -------------------------------------------------------------------
    Write-HardenLog -Message 'krbtgt password age' -Level Header
    try {
        $krbtgt = Get-ADUser -Identity "$($ctx.DomainSid)-502" -Properties PasswordLastSet, whenCreated @ad -ErrorAction Stop
        $set = $krbtgt.PasswordLastSet
        if (-not $set) { $set = $krbtgt.whenCreated }
        $age = [int]((Get-Date) - $set).TotalDays

        Write-HardenLog -Message "Last changed $($set.ToString('yyyy-MM-dd')) - $age day(s) ago" -Level $(
            if ($age -gt 365) { 'Error' } elseif ($age -gt 180) { 'Warning' } else { 'Success' })

        if ($age -gt 365) {
            Write-HardenLog -Message 'Every Kerberos ticket in the domain is signed with this key. A golden ticket forged at any point since that date is still valid today, and nothing in the directory will tell you one exists.' -Level Warning
            $blockers.Add("krbtgt password is $age days old. Reset it twice, with a full replication cycle plus the maximum ticket lifetime in between - resetting twice in quick succession invalidates every ticket at once and takes the domain down with it.")
            Add-HardenAction -Area 'Scan' -Setting 'krbtgt-PasswordAge' -Target $ctx.DomainFqdn -Result 'Drift' -Detail "$age days" -Severity 'High'
        }
        elseif ($age -gt 180) {
            Write-HardenLog -Message 'Past the point where a yearly rotation would have run. Worth scheduling.' -Level Info
            Add-HardenAction -Area 'Scan' -Setting 'krbtgt-PasswordAge' -Target $ctx.DomainFqdn -Result 'Observed' -Detail "$age days" -Severity 'Medium'
        }
        else {
            Add-HardenAction -Area 'Scan' -Setting 'krbtgt-PasswordAge' -Target $ctx.DomainFqdn -Result 'Compliant' -Detail "$age days"
        }

        # A domain that was ever at 2003 functional level may still carry the second krbtgt
        # account used for RODCs, and read-only DCs each have their own.
        $others = @(Get-ADUser -LDAPFilter '(&(objectClass=user)(sAMAccountName=krbtgt_*))' -Properties PasswordLastSet @ad -ErrorAction SilentlyContinue)
        foreach ($o in $others) {
            $oAge = if ($o.PasswordLastSet) { [int]((Get-Date) - $o.PasswordLastSet).TotalDays } else { $null }
            Write-HardenLog -Message "$($o.SamAccountName): $(if ($null -eq $oAge) { 'never changed' } else { "$oAge day(s)" })" -Level Info
        }
    }
    catch {
        Write-HardenLog -Message "krbtgt could not be read - $($_.Exception.Message)" -Level Warning
        Add-HardenAction -Area 'Scan' -Setting 'krbtgt-PasswordAge' -Target $ctx.DomainFqdn -Result 'Failed' -Detail $_.Exception.Message
    }

    # -- what is set today ---------------------------------------------------------------------
    # Scoped, because being asked about one group and answered about all seven is how a report
    # gets skimmed. The event log sections above stay unscoped on purpose - they describe the
    # domain, not a group, and their findings are what gate any later enforcement.
    $allGroups = 'Signing', 'LegacyAuth', 'CredentialProtection', 'Protocols', 'PolicyIntegrity', 'Logging', 'Services'
    $scoped = @($Area | Where-Object { $_ -in $allGroups })
    $header = if ($scoped.Count -lt $allGroups.Count) {
        "Current state on the domain controllers - $($scoped -join ', ')"
    }
    else { 'Current state on the domain controllers' }

    Write-HardenLog -Message $header -Level Header
    # Not filtered by profile, but marked: a Strict setting shown here without a word about it
    # reads as something a default deployment would fix, and then does not. Same trap as -Area
    # being ignored - the scan answering about more than the deployment would touch.
    $baseline = @(Get-HardenBaseline | Where-Object {
            $_.Type -eq 'SecurityOption' -and $_.Target -in 'DC', 'Both' -and $_.Group -in $scoped -and
            ($HardeningProfile -eq 'Strict' -or $_.Profile -eq 'Baseline' -or $_.Profile -eq 'Strict')
        })
    $strictCount = @($baseline | Where-Object { $_.Profile -eq 'Strict' -and $HardeningProfile -ne 'Strict' }).Count
    if ($baseline.Count -eq 0) {
        Write-HardenLog -Message "No registry-backed settings in $($scoped -join ', ') - that group is delivered another way, so there is nothing to read here." -Level Info
    }
    elseif ($strictCount -gt 0) {
        Write-HardenLog -Message "$strictCount of these belong to the Strict profile and are marked as such - deploying without -Profile Strict leaves them alone." -Level Info
    }
    $dc = $dcs | Select-Object -First 1

    if ($dc) {
        foreach ($item in $baseline) {
            $path = 'HKLM:\' + ($item.Key -replace '^MACHINE\\', '') 
            $valueName = Split-Path $path -Leaf
            $regPath = Split-Path $path -Parent
            try {
                $current = Invoke-Command -ComputerName $dc.HostName -ArgumentList $regPath, $valueName -ScriptBlock {
                    param($p, $v)
                    (Get-ItemProperty -Path $p -Name $v -ErrorAction SilentlyContinue).$v
                } -ErrorAction Stop

                # Compare against what this run would actually write. Showing the enforcing value
                # while running at Level Audit invites someone to deploy straight to Enforce
                # because the scan appeared to ask for it.
                $target = if ($item.Staged -and $Level -eq 'Audit') { $item.AuditValue } else { $item.EnforceValue }

                if ($null -eq $target) {
                    # Staged with no observation form: nothing is deployed at this level, so there
                    # is no target to compare against and reporting one would be misleading.
                    $shown = if ($null -eq $current) { 'not set' } else { $current }
                    Write-HardenLog -Message "$($item.Name): $shown - not deployed at Level Audit, would become $($item.EnforceValue) at Level Enforce" -Level Skip
                    Add-HardenAction -Area 'Scan' -Setting $item.Id -Target $dc.HostName -Result 'Observed' `
                        -Detail "Currently $shown; enforcing value $($item.EnforceValue)"
                }
                elseif ("$current" -eq "$target") {
                    Write-HardenLog -Message "$($item.Name): already $current" -Level Success
                    Add-HardenAction -Area 'Scan' -Setting $item.Id -Target $dc.HostName -Result 'Compliant' -Detail "Value $current"
                }
                elseif ($null -eq $current -and $item.Contains('DefaultWhenUnset') -and "$($item.DefaultWhenUnset)" -eq "$target") {
                    # Absent, but Windows behaves as though it were set. Not a gap - deploying it
                    # still pins the value against later drift, which is why it stays in the
                    # baseline rather than being dropped.
                    Write-HardenLog -Message "$($item.Name): not set, platform default is already $($item.DefaultWhenUnset)" -Level Success
                    Add-HardenAction -Area 'Scan' -Setting $item.Id -Target $dc.HostName -Result 'Compliant' `
                        -Detail "Not set; platform default $($item.DefaultWhenUnset) already matches. Deploying pins it."
                }
                else {
                    $shown = if ($null -eq $current) { 'not set' } else { $current }
                    $note = if ($item.Profile -eq 'Strict' -and $HardeningProfile -ne 'Strict') { ' [Strict profile - a default deployment will not touch this]' } else { '' }
                    Write-HardenLog -Message "$($item.Name): $shown, target $target$note" -Level Info
                    Add-HardenAction -Area 'Scan' -Setting $item.Id -Target $dc.HostName -Result 'Missing' -Detail "Currently $shown, target $target$note"
                }
            }
            catch {
                Write-HardenLog -Message "$($item.Name): not readable" -Level Skip
            }
        }
    }

    # -- verdict -------------------------------------------------------------------------------
    Write-HardenLog -Message 'Verdict' -Level Header
    if ($blockers.Count -eq 0) {
        Write-HardenLog -Message 'Nothing found that would obviously break. That is not the same as nothing breaking - deploy at Level Audit first anyway.' -Level Success
    }
    else {
        foreach ($b in $blockers) { Write-HardenLog -Message $b -Level Warning }
        Write-HardenLog -Message 'Resolve these before running with -Level Enforce, or use -Force to proceed anyway.' -Level Warning
    }

    return $blockers.ToArray()
}

#endregion Scan

####################################################################################################
#region Deployment
####################################################################################################

function Invoke-HardenDeployment {
    <#
        .SYNOPSIS
        Creates one GPO per setting group and role, fills it, and links it.

        .DESCRIPTION
        A group with nothing applicable to a role produces no GPO at all - there is no empty
        ADHardenKit-Member-Services sitting around confusing people.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$HardeningProfile,
        [Parameter(Mandatory)][string]$Level,
        [Parameter(Mandatory)][string[]]$Area,
        [Parameter(Mandatory)][string]$GpoNamePattern,
        [string]$MemberOu,
        [switch]$AuditOnly
    )

    $ctx = Get-HardenContext
    $baseline = @(Get-HardenBaseline)
    $auditPolicy = @(Get-HardenAuditPolicy)

    if ($HardeningProfile -eq 'Baseline') {
        $baseline = @($baseline | Where-Object { $_.Profile -eq 'Baseline' })
    }

    # Kept for the report: which settings were actually in scope for this run, so the page can
    # explain them rather than listing bare identifiers.
    $script:ScopeBaseline = @($baseline | Where-Object { $_.Group -in $Area })
    $script:ScopeAuditPolicy = if ('Logging' -in $Area) { $auditPolicy } else { @() }

    Write-HardenLog -Message "Profile: $HardeningProfile   Level: $Level" -Level Info
    Write-HardenLog -Message "Groups: $($Area -join ', ')" -Level Info
    if ($Level -eq 'Enforce') {
        Write-HardenLog -Message 'Staged settings will be ENFORCED, not observed. Anything depending on them stops working at the next policy refresh.' -Level Warning
    }

    foreach ($role in 'DC', 'Member') {
        $roleLabel = if ($role -eq 'DC') { 'Domain controllers' } else { 'Member servers' }
        $targetDn = if ($role -eq 'DC') { $ctx.DomainControllersDn } else { $MemberOu }

        foreach ($group in $Area) {

            $applicable = @($baseline | Where-Object {
                    $_.Group -eq $group -and ($_.Target -eq $role -or $_.Target -eq 'Both')
                })

            # The audit policy travels with the Logging group but is not a baseline row.
            $wantsAuditCsv = ($group -eq 'Logging')

            if ($applicable.Count -eq 0 -and -not $wantsAuditCsv) { continue }

            $gpoName = $GpoNamePattern -replace '\{ROLE\}', $role -replace '\{GROUP\}', $group
            Write-HardenLog -Message "$roleLabel - $group" -Level Header

            $creation = New-HardenGpoIfMissing -Name $gpoName -Comment "ADHardenKit $group, $HardeningProfile profile, level $Level" -AuditOnly:$AuditOnly
            Add-HardenAction -Area $group -Setting $gpoName -Target $role -Result $creation.Result
            Write-HardenLog -Message "GPO $gpoName : $($creation.Result)" -Level $(if ($creation.Result -eq 'Compliant') { 'Skip' } else { 'Success' })

            # In plan mode the GPO was not created, so there is no object - but stopping here
            # would reduce the whole plan to "would create two GPOs" and hide every setting,
            # which defeats the point of a plan. A placeholder with an empty GUID lets the loop
            # run; every function that writes checks ShouldProcess first and reports Planned, so
            # nothing can reach SYSVOL through it. In audit mode a missing GPO genuinely means
            # everything below is missing, and the actions say so.
            if (-not $creation.Gpo) {
                if ($AuditOnly) {
                    Add-HardenAction -Area $group -Setting "$gpoName settings" -Target $role -Result 'Missing' -Detail 'GPO does not exist, so none of its settings do'
                    continue
                }
                $creation = [pscustomobject]@{
                    Gpo = [pscustomobject]@{ Id = [guid]::Empty; DisplayName = $gpoName }
                    Result = $creation.Result
                }
            }

            # -- one question per topic, with the live state next to the target ----------------
            if ($script:InteractiveMode) {
                $promptItems = [System.Collections.Generic.List[object]]::new()
                foreach ($it in $applicable) { $promptItems.Add($it) }

                if ($wantsAuditCsv) {
                    $count = @($auditPolicy | Where-Object { $(if ($role -eq 'DC') { $_.DcValue } else { $_.MemberValue }) -ne 0 }).Count
                    $promptItems.Add([pscustomobject]@{
                            Id = 'AuditCsv'; Topic = 'Advanced audit policy'; Type = 'AuditCsv'
                            Name = 'Advanced audit policy (audit.csv)'; Profile = 'Baseline'; Staged = $false
                            EnforceValue = $count; Reference = 'KB921468'
                            Why = 'The subcategory list that decides which security events are recorded at all. Without these events a later investigation has counts and no detail.'
                            Observe = 'Raises the security log volume considerably - the log size in this same group is what keeps that from turning into lost evidence.'
                        })
                }

                foreach ($tg in ($promptItems | Group-Object { $_.Topic })) {
                    [void](Request-HardenTopicDecision -TopicName $tg.Name -Items $tg.Group -Role $role -GpoName $gpoName -Level $Level)
                }

                if ($wantsAuditCsv -and -not (Test-HardenTopicApproved -Topic 'Advanced audit policy')) {
                    Add-HardenAction -Area $group -Setting 'AuditCsv' -Target $gpoName -Result 'Skipped' -Detail 'Declined'
                    $wantsAuditCsv = $false
                }
            }

            # -- security options and services share one template per GPO ----------------------
            $registryValues = @{}
            $services = @{}

            foreach ($item in $applicable) {
                switch ($item.Type) {

                    'SecurityOption' {
                        $value = if ($item.Staged -and $Level -eq 'Audit') { $item.AuditValue } else { $item.EnforceValue }

                        # Guarded rather than skipped with continue: inside a switch, continue moves
                        # to the next switch item, not the next item of the enclosing foreach. It
                        # happens to behave correctly here only because the switch is the last
                        # statement in the loop body, and that is not a property worth relying on.
                        if ($null -ne $value) {
                            $stage = if ($item.Staged) { if ($Level -eq 'Audit') { ' (observing)' } else { ' (enforcing)' } } else { '' }

                            # A staged rollout must only ever move in one direction. If a future
                            # edit reintroduces an AuditValue below the enforcing one, refuse it
                            # here rather than quietly writing a weaker setting than the target.
                            if ($item.Staged -and $Level -eq 'Audit' -and
                                $item.ValueType -eq 4 -and $item.EnforceValue -is [int] -and $value -is [int] -and
                                $value -lt $item.EnforceValue -and $item.EnforceValue -le 2 -and $value -eq 0) {
                                Write-HardenLog -Message "$($item.Name): audit value 0 would switch the setting off rather than observe it - refusing" -Level Error
                                Add-HardenAction -Area $group -Setting $item.Id -Target $role -Result 'Failed' `
                                    -Detail 'AuditValue 0 is a downgrade, not an observation form' -Severity 'High'
                            }
                            elseif (Test-HardenTopicApproved -Item $item) {
                                # A string value in a security template is quoted; a DWORD is not.
                                $written = if ($item.ValueType -eq 1) { "`"$value`"" } else { $value }
                                $registryValues[$item.Key] = @{ Type = $item.ValueType; Value = $written }

                                Write-HardenLog -Message "$($item.Name) = $value$stage" -Level Info
                                Add-HardenAction -Area $group -Setting $item.Id -Target $role -Result 'Planned' -Detail "$value$stage"
                            }
                            else {
                                Add-HardenAction -Area $group -Setting $item.Id -Target $role -Result 'Skipped' -Detail 'Declined'
                            }
                        }
                    }

                    'StartupScript' {
                        # Goes into this role's own GPO like everything else, so the member GPO
                        # carries it too and the OU decides who runs it.
                        if (Test-HardenTopicApproved -Item $item) {
                            [void](Set-HardenStartupScript -Gpo $creation.Gpo -Item $item -AuditOnly:$AuditOnly)
                        }
                        else {
                            Add-HardenAction -Area $group -Setting $item.Id -Target $role -Result 'Skipped' -Detail 'Declined'
                        }
                    }

                    'Service' {
                        if (Test-HardenTopicApproved -Item $item) {
                            $services[$item.ServiceName] = $item.StartupMode
                            Write-HardenLog -Message $item.Name -Level Info
                            Add-HardenAction -Area $group -Setting $item.Id -Target $role -Result 'Planned'
                        }
                        else {
                            Add-HardenAction -Area $group -Setting $item.Id -Target $role -Result 'Skipped' -Detail 'Declined'
                        }
                    }

                    'AdminTemplate' {
                        if (-not (Test-HardenTopicApproved -Item $item)) {
                            Add-HardenAction -Area $group -Setting $item.Id -Target $role -Result 'Skipped' -Detail 'Declined'
                            break
                        }

                        foreach ($v in $item.Values) {
                            try {
                                $result = Set-HardenRegistrySetting -GpoName $gpoName -Key $item.RegKey -ValueName $v.Name `
                                    -Type $v.Type -Value $v.Value -AuditOnly:$AuditOnly -Confirm:$false
                                Write-HardenLog -Message "$($item.Name) / $($v.Name) = $($v.Value) : $result" -Level $(if ($result -eq 'Compliant') { 'Skip' } else { 'Success' })
                                Add-HardenAction -Area $group -Setting "$($item.Id):$($v.Name)" -Target $role -Result $result
                            }
                            catch {
                                Write-HardenLog -Message "$($item.Name) / $($v.Name) failed - $($_.Exception.Message)" -Level Error
                                Add-HardenAction -Area $group -Setting "$($item.Id):$($v.Name)" -Target $role -Result 'Failed' -Detail $_.Exception.Message -Severity 'Medium'
                            }
                        }
                    }
                }
            }

            if ($registryValues.Count -gt 0 -or $services.Count -gt 0) {
                try {
                    $result = Set-HardenSecurityTemplate -Gpo $creation.Gpo -RegistryValues $registryValues -Services $services -AuditOnly:$AuditOnly -Confirm:$false
                    Write-HardenLog -Message "Security template: $result ($($registryValues.Count) value(s), $($services.Count) service(s))" -Level $(if ($result -eq 'Compliant') { 'Skip' } else { 'Success' })
                    Add-HardenAction -Area $group -Setting 'SecurityTemplate' -Target $gpoName -Result $result
                }
                catch {
                    Write-HardenLog -Message "Security template failed - $($_.Exception.Message)" -Level Error
                    Add-HardenAction -Area $group -Setting 'SecurityTemplate' -Target $gpoName -Result 'Failed' -Detail $_.Exception.Message -Severity 'High'
                }
            }

            # -- advanced audit policy, in the Logging GPO -------------------------------------
            if ($wantsAuditCsv) {
                try {
                    $result = Set-HardenAuditCsv -Gpo $creation.Gpo -Subcategories $auditPolicy -Role $role -AuditOnly:$AuditOnly -Confirm:$false
                    $count = @($auditPolicy | Where-Object { $(if ($role -eq 'DC') { $_.DcValue } else { $_.MemberValue }) -ne 0 }).Count
                    Write-HardenLog -Message "Advanced audit policy: $result ($count subcategories)" -Level $(if ($result -eq 'Compliant') { 'Skip' } else { 'Success' })
                    Add-HardenAction -Area $group -Setting 'AuditCsv' -Target $gpoName -Result $result -Detail "$count subcategories"
                }
                catch {
                    Write-HardenLog -Message "Audit policy failed - $($_.Exception.Message)" -Level Error
                    Add-HardenAction -Area $group -Setting 'AuditCsv' -Target $gpoName -Result 'Failed' -Detail $_.Exception.Message -Severity 'High'
                }
            }

            # -- link -------------------------------------------------------------------------
            if (-not $targetDn) {
                # Not knowing where to look is not the same as nothing being there. Reporting a
                # link as missing because the caller omitted -MemberServerOu turns an operator
                # omission into directory drift, and sends someone chasing a link that exists.
                $existingLinks = @()
                try {
                    # Get-HardenAdParameter here rather than relying on an outer $ad: this block
                    # sits in a different function than the one that defines it, and an empty
                    # splat would silently query whichever DC happened to answer.
                    $adParam = Get-HardenAdParameter
                    $idPattern = "*$($creation.Gpo.Id.ToString())*"
                    $existingLinks = @(
                        @(Get-ADOrganizationalUnit -LDAPFilter '(gPLink=*)' -Properties gPLink @adParam -ErrorAction Stop)
                        @(Get-ADObject -Identity $ctx.DomainDn -Properties gPLink @adParam -ErrorAction SilentlyContinue)
                    ) | Where-Object { $_.gPLink -like $idPattern } | ForEach-Object { $_.DistinguishedName }
                }
                catch { }

                if ($existingLinks.Count -gt 0) {
                    Write-HardenLog -Message "$gpoName is linked to $($existingLinks -join ', ') - no -MemberServerOu given, so nothing was checked against it" -Level Skip
                    Add-HardenAction -Area $group -Setting "$gpoName link" -Target $role -Result 'Compliant' -Detail "Linked to $($existingLinks -join ', ')"
                }
                else {
                    Write-HardenLog -Message "$gpoName is not linked anywhere. Pass -MemberServerOu, or link it yourself." -Level Warning
                    Add-HardenAction -Area $group -Setting "$gpoName link" -Target $role -Result 'Missing' -Detail 'GPO exists but is linked nowhere' -Severity 'Medium'
                }
                continue
            }

            try {
                $result = Set-HardenGpoLink -GpoName $gpoName -TargetDn $targetDn -AuditOnly:$AuditOnly -Confirm:$false
                Write-HardenLog -Message "Link $gpoName -> $targetDn : $result" -Level $(if ($result -eq 'Compliant') { 'Skip' } else { 'Success' })
                Add-HardenAction -Area $group -Setting "$gpoName link" -Target $targetDn -Result $result
            }
            catch {
                Write-HardenLog -Message "Link failed - $($_.Exception.Message)" -Level Error
                Add-HardenAction -Area $group -Setting "$gpoName link" -Target $targetDn -Result 'Failed' -Detail $_.Exception.Message -Severity 'High'
            }
        }
    }

    # Only worth saying when something in this run actually needs it. Printing it after a
    # logging-only deployment trains people to ignore the line.
    # Driven by the baseline rather than a list kept here, because a list kept here goes stale the
    # first time someone adds a setting and does not think to update it.
    $needsReboot = @($baseline | Where-Object { $_.NeedsReboot -and $_.Group -in $Area })
    if ($needsReboot.Count -gt 0) {
        # In plan mode nothing was written, and a notice claiming otherwise erodes exactly the
        # trust the plan mode exists to build.
        # Audit mode reads; plan mode plans; only a real apply writes. Saying "written" in the
        # other two is the same mistake the plan-mode wording had.
        $rebootMsg = if ($AuditOnly) { 'These would only take effect after a restart once deployed:' }
        elseif ($WhatIfPreference) { 'After -Apply, these take effect only at the next reboot:' }
        else { 'Written, but not yet in force. These take effect at the next reboot:' }
        Write-HardenLog -Message $rebootMsg -Level Warning
        foreach ($r in ($needsReboot | Sort-Object { $_.Name })) {
            Write-HardenLog -Message "    $($r.Name)" -Level Info
        }
    }
}

function ConvertTo-HardenHtmlText {
    <#
        .SYNOPSIS
        Escapes text for HTML without pulling in System.Web, which is not present everywhere.
    #>
    [CmdletBinding()]
    param([AllowNull()][string]$Text)

    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
}

function New-HardenReport {
    <#
        .SYNOPSIS
        Writes the run as JSON for pipelines and as a self-contained HTML page for people.

        .DESCRIPTION
        The HTML has no external dependencies - no fonts, no scripts, no stylesheets fetched from
        anywhere. It survives being emailed to somebody who then opens it on a machine with no
        internet access, which is where these reports usually end up. It also prints sensibly,
        because the audit copy tends to end up on paper.

        The page is built to answer, in order: what happened, was it safe, what exactly changed,
        and what does each of these settings mean. The last part matters most six months later,
        when the person reading it was not the person who ran it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Summary,
        [Parameter(Mandatory)][string]$OutputDirectory
    )

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force -WhatIf:$false -Confirm:$false | Out-Null
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $jsonPath = Join-Path $OutputDirectory "ADHardenKit-$($Summary.Mode)-$stamp.json"
    $htmlPath = Join-Path $OutputDirectory "ADHardenKit-$($Summary.Mode)-$stamp.html"

    $Summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8 -WhatIf:$false -Confirm:$false

    $e = { param($t) ConvertTo-HardenHtmlText ([string]$t) }

    # -- verdict -------------------------------------------------------------------------------
    $mode = [string]$Summary.Mode
    if ($Summary.Failed -gt 0) {
        $vClass = 'bad'; $vTitle = "$($Summary.Failed) operation(s) failed"
        $vText = 'The run did not complete cleanly. Work through the failures in the table below before treating any of this as deployed.'
    }
    elseif ($mode -eq 'Scan') {
        if ($Summary.Blockers.Count -gt 0) {
            $vClass = 'warn'; $vTitle = "$($Summary.Blockers.Count) finding(s) to resolve before enforcing"
            $vText = 'Nothing was changed. The findings below describe what would stop working if the staged settings were enforced today.'
        }
        else {
            $vClass = 'good'; $vTitle = 'Nothing found that would obviously break'
            $vText = 'Nothing was changed. An empty result is only as good as the diagnostics behind it - check that the observation settings are actually on before reading this as a clean bill of health.'
        }
    }
    elseif ($mode -eq 'WhatIf') {
        $vClass = 'info'; $vTitle = "$($Summary.Planned) change(s) planned, nothing written"
        $vText = 'This was a plan. Re-run the same command with -Apply to deploy exactly what is listed here.'
    }
    elseif ($mode -eq 'Audit') {
        if ($Summary.Missing -gt 0) {
            $vClass = 'warn'; $vTitle = "$($Summary.Missing) setting(s) missing or drifted"
            $vText = 'The deployed state does not match the selected profile. Read-only - nothing was corrected.'
        }
        else {
            $vClass = 'good'; $vTitle = 'No drift against the selected profile'
            $vText = 'Everything in scope matches what the profile expects.'
        }
    }
    else {
        $changed = $Summary.Created + $Summary.Updated
        if ($changed -eq 0) {
            $vClass = 'good'; $vTitle = 'Nothing to change - already in the target state'
            $vText = 'Every setting in scope was already correct. This is what a repeat run should look like.'
        }
        else {
            $vClass = 'good'; $vTitle = "$changed change(s) written"
            $vText = 'Group Policy has been updated. Clients pick this up at their next policy refresh; settings marked as needing a restart are written but not yet in force.'
        }
    }

    # -- stat tiles ----------------------------------------------------------------------------
    $tileDefs = @(
        @{ Key = 'Created'; Label = 'Created'; Tone = 'ok' }
        @{ Key = 'Updated'; Label = 'Updated'; Tone = 'ok' }
        @{ Key = 'Planned'; Label = 'Planned'; Tone = 'info' }
        @{ Key = 'Compliant'; Label = 'Already correct'; Tone = 'muted' }
        @{ Key = 'Observed'; Label = 'Observations'; Tone = 'info' }
        @{ Key = 'Missing'; Label = 'Missing or drifted'; Tone = 'warn' }
        @{ Key = 'Skipped'; Label = 'Declined'; Tone = 'muted' }
        @{ Key = 'Failed'; Label = 'Failed'; Tone = 'bad' }
    )
    $tiles = foreach ($t in $tileDefs) {
        $v = [int]$Summary.($t.Key)
        if ($v -eq 0 -and $t.Tone -in 'muted', 'ok', 'warn', 'bad' -and $t.Key -notin 'Failed') { continue }
        '<div class="tile t-{0}"><span class="num">{1}</span><span class="lbl">{2}</span></div>' -f $t.Tone, $v, (& $e $t.Label)
    }

    # -- run facts -----------------------------------------------------------------------------
    $p = $Summary.Parameters
    $facts = [ordered]@{
        'ADHardenKit'      = $(if ($p -and $p['Version']) { $p['Version'] } else { 'unknown' })
        'Domain'           = $Summary.Domain
        'Directory server' = $Summary.Server
        'Mode'             = $mode
        'Profile'          = if ($p) { $p['Profile'] } else { $null }
        'Level'            = if ($p) { $p['Level'] } else { $null }
        'Groups in scope'  = if ($p) { ($p['Area'] -join ', ') } else { $null }
        'Member server OU' = if ($p -and $p['MemberServerOu']) { $p['MemberServerOu'] } else { 'not supplied - member GPOs unlinked' }
        'Started'          = ([datetime]$Summary.Started).ToString('yyyy-MM-dd HH:mm:ss')
        'Duration'         = '{0:n1} s' -f ([timespan]$Summary.Duration).TotalSeconds
        'Run by'           = "$($Summary.RunBy) on $($Summary.RunFrom)"
        'PowerShell'       = $Summary.PowerShell
    }
    $factRows = foreach ($k in $facts.Keys) {
        if ([string]::IsNullOrWhiteSpace([string]$facts[$k])) { continue }
        '<div class="fact"><dt>{0}</dt><dd>{1}</dd></div>' -f (& $e $k), (& $e $facts[$k])
    }

    # -- blockers ------------------------------------------------------------------------------
    $blockerHtml = ''
    if ($Summary.Blockers.Count -gt 0) {
        $items = foreach ($b in $Summary.Blockers) { '<li>{0}</li>' -f (& $e $b) }
        $blockerHtml = @"
<section class="card">
  <h2>Findings</h2>
  <p class="lede">Each of these is a reason not to move to <code>-Level Enforce</code> yet. They are observations about the domain, not errors in the run.</p>
  <ul class="findings">$($items -join '')</ul>
</section>
"@
    }

    # -- what was touched, grouped by topic ----------------------------------------------------
    $topicHtml = ''
    if ($Summary.Baseline.Count -gt 0) {
        $byTopic = $Summary.Baseline | Group-Object { $_.Topic } | Sort-Object Name
        $topicRows = foreach ($tg in $byTopic) {
            $ids = @($tg.Group | ForEach-Object { $_.Id })
            $acts = @($Summary.Actions | Where-Object { $_.Setting -in $ids -or ($_.Setting -split ':')[0] -in $ids })
            $state = if (@($acts | Where-Object Result -eq 'Failed').Count) { 'bad' }
            elseif (@($acts | Where-Object Result -eq 'Skipped').Count) { 'skip' }
            elseif (@($acts | Where-Object { $_.Result -in 'Created', 'Updated', 'Planned' }).Count) { 'ok' }
            elseif (@($acts | Where-Object Result -eq 'Compliant').Count) { 'same' }
            else { 'none' }
            $stateText = switch ($state) {
                'bad' { 'failed' } 'skip' { 'declined' } 'ok' { 'deployed' }
                'same' { 'already correct' } default { 'not in scope' }
            }
            $risk = if (@($tg.Group | Where-Object { $_.Staged }).Count) { 'staged' }
            elseif (@($tg.Group | Where-Object { $_.Profile -eq 'Strict' }).Count) { 'strict' }
            else { 'baseline' }
            $refs = @($tg.Group | Where-Object { $_.Reference } | ForEach-Object { $_.Reference -split ',\s*' } | Sort-Object -Unique)
            $settingList = ($tg.Group | ForEach-Object { '<li>{0}</li>' -f (& $e $_.Name) }) -join ''
            $lead = ($tg.Group | Where-Object { $_.Staged } | Select-Object -First 1)
            # Same OrderedDictionary unwrapping trap as in the interactive card: with exactly one
            # entry in the group, [0] returns that entry's first value rather than the entry.
            if (-not $lead) { $lead = @($tg.Group) | Select-Object -First 1 }

            @"
<details class="topic s-$state">
  <summary>
    <span class="tname">$(& $e $tg.Name)</span>
    <span class="chip c-$risk">$risk</span>
    <span class="chip c-state">$stateText</span>
    <span class="tcount">$($tg.Count) setting$(if ($tg.Count -ne 1) { 's' })</span>
  </summary>
  <div class="tbody">
    <p>$(& $e $lead.Why)</p>
    $(if ($lead.Observe) { '<p class="watch"><strong>Watch out.</strong> ' + (& $e $lead.Observe) + '</p>' })
    <ul class="settings">$settingList</ul>
    $(if ($refs.Count) { '<p class="refs">Read more: ' + (& $e (($refs | Select-Object -First 8) -join ', ')) + '</p>' })
  </div>
</details>
"@
        }
        $topicHtml = @"
<section class="card">
  <h2>Topics in scope</h2>
  <p class="lede">Grouped the way the decision is actually made rather than by registry key. Expand a topic for what it does, what it can break and where to read more.</p>
  <div class="controls"><button id="expand" data-open="false" aria-pressed="false">Expand all topics</button></div>
  <div class="topics">$($topicRows -join '')</div>
</section>
"@
    }

    # -- audit policy appendix -----------------------------------------------------------------
    $auditHtml = ''
    if ($Summary.AuditPolicy.Count -gt 0) {
        $ar = foreach ($sub in $Summary.AuditPolicy) {
            $dc = switch ([int]$sub.DcValue) { 1 { 'Success' } 2 { 'Failure' } 3 { 'Success + Failure' } default { '<span class="off">off</span>' } }
            $mb = switch ([int]$sub.MemberValue) { 1 { 'Success' } 2 { 'Failure' } 3 { 'Success + Failure' } default { '<span class="off">off</span>' } }
            '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td class="detail">{3}</td></tr>' -f (& $e $sub.Subcategory), $dc, $mb, (& $e $sub.Why)
        }
        $auditHtml = @"
<section class="card">
  <h2>Advanced audit policy</h2>
  <p class="lede">Addressed by subcategory GUID, so the same file applies identically on a localised system. Subcategories not listed are left as they are - the policy adds, it does not reset.</p>
  <table class="grid">
    <thead><tr><th>Subcategory</th><th>Domain controllers</th><th>Member servers</th><th>Why</th></tr></thead>
    <tbody>$($ar -join '')</tbody>
  </table>
</section>
"@
    }

    # -- action table --------------------------------------------------------------------------
    $order = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
    $sorted = $Summary.Actions | Sort-Object @{ Expression = { $order[[string]$_.Severity] } }, Area, Setting
    $rows = foreach ($action in $sorted) {
        $sev = [string]$action.Severity
        $res = [string]$action.Result
        $resClass = switch ($res) {
            'Created' { 'r-ok' } 'Updated' { 'r-ok' } 'Compliant' { 'r-same' }
            'Planned' { 'r-plan' } 'Skipped' { 'r-skip' } 'Failed' { 'r-bad' }
            'Missing' { 'r-warn' } 'Drift' { 'r-warn' } 'Observed' { 'r-info' } default { 'r-info' }
        }
        '<tr class="sev-{0}"><td><span class="pill p-{0}">{1}</span></td><td>{2}</td><td class="mono">{3}</td><td class="mono">{4}</td><td><span class="res {5}">{6}</span></td><td class="detail">{7}</td></tr>' -f `
            $sev.ToLower(), (& $e $sev), (& $e $action.Area), (& $e $action.Setting),
        (& $e $action.Target), $resClass, (& $e $res), (& $e $action.Detail)
    }

    # -- next steps ----------------------------------------------------------------------------
    $steps = [System.Collections.Generic.List[string]]::new()
    if ($Summary.Failed -gt 0) { $steps.Add('Resolve the failed operations above and re-run. The run is idempotent - what already succeeded will report as already correct.') }
    if ($mode -eq 'WhatIf') { $steps.Add('Re-run the same command with <code>-Apply</code> to deploy what is listed here.') }
    if ($mode -eq 'Apply') {
        $steps.Add('Give clients a policy refresh cycle, then confirm the settings arrived rather than assuming it.')
        if (@($Summary.Baseline | Where-Object { $_.NeedsReboot }).Count -gt 0) {
            $steps.Add('Settings marked as needing a restart are written but not yet in force. Schedule the reboot.')
        }
        if ($p -and -not $p['MemberServerOu']) { $steps.Add('No member server OU was supplied, so the member GPOs exist but are not linked. Re-run with <code>-MemberServerOu</code> or link them by hand.') }
    }
    if ($mode -eq 'Scan' -and $Summary.Blockers.Count -gt 0) { $steps.Add('Work through the findings, then leave the observation settings running for a full business cycle including month-end before scanning again.') }
    if ($p -and $p['Level'] -eq 'Audit' -and $mode -eq 'Apply') { $steps.Add('This was an observing deployment. Nothing here refuses an authentication yet - that is <code>-Level Enforce</code>, and it should follow a clean scan, not a calendar date.') }
    $stepHtml = if ($steps.Count) { '<ol class="steps">' + (($steps | ForEach-Object { "<li>$_</li>" }) -join '') + '</ol>' } else { '' }

    $css = @'
*{box-sizing:border-box}
body{margin:0;background:#eef1f5;color:#12161a;font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:28px 20px 60px}
.mono{font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;font-size:12.5px}
code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.9em;background:#e6eaef;padding:1px 5px;border-radius:4px}
header.top{background:#12161a;color:#fff;border-radius:14px;padding:24px 26px;margin-bottom:18px}
header.top h1{margin:0;font-size:21px;letter-spacing:-.2px}
header.top .sub{color:#9aa4b0;font-size:13.5px;margin-top:6px}
.verdict{border-radius:14px;padding:18px 22px;margin-bottom:18px;border-left:6px solid}
.verdict h2{margin:0 0 6px;font-size:17px}
.verdict p{margin:0;font-size:14px}
.verdict.good{background:#e8f6ec;border-color:#2e7d43;color:#12351d}
.verdict.warn{background:#fdf3e0;border-color:#b07208;color:#3d2a05}
.verdict.bad{background:#fdeceb;border-color:#b3261e;color:#3f100d}
.verdict.info{background:#e9eff9;border-color:#2b5fa8;color:#0f2544}
.tiles{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:18px}
.tile{background:#fff;border:1px solid #dde2e8;border-radius:12px;padding:12px 18px;min-width:120px;flex:1 1 120px}
.tile .num{display:block;font-size:26px;font-weight:650;line-height:1.1}
.tile .lbl{display:block;font-size:12px;color:#66707c;margin-top:2px}
.tile.t-ok .num{color:#2e7d43}.tile.t-bad .num{color:#b3261e}
.tile.t-warn .num{color:#b07208}.tile.t-info .num{color:#2b5fa8}.tile.t-muted .num{color:#66707c}
.card{background:#fff;border:1px solid #dde2e8;border-radius:14px;padding:20px 22px;margin-bottom:18px}
.card h2{margin:0 0 4px;font-size:16px}
.lede{margin:0 0 14px;color:#5c6672;font-size:13.5px}
.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px 22px;margin:0}
.fact dt{font-size:11.5px;text-transform:uppercase;letter-spacing:.4px;color:#7a848f}
.fact dd{margin:2px 0 0;font-size:13.5px;word-break:break-word}
.findings{margin:0;padding-left:20px}
.findings li{margin-bottom:8px;font-size:13.5px}
.topics{display:flex;flex-direction:column;gap:8px}
.topic{border:1px solid #dde2e8;border-radius:10px;background:#fbfcfd;overflow:hidden}
.topic summary{cursor:pointer;padding:11px 14px;display:flex;align-items:center;gap:9px;flex-wrap:wrap;list-style:none}
.topic summary::-webkit-details-marker{display:none}
.topic summary::before{content:"\25B8";color:#98a2ae;font-size:11px;transition:transform .12s}
.topic[open] summary::before{transform:rotate(90deg)}
.tname{font-weight:600;font-size:14px}
.tcount{margin-left:auto;color:#7a848f;font-size:12px}
.chip{font-size:10.5px;text-transform:uppercase;letter-spacing:.5px;padding:2px 7px;border-radius:20px;font-weight:600}
.c-baseline{background:#e8f6ec;color:#276b3a}.c-staged{background:#fdf3e0;color:#8a5a06}
.c-strict{background:#f3e9f8;color:#6b2d8a}.c-state{background:#e6eaef;color:#4c5661}
.topic.s-bad{border-color:#e8b4b0}.topic.s-skip{opacity:.72}
.tbody{padding:2px 16px 15px 30px;border-top:1px solid #e6eaef;font-size:13.5px}
.tbody p{margin:11px 0}
.watch{color:#7a5406;background:#fdf8ec;padding:9px 12px;border-radius:8px}
.settings{margin:10px 0;padding-left:20px;color:#4c5661;font-size:13px}
.refs{color:#5c6672;font-size:12.5px}
.grid{width:100%;border-collapse:collapse;font-size:13px}
.grid th{text-align:left;padding:8px 10px;border-bottom:2px solid #dde2e8;font-size:11.5px;text-transform:uppercase;letter-spacing:.4px;color:#7a848f}
.grid td{padding:8px 10px;border-bottom:1px solid #eef1f5;vertical-align:top}
.grid tbody tr:hover{background:#f7f9fb}
.detail{color:#5c6672;font-size:12.5px}
.off{color:#a8b0ba}
.controls{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.controls button{border:1px solid #dde2e8;background:#fff;border-radius:20px;padding:5px 13px;font-size:12.5px;cursor:pointer;color:#4c5661}
.controls button[aria-pressed=true]{background:#12161a;color:#fff;border-color:#12161a}
.controls input{flex:1 1 200px;min-width:170px;border:1px solid #dde2e8;border-radius:8px;padding:6px 11px;font-size:13px}
.counter{color:#7a848f;font-size:12.5px}
.pill{font-size:10.5px;text-transform:uppercase;letter-spacing:.5px;padding:2px 7px;border-radius:20px;font-weight:600;white-space:nowrap}
.p-high{background:#fdeceb;color:#a01e17}.p-medium{background:#fdf3e0;color:#8a5a06}
.p-low{background:#e9eff9;color:#24518f}.p-info{background:#eef1f5;color:#5c6672}
.res{font-size:12px;font-weight:600;white-space:nowrap}
.r-ok{color:#2e7d43}.r-bad{color:#b3261e}.r-warn{color:#b07208}
.r-plan{color:#2b5fa8}.r-skip{color:#8a919a}.r-same{color:#66707c}.r-info{color:#4c5661}
.steps{margin:0;padding-left:20px;font-size:13.5px}
.steps li{margin-bottom:7px}
footer{color:#7a848f;font-size:12px;text-align:center;padding-top:6px}
@media print{
  body{background:#fff}.wrap{max-width:none;padding:0}
  .card,.tile,header.top{break-inside:avoid;border-radius:0}
  header.top{background:#fff;color:#000;border-bottom:2px solid #000}
  header.top .sub{color:#444}
  .controls{display:none}.topic{break-inside:avoid}
  details{open:true}.tbody{display:block !important}
}
'@

    $js = @'
(function () {
  "use strict";
  var table = document.getElementById("actions");
  if (!table) { return; }
  var rows = Array.prototype.slice.call(table.querySelectorAll("tbody tr"));
  var buttons = Array.prototype.slice.call(document.querySelectorAll(".controls button"));
  var search = document.getElementById("q");
  var counter = document.getElementById("counter");
  var empty = document.getElementById("empty");
  var severity = "all";

  function apply() {
    var needle = search.value.trim().toLowerCase();
    var shown = 0;
    rows.forEach(function (row) {
      var bySeverity = severity === "all" || row.className.indexOf("sev-" + severity) > -1;
      var byText = needle === "" || row.textContent.toLowerCase().indexOf(needle) > -1;
      var visible = bySeverity && byText;
      row.hidden = !visible;
      if (visible) { shown++; }
    });
    counter.textContent = shown + " of " + rows.length + " shown";
    empty.hidden = shown !== 0;
  }

  buttons.forEach(function (button) {
    button.addEventListener("click", function () {
      severity = button.getAttribute("data-filter");
      buttons.forEach(function (other) {
        other.setAttribute("aria-pressed", other === button ? "true" : "false");
      });
      apply();
    });
  });

  search.addEventListener("input", apply);

  // Guarded: a section can legitimately be absent - the Check mode report has no topics - and a
  // null here would throw and take the filtering and search down with it.
  var expand = document.getElementById("expand");
  if (expand) {
    expand.addEventListener("click", function () {
      var open = this.getAttribute("data-open") !== "true";
      this.setAttribute("data-open", open ? "true" : "false");
      this.textContent = open ? "Collapse all topics" : "Expand all topics";
      Array.prototype.slice.call(document.querySelectorAll(".topic")).forEach(function (d) { d.open = open; });
    });
  }

  apply();
})();
'@

    $title = "ADHardenKit $mode report"
    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>$(& $e $title) - $(& $e $Summary.Domain)</title>
<style>$css</style>
</head><body><div class="wrap">

<header class="top">
  <h1>ADHardenKit &mdash; $(& $e $mode)</h1>
  <div class="sub">$(& $e $Summary.Domain) &nbsp;&middot;&nbsp; $(([datetime]$Summary.Started).ToString('dddd, dd MMMM yyyy HH:mm')) &nbsp;&middot;&nbsp; $(& $e $Summary.RunBy)</div>
</header>

<div class="verdict $vClass">
  <h2>$(& $e $vTitle)</h2>
  <p>$(& $e $vText)</p>
</div>

<div class="tiles">$($tiles -join '')</div>

<section class="card">
  <h2>The run</h2>
  <dl class="facts">$($factRows -join '')</dl>
</section>

$blockerHtml
$topicHtml

<section class="card">
  <h2>Every action</h2>
  <p class="lede">One row per thing the run touched or looked at. Filter by severity or search for a setting name, a GPO or an OU.</p>
  <div class="controls">
    <button data-filter="all" aria-pressed="true">All</button>
    <button data-filter="high" aria-pressed="false">High</button>
    <button data-filter="medium" aria-pressed="false">Medium</button>
    <button data-filter="low" aria-pressed="false">Low</button>
    <button data-filter="info" aria-pressed="false">Info</button>
    <input id="q" type="search" placeholder="Search setting, GPO, OU or detail">
    <span class="counter" id="counter"></span>
  </div>
  <table class="grid" id="actions">
    <thead><tr><th>Severity</th><th>Group</th><th>Setting</th><th>Target</th><th>Result</th><th>Detail</th></tr></thead>
    <tbody>$($rows -join '')</tbody>
  </table>
  <p id="empty" class="lede" hidden>Nothing matches that filter.</p>
</section>

$auditHtml

$(if ($stepHtml) { '<section class="card"><h2>What to do next</h2>' + $stepHtml + '</section>' })

<footer>
  Generated by ADHardenKit on $(& $e $Summary.RunFrom) &middot; PowerShell $(& $e $Summary.PowerShell) &middot;
  machine-readable copy alongside this file as JSON
</footer>

</div>
<script>$js</script>
</body></html>
"@

    Set-Content -LiteralPath $htmlPath -Value $html -Encoding UTF8 -WhatIf:$false -Confirm:$false

    return [pscustomobject]@{ Json = $jsonPath; Html = $htmlPath }
}

function New-HardenSummary {
    <#
        .SYNOPSIS
        Collects everything the report needs into one object.

        .DESCRIPTION
        Deliberately more than counters. A report that only says "5 created" is a receipt; one
        that also carries which domain, which server, which profile, which settings were in scope
        and what the scan objected to can be read months later by somebody who was not there.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Mode,
        [Parameter(Mandatory)][datetime]$Started,
        [object]$Context,
        [hashtable]$RunParameters,
        [object[]]$Baseline,
        [object[]]$AuditPolicy,
        [string[]]$Blockers
    )

    $a = $script:Actions

    return [pscustomobject]@{
        Mode          = $Mode
        Started       = $Started
        Finished      = Get-Date
        Duration      = (New-TimeSpan -Start $Started -End (Get-Date))

        Domain        = if ($Context) { $Context.DomainFqdn } else { $null }
        DomainDn      = if ($Context) { $Context.DomainDn } else { $null }
        Server        = if ($Context) { $Context.Server } else { $null }
        # Never let identity lookup take the report down with it - the report is often the only
        # record of a run that went wrong, so it has to survive things being unusual.
        RunBy         = $(
            if ($env:USERDOMAIN -and $env:USERNAME) { "$env:USERDOMAIN\$env:USERNAME" }
            elseif ($env:USERNAME) { $env:USERNAME }
            else { try { [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { 'unknown' } }
        )
        RunFrom       = $(if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [Net.Dns]::GetHostName() })
        PowerShell    = $PSVersionTable.PSVersion.ToString()

        Parameters    = $RunParameters
        # Filtered, not just wrapped: @($null) is an array of one null, not an empty array, so an
        # unpassed parameter would report a count of 1 and the report would render a section with
        # a single blank entry in it.
        Baseline      = @($Baseline | Where-Object { $_ })
        AuditPolicy   = @($AuditPolicy | Where-Object { $_ })
        Blockers      = @($Blockers | Where-Object { $_ })

        Created       = @($a | Where-Object Result -eq 'Created').Count
        Updated       = @($a | Where-Object Result -eq 'Updated').Count
        Compliant     = @($a | Where-Object Result -eq 'Compliant').Count
        Planned       = @($a | Where-Object Result -eq 'Planned').Count
        Missing       = @($a | Where-Object { $_.Result -in 'Missing', 'Drift' }).Count
        Observed      = @($a | Where-Object Result -eq 'Observed').Count
        Skipped       = @($a | Where-Object Result -eq 'Skipped').Count
        Failed        = @($a | Where-Object Result -eq 'Failed').Count
        High          = @($a | Where-Object Severity -eq 'High').Count
        Actions       = @($a)
    }
}

#endregion Deployment

####################################################################################################
#region Menu
####################################################################################################

function Read-HardenMenuChoice {
    <#
        .SYNOPSIS
        Prints numbered options and returns the chosen key. Enter picks the default.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Question,
        [Parameter(Mandatory)][object[]]$Options,   # @{ Key; Label; Detail } each
        [string]$Default
    )

    Write-Host ''
    Write-Host "  $Question" -ForegroundColor White
    foreach ($opt in $Options) {
        $marker = if ($opt.Key -eq $Default) { ' (default)' } else { '' }
        Write-Host '    [' -ForegroundColor DarkGray -NoNewline
        Write-Host $opt.Key -ForegroundColor Cyan -NoNewline
        Write-Host ']' -ForegroundColor DarkGray -NoNewline
        Write-Host (" {0}{1}" -f $opt.Label, $marker) -ForegroundColor Gray
        if ($opt.Detail) { Write-Host ("        {0}" -f $opt.Detail) -ForegroundColor DarkGray }
    }

    while ($true) {
        $answer = (Read-Host '  Choice').Trim()
        if ([string]::IsNullOrEmpty($answer) -and $Default) { return $Default }
        $hit = $Options | Where-Object { "$($_.Key)" -eq $answer -or "$($_.Key)".ToUpper() -eq $answer.ToUpper() } | Select-Object -First 1
        if ($hit) { return $hit.Key }
        Write-Host '  Not one of the options.' -ForegroundColor Red
    }
}

function Confirm-HardenApply {
    <#
        .SYNOPSIS
        One last look before an unattended -Apply writes anything.

        .DESCRIPTION
        With -Interactive every topic is confirmed individually, so this would be the seventeenth
        prompt and adds nothing. Without it, -Apply goes from command line straight to writing,
        and the difference between a plan and a deployment is four characters that are easy to
        leave on from the previous command. This is the brake.

        Skipped entirely when the session has no console, so a scheduled task is unaffected, and
        with -Force for a deliberate unattended run. The default answer is no: someone who meant
        to deploy can type one letter, and someone who did not gets to keep their afternoon.

        Nothing here talks to the directory - it describes what the run intends from the baseline
        and the parameters, which is exactly what the person needs to recognise a wrong command.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$HardeningProfile,
        [Parameter(Mandatory)][string]$Level,
        [Parameter(Mandatory)][string[]]$Area,
        [Parameter(Mandatory)][string]$GpoNamePattern,
        [string]$MemberOu
    )

    $baseline = @(Get-HardenBaseline)
    if ($HardeningProfile -eq 'Baseline') { $baseline = @($baseline | Where-Object { $_.Profile -eq 'Baseline' }) }
    $inScope = @($baseline | Where-Object { $_.Group -in $Area })

    $gpos = [System.Collections.Generic.List[string]]::new()
    foreach ($group in $Area) {
        foreach ($role in 'DC', 'Member') {
            $count = @($inScope | Where-Object { $_.Group -eq $group -and ($_.Target -eq $role -or $_.Target -eq 'Both') }).Count
            if ($count -eq 0 -and -not ($group -eq 'Logging')) { continue }
            $gpos.Add(($GpoNamePattern -replace '\{ROLE\}', $role -replace '\{GROUP\}', $group))
        }
    }

    $staged = @($inScope | Where-Object { $_.Staged })
    $reboot = @($inScope | Where-Object { $_.NeedsReboot })
    $scripts = @($inScope | Where-Object { $_.Type -eq 'StartupScript' })

    Write-Host ''
    Write-Host '  ' -NoNewline
    Write-Host ' APPLY ' -ForegroundColor Black -BackgroundColor Yellow -NoNewline
    Write-Host '  This run writes to Group Policy.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host ("    Profile   {0}" -f $HardeningProfile) -ForegroundColor Gray
    Write-Host '    Level     ' -ForegroundColor Gray -NoNewline
    if ($Level -eq 'Enforce') {
        Write-Host 'Enforce - staged settings will require, not observe' -ForegroundColor Red
    }
    elseif ($staged.Count -gt 0) {
        Write-Host "Audit - $($staged.Count) staged setting(s) deploy in observing form" -ForegroundColor Gray
    }
    else {
        # Saying "0 staged settings" invites the reader to wonder what they are missing.
        Write-Host 'Audit - nothing in this scope is staged, so every setting deploys at its target value' -ForegroundColor Gray
    }
    Write-Host ("    Groups    {0}" -f ($Area -join ', ')) -ForegroundColor Gray
    Write-Host ("    Settings  {0} in scope" -f $inScope.Count) -ForegroundColor Gray
    Write-Host ("    GPOs      {0}" -f $gpos.Count) -ForegroundColor Gray
    foreach ($g in $gpos) { Write-Host ("              {0}" -f $g) -ForegroundColor DarkGray }

    if ($MemberOu) { Write-Host ("    Member OU {0}" -f $MemberOu) -ForegroundColor Gray }
    else { Write-Host '    Member OU not given - member GPOs will be created but left unlinked' -ForegroundColor DarkGray }

    if ($reboot.Count -gt 0) {
        Write-Host ("    Reboot    {0} setting(s) only take effect after a restart" -f $reboot.Count) -ForegroundColor DarkYellow
    }
    # Group-Object MinOS on an OrderedDictionary groups on a property that does not exist and
    # returns one empty-named group; the script block form reads the key.
    $osLimited = @($inScope | Where-Object { $_.MinOS })
    if ($osLimited.Count -gt 0) {
        $byOs = $osLimited | Group-Object { $_.MinOS } | Sort-Object Name | ForEach-Object { "$($_.Count) need $($_.Name)+" }
        Write-Host ("    Versions  {0} - older machines apply these and ignore them" -f ($byOs -join ', ')) -ForegroundColor DarkYellow
    }
    if ($scripts.Count -gt 0) {
        Write-Host ("    Scripts   {0} setting(s) deploy as a GPO startup script and need two restarts to take hold" -f $scripts.Count) -ForegroundColor DarkYellow
    }

    Write-Host ''
    if ($Level -eq 'Enforce') {
        Write-Host '    Enforce is the run that can break authentication. A clean scan should come first.' -ForegroundColor Red
        Write-Host ''
    }
    Write-Host '    Run -Interactive instead to review each topic one at a time, or -Force to skip this prompt.' -ForegroundColor DarkGray

    $answer = (Read-Host '  Write these changes? (y/N)').Trim()
    return ($answer -and $answer.Substring(0, 1).ToUpper() -eq 'Y')
}

function Show-HardenMenu {
    <#
        .SYNOPSIS
        The interactive front door: builds the same choices the parameters express.

        .DESCRIPTION
        Shown only when the script is started without any parameters on an interactive console, so
        double-clicking into it works while every scripted or scheduled invocation behaves exactly
        as before - a menu that appeared for a scheduled task would hang it until the timeout.

        Returns a hashtable of parameter overrides, or $null when the person quits. Deliberately
        produces nothing the command line cannot: the last screen prints the equivalent command,
        so the menu doubles as a way of learning the parameters rather than replacing them.
    #>
    [CmdletBinding()]
    param()

    Write-Host ''
    # ASCII, not box drawing: this is the first thing anyone sees, and the console it renders in
    # is not always a UTF-8 one. A banner of question marks is a bad first impression.
    Write-Host ('  ' + ('=' * 68)) -ForegroundColor DarkGray
    Write-Host "   ADHardenKit $script:HardenKitVersion" -ForegroundColor White
    Write-Host '   Harden the protocol layer of an Active Directory - in order.' -ForegroundColor DarkGray
    Write-Host ('  ' + ('=' * 68)) -ForegroundColor DarkGray

    $choice = [ordered]@{}

    # -- what to do ----------------------------------------------------------------------------
    $mode = Read-HardenMenuChoice -Question 'What should this run do?' -Default '1' -Options @(
        @{ Key = '1'; Label = 'Scan - read what the domain is doing today'; Detail = 'Read-only. Event logs, NTLM usage, unsigned LDAP binds, current settings.' }
        @{ Key = '2'; Label = 'Deploy - create and fill the hardening GPOs'; Detail = 'Plans first; nothing is written until you confirm at the end.' }
        @{ Key = '3'; Label = 'Audit - drift report against a profile'; Detail = 'Read-only. What differs from the selected profile.' }
        @{ Key = '4'; Label = 'Check - prerequisites only' }
        @{ Key = 'Q'; Label = 'Quit' }
    )
    if ($mode -eq 'Q') { return $null }
    $choice.Mode = @('Scan', 'Deploy', 'Audit', 'Check')[[int]$mode - 1]

    if ($choice.Mode -in 'Scan', 'Check') {
        # Nothing else to decide; both are read-only and profile-independent enough.
        return $choice
    }

    # -- profile -------------------------------------------------------------------------------
    $profile = Read-HardenMenuChoice -Question 'Which profile?' -Default '1' -Options @(
        @{ Key = '1'; Label = 'Baseline - little or no compatibility risk' }
        @{ Key = '2'; Label = 'Strict - adds TLS 1.0/1.1 removal, RC4 ciphers, spooler RPC and more'; Detail = 'Needs a maintenance window and a rollback plan.' }
    )
    $choice.HardeningProfile = @('Baseline', 'Strict')[[int]$profile - 1]

    if ($choice.Mode -eq 'Audit') { return $choice }

    # -- level ---------------------------------------------------------------------------------
    $level = Read-HardenMenuChoice -Question 'Which level?' -Default '1' -Options @(
        @{ Key = '1'; Label = 'Audit - staged settings deploy in their observing form'; Detail = 'LDAP signing negotiates instead of requiring, NTLM is audited instead of denied.' }
        @{ Key = '2'; Label = 'Enforce - staged settings actually require'; Detail = 'The run that can break things. A clean scan should come first.' }
    )
    $choice.Level = @('Audit', 'Enforce')[[int]$level - 1]

    # -- scope ---------------------------------------------------------------------------------
    $allAreas = 'Logging', 'Signing', 'Protocols', 'CredentialProtection', 'LegacyAuth', 'PolicyIntegrity', 'Services'
    Write-Host ''
    Write-Host '  Which groups? Comma-separated numbers, or Enter for all.' -ForegroundColor White
    Write-Host '  On a domain that has never been watched, Logging alone is the right first run.' -ForegroundColor DarkGray
    for ($i = 0; $i -lt $allAreas.Count; $i++) {
        Write-Host ('    [{0}] {1}' -f ($i + 1), $allAreas[$i]) -ForegroundColor Gray
    }
    while ($true) {
        $raw = (Read-Host '  Groups').Trim()
        if ([string]::IsNullOrEmpty($raw)) { $choice.Area = $allAreas; break }
        $picked = [System.Collections.Generic.List[string]]::new()
        $valid = $true
        foreach ($token in ($raw -split '[,\s]+' | Where-Object { $_ })) {
            $index = 0
            if ([int]::TryParse($token, [ref]$index) -and $index -ge 1 -and $index -le $allAreas.Count) {
                if ($allAreas[$index - 1] -notin $picked) { $picked.Add($allAreas[$index - 1]) }
            }
            elseif ($token -in $allAreas) {
                if ($token -notin $picked) { $picked.Add($token) }
            }
            else { Write-Host "  '$token' is neither a number from the list nor a group name." -ForegroundColor Red; $valid = $false; break }
        }
        if ($valid -and $picked.Count -gt 0) { $choice.Area = $picked.ToArray(); break }
    }

    # -- member server OU ----------------------------------------------------------------------
    Write-Host ''
    Write-Host '  OU to link the member server GPOs to. Enter to skip - the GPOs are then' -ForegroundColor White
    Write-Host '  created but left unlinked, and can be linked in a later run.' -ForegroundColor DarkGray
    $ad = Get-HardenAdParameter
    while ($true) {
        $ou = (Read-Host '  Member server OU (distinguished name)').Trim().Trim('"', "'")
        if ([string]::IsNullOrEmpty($ou)) { break }
        try {
            Get-ADObject -Identity $ou @ad -ErrorAction Stop | Out-Null
            $choice.MemberServerOu = $ou
            break
        }
        catch {
            Write-Host "  Not found in the directory: $ou" -ForegroundColor Red
            Write-Host '  Enter to skip, or try again.' -ForegroundColor DarkGray
        }
    }

    # -- walkthrough and writing ---------------------------------------------------------------
    $walk = Read-HardenMenuChoice -Question 'Show each topic for confirmation before it is deployed?' -Default '1' -Options @(
        @{ Key = '1'; Label = 'Yes - one card per topic with its current state and explanation' }
        @{ Key = '2'; Label = 'No - deploy everything in the selected scope' }
    )
    $choice.Interactive = ($walk -eq '1')

    $write = Read-HardenMenuChoice -Question 'Plan only, or write?' -Default '1' -Options @(
        @{ Key = '1'; Label = 'Plan - show everything, change nothing' }
        @{ Key = '2'; Label = 'Apply - actually create and link the GPOs' }
    )
    $choice.Apply = ($write -eq '2')

    # -- summary and the equivalent command line -----------------------------------------------
    # Not $MyInvocation: inside a function that names the function, not the script file.
    $cmd = if ($PSCommandPath) { ".\$(Split-Path $PSCommandPath -Leaf)" } else { '.\ADHardenKit.ps1' }
    $cmd += " -Mode $($choice.Mode)"
    if ($choice.Contains('HardeningProfile') -and $choice.HardeningProfile -ne 'Baseline') { $cmd += " -Profile $($choice.HardeningProfile)" }
    if ($choice.Contains('Level') -and $choice.Level -ne 'Audit') { $cmd += " -Level $($choice.Level)" }
    if ($choice.Contains('Area') -and @($choice.Area).Count -lt $allAreas.Count) { $cmd += " -Area $($choice.Area -join ',')" }
    if ($choice.Contains('MemberServerOu')) { $cmd += " -MemberServerOu '$($choice.MemberServerOu)'" }
    if ($choice.Contains('Interactive') -and $choice.Interactive) { $cmd += ' -Interactive' }
    if ($choice.Contains('Apply') -and $choice.Apply) { $cmd += ' -Apply' }

    Write-Host ''
    Write-Host '  The same run as a command line, for a script or a scheduled task:' -ForegroundColor DarkGray
    Write-Host "    $cmd" -ForegroundColor Cyan
    Write-Host ''

    $go = Read-HardenMenuChoice -Question 'Run it?' -Default 'Y' -Options @(
        @{ Key = 'Y'; Label = 'Yes' }
        @{ Key = 'N'; Label = 'No - back to the start' }
        @{ Key = 'Q'; Label = 'Quit' }
    )
    if ($go -eq 'Q') { return $null }
    if ($go -eq 'N') { return Show-HardenMenu }
    return $choice
}

#endregion Menu

####################################################################################################
#region Entry point
####################################################################################################

$started = Get-Date
$exitCode = 0

# Argument validation before anything else runs. Deploy-only switches in a mode that cannot honour
# them are almost always a forgotten -Mode Deploy, and carrying on with the scan would be worse
# than an error: the person reads a successful-looking run and walks away believing something was
# deployed. -Area alone stays permitted, because a scoped scan is coherent.
# Checked here rather than after the prerequisites so the failure is not buried under half a
# screen of unrelated green ticks.
if ($Mode -ne 'Deploy' -and ($Apply -or $Interactive -or $MemberServerOu)) {
    $flags = @(
        if ($Apply) { '-Apply' }
        if ($Interactive) { '-Interactive' }
        if ($MemberServerOu) { '-MemberServerOu' }
    ) -join ', '

    $script = if ($PSCommandPath) { Split-Path $PSCommandPath -Leaf } else { 'ADHardenKit.ps1' }
    $suggest = ".\$script -Mode Deploy"
    if ($PSBoundParameters.ContainsKey('Area')) { $suggest += " -Area $($Area -join ',')" }
    if ($MemberServerOu) { $suggest += " -MemberServerOu '$MemberServerOu'" }
    if ($Interactive) { $suggest += ' -Interactive' }
    if ($Apply) { $suggest += ' -Apply' }

    Write-Host ''
    Write-Host "  $flags only has meaning in Deploy mode." -ForegroundColor Red
    # The "you forgot -Mode" hint is only true when they actually left it out. Saying it to
    # someone who typed -Mode Audit reads as the tool not having noticed what they wrote.
    $why = if ($PSBoundParameters.ContainsKey('Mode')) { "This run is in $Mode mode" }
    else { "This run is in Scan mode, which is the default when -Mode is not given" }
    Write-Host "  $why, so nothing was done." -ForegroundColor Red
    Write-Host ''
    Write-Host '  Probably meant:' -ForegroundColor DarkGray
    Write-Host "    $suggest" -ForegroundColor Cyan
    Write-Host ''
    exit 3
}

# Everything the report needs to say what this run was, in one place rather than assembled
# differently at each of the four call sites.
$runParameters = [ordered]@{
    Version        = $script:HardenKitVersion
    Mode           = $Mode
    Profile        = $HardeningProfile
    Level          = $Level
    Area           = $Area
    Apply          = [bool]$Apply
    Interactive    = [bool]$Interactive
    Force          = [bool]$Force
    GpoNamePattern = $GpoNamePattern
    MemberServerOu = $MemberServerOu
    ScanDays       = $ScanDays
    Server         = $Server
}

Initialize-HardenLog -LogDirectory $LogDirectory | Out-Null
Write-HardenLog -Message "ADHardenKit $script:HardenKitVersion" -Level Header

try {
    Initialize-HardenContext -Server $Server | Out-Null
    $ctx = Get-HardenContext
    Write-HardenLog -Message "Domain: $($ctx.DomainFqdn)" -Level Info
    Write-HardenLog -Message "Directory server: $($ctx.Server)" -Level Info
}
catch {
    Write-HardenLog -Message "Could not reach the directory - $($_.Exception.Message)" -Level Error
    exit 3
}

if (-not (Test-HardenPrerequisite)) {
    Write-HardenLog -Message 'Prerequisites not met.' -Level Error
    exit 3
}


# The menu is the front door for a person, never for a machine: it appears only when the script
# was started with no parameters at all on a console that can answer. Any parameter - even one -
# means the caller knew what they wanted, and -NoMenu covers the deliberate parameterless scan.
if ($PSBoundParameters.Count -eq 0 -and -not $NoMenu -and [Environment]::UserInteractive) {
    $menuChoice = Show-HardenMenu
    if ($null -eq $menuChoice) {
        Write-HardenLog -Message 'Nothing selected - nothing done.' -Level Info
        exit 0
    }
    foreach ($key in $menuChoice.Keys) {
        Set-Variable -Name $key -Value $menuChoice[$key] -Scope Script
    }
    # The report must describe what actually ran, not the pre-menu defaults.
    $runParameters['Mode'] = $Mode
    $runParameters['Profile'] = $HardeningProfile
    $runParameters['Level'] = $Level
    $runParameters['Area'] = $Area
    $runParameters['Apply'] = [bool]$Apply
    $runParameters['Interactive'] = [bool]$Interactive
    $runParameters['MemberServerOu'] = $MemberServerOu
}

switch ($Mode) {

    'Check' {
        Write-HardenLog -Message 'Prerequisite check only - nothing else was done.' -Level Info
        $summary = New-HardenSummary -Mode 'Check' -Started $started -Context (Get-HardenContext) -RunParameters $runParameters
        $report = New-HardenReport -Summary $summary -OutputDirectory $ReportDirectory
        Write-HardenLog -Message "Report: $($report.Html)" -Level Info
    }

    'Scan' {
        if ($Interactive) {
            Write-HardenLog -Message '-Interactive only applies to Deploy mode. Scan changes nothing, so there is nothing to confirm.' -Level Info
        }
        $blockers = @(Invoke-HardenScan -Days $ScanDays -Level $Level -Area $Area -HardeningProfile $HardeningProfile)
        $summary = New-HardenSummary -Mode 'Scan' -Started $started -Context (Get-HardenContext) `
            -RunParameters $runParameters -Baseline (Get-HardenBaseline | Where-Object { $_.Group -in $Area }) `
            -AuditPolicy (Get-HardenAuditPolicy) -Blockers $blockers
        $report = New-HardenReport -Summary $summary -OutputDirectory $ReportDirectory
        Write-HardenLog -Message "Report: $($report.Html)" -Level Info
        Write-HardenLog -Message "Data:   $($report.Json)" -Level Info
        if ($blockers.Count -gt 0) { $exitCode = 4 }
    }

    'Deploy' {
        if (-not $Apply) {
            $WhatIfPreference = $true
            Write-Host ''
            Write-Host '  PLAN MODE - nothing will be changed. Re-run with -Apply to deploy.' -ForegroundColor Yellow
        }

        if ($Level -eq 'Enforce' -and -not $Force) {
            Write-HardenLog -Message 'Level Enforce was requested. Run -Mode Scan first and read the result - this is the run that can break things.' -Level Warning
        }

        # The brake for the unattended sharp run. Not shown with -Interactive, where every topic is
        # confirmed anyway, nor with -Force, nor on a host with no console.
        if ($Apply -and -not $Interactive -and -not $Force -and [Environment]::UserInteractive) {
            if (-not (Confirm-HardenApply -HardeningProfile $HardeningProfile -Level $Level -Area $Area `
                        -GpoNamePattern $GpoNamePattern -MemberOu $MemberServerOu)) {
                Write-HardenLog -Message 'Not confirmed - nothing was written.' -Level Info
                exit 0
            }
        }

        if ($Interactive) {
            # Refuse rather than silently deploy everything: a host with no console cannot answer,
            # and a prompt that times out into yes is worse than no prompt at all.
            if (-not [Environment]::UserInteractive) {
                Write-HardenLog -Message '-Interactive was asked for but this session has no console to ask on. Nothing was done.' -Level Error
                exit 3
            }
            $script:InteractiveMode = $true
            Write-Host ''
            Write-Host '  Each topic - SMB signing, Credential Guard, and so on - is shown once with its' -ForegroundColor Cyan
            Write-Host '  current state on the directory server next to what it would become.' -ForegroundColor Cyan
            Write-Host '  Y or Enter deploys it, N skips it, A accepts everything remaining, Q stops here.' -ForegroundColor DarkGray
        }

        try {
            Invoke-HardenDeployment -HardeningProfile $HardeningProfile -Level $Level -Area $Area `
                -GpoNamePattern $GpoNamePattern -MemberOu $MemberServerOu -Confirm:$false
        }
        catch {
            if ($_.Exception.Message -ne 'HardenAbort') { throw }
            Write-HardenLog -Message 'Stopped on request. What was already written stays - the settings confirmed so far are deployed, the rest were never touched.' -Level Warning
        }

        $summary = New-HardenSummary -Mode $(if ($Apply) { 'Apply' } else { 'WhatIf' }) -Started $started `
            -Context (Get-HardenContext) -RunParameters $runParameters `
            -Baseline $script:ScopeBaseline -AuditPolicy $script:ScopeAuditPolicy
        Write-HardenLog -Message 'Summary' -Level Header
        if ($Apply) {
            Write-HardenLog -Message "Created: $($summary.Created) | Updated: $($summary.Updated) | Compliant: $($summary.Compliant) | Skipped: $($summary.Skipped) | Failed: $($summary.Failed)" -Level Info
        }
        else {
            # In plan mode everything lands in Planned, so the apply-shaped line reads as all
            # zeros and looks like the run did nothing - which after sixteen confirmations is
            # exactly the wrong message.
            Write-HardenLog -Message "Planned: $($summary.Planned) | Compliant: $($summary.Compliant) | Skipped: $($summary.Skipped) | Failed: $($summary.Failed)" -Level Info
            if ($summary.Planned -gt 0) {
                Write-HardenLog -Message "Nothing was written. The same command with -Apply deploys what was confirmed." -Level Info
            }
        }
        $report = New-HardenReport -Summary $summary -OutputDirectory $ReportDirectory
        Write-HardenLog -Message "Report: $($report.Html)" -Level Info
        Write-HardenLog -Message "Data:   $($report.Json)" -Level Info
        if ($summary.Failed -gt 0) { $exitCode = 1 }
    }

    'Audit' {
        Invoke-HardenDeployment -HardeningProfile $HardeningProfile -Level $Level -Area $Area `
            -GpoNamePattern $GpoNamePattern -MemberOu $MemberServerOu -AuditOnly -Confirm:$false

        $summary = New-HardenSummary -Mode 'Audit' -Started $started -Context (Get-HardenContext) `
            -RunParameters $runParameters -Baseline $script:ScopeBaseline -AuditPolicy $script:ScopeAuditPolicy
        Write-HardenLog -Message 'Audit summary' -Level Header
        Write-HardenLog -Message "Compliant: $($summary.Compliant) | Missing or drifted: $($summary.Missing) | Errors: $($summary.Failed)" -Level Info
        $report = New-HardenReport -Summary $summary -OutputDirectory $ReportDirectory
        Write-HardenLog -Message "Report: $($report.Html)" -Level Info
        Write-HardenLog -Message "Data:   $($report.Json)" -Level Info
        if ($summary.Missing -gt 0) { $exitCode = 2 }
    }
}

Write-HardenLog -Message "Log: $($script:LogFile)" -Level Info
exit $exitCode

#endregion Entry point
