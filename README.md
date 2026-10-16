<div align="center">

# ADHardenKit

Hardens the protocol layer of an Active Directory (signing, credential exposure, legacy authentication and audit logging) in an order that does not break the domain.

<br>

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?style=for-the-badge&logo=powershell&logoColor=white)](#prerequisites)
[![Platform](https://img.shields.io/badge/Windows_Server-2016%2B-0078D6?style=for-the-badge&logo=windows&logoColor=white)](#prerequisites)
![Lab tested](https://img.shields.io/badge/lab_tested-Server_2025-2ea44f?style=for-the-badge)
[![Settings](https://img.shields.io/badge/92_settings-38_topics-6f42c1?style=for-the-badge)](#what-it-deploys)
[![License](https://img.shields.io/badge/license-GPLv3-555555?style=for-the-badge)](LICENSE)

</div>

<br>

Most hardening settings can break something that used to work, and the breakage shows up far from the cause. Require LDAP signing and a print server stops finding the directory; enforce SMB signing and a NAS drops out at 3 a.m.; restrict NTLM and a line-of-business application stalls with an error that names nothing useful.

ADHardenKit turns on logging first, reads what the domain is actually doing, tells you by name which clients would break, and only then offers to enforce. Eight settings carry that risk, and each has an observing form and an enforcing form.

It is one PowerShell script with no module, configuration file or build step. A guided Windows app is available as a front end.

> [!WARNING]
> Lab-tested, not production-tested. Take a system state backup of a domain controller before the first enforced deployment.

> [!CAUTION]
> Unlinking the GPOs does not fully revert them. Only the 34 settings delivered as policy registry values disappear when the link goes. The 39 in the security template and the 18 written outside a `Policies` branch stay. See [rolling back](#rolling-back) for what to write back.

> [!NOTE]
> Most of the code and documentation was written by Claude (Anthropic) in a pair-programming workflow, with requirements defined and reviewed by a human. Review it before running it in production.

## Quick start

### Guided app

Download `ADHardenKit-win-x64.zip` from the releases page, unpack it on a domain controller or a management host with RSAT, and start `ADHardenKit.exe`. It needs no .NET installation.

The app walks through the recommended rollout and remembers, per domain, which steps are done:

1. Start: the rollout with the next step marked, a plain scan, or a custom deployment.
2. Check: RSAT modules, rights and WinRM. Missing RSAT comes with the install command to copy.
3. Scan: findings grouped by the group they would block, and how many settings are already in place.
4. Choose: profile, level, groups, member server OU (picked from the directory) and each topic, with its explanation, observing and enforcing value, and current value from the scan. The equivalent command line is shown for a change ticket or a scheduled task.
5. Preview: the engine's plan mode, listing every change before anything is written.
6. Deploy: needs an explicit confirmation; at level Enforce you type the domain name. If the scan finds something that still depends on the old behaviour, nothing is written and the findings are listed.
7. Done: the HTML report, the log, reboot notes and the next rollout step.

Every run is `ADHardenKit.ps1` in Windows PowerShell 5.1, with the same parameters, log and report as on the command line.

### Console

```powershell
Unblock-File .\ADHardenKit.ps1

# No parameters on a console: an interactive menu walks through mode, profile,
# level and scope, then prints the equivalent command line before running.
.\ADHardenKit.ps1

# 1. See where you stand. Read-only. (-NoMenu keeps this scriptable.)
.\ADHardenKit.ps1 -NoMenu

# 2. Turn on the observation. Nothing here can refuse an authentication.
.\ADHardenKit.ps1 -Mode Deploy -Area Logging -Apply -MemberServerOu 'OU=Servers,DC=example,DC=com'

# 3. Wait weeks. Then scan again — now it has something to report.
.\ADHardenKit.ps1

# 4. Deploy the rest in observing form, one topic at a time, with explanations.
.\ADHardenKit.ps1 -Mode Deploy -Interactive -Apply -MemberServerOu 'OU=Servers,DC=example,DC=com'
```

On a domain that has never been watched, the first scan will mostly report that it cannot see anything, because the diagnostics that produce the evidence are off by default. Step 2 fixes that.

## Modes

| Command | Writes | Purpose |
| --- | :---: | --- |
| `.\ADHardenKit.ps1` | no | Scan (default). Reads event logs and the directory, reports what would break if the staged settings were enforced today. |
| `.\ADHardenKit.ps1 -Mode Deploy` | yes | Creates and links the GPOs. Plans by default and writes only with `-Apply`. |
| `.\ADHardenKit.ps1 -Mode Audit` | no | Drift report against the selected profile. |
| `.\ADHardenKit.ps1 -Mode Check` | no | Prerequisite check only. |
| `.\ADHardenKit.ps1 -Mode Catalog` | no | The baseline as JSON. Needs no domain and no RSAT. The app reads this. |

| Switch | Effect |
| --- | --- |
| `-Apply` | Deploy mode only. Without it nothing is written, but the full plan is produced. |
| `-Interactive` | Ask before each topic, showing its current state on the directory server next to what it would become, with an explanation and a Microsoft article number. Deploy mode only. |
| `-Profile Baseline\|Strict` | `Baseline` (70 settings) carries little or no compatibility risk. `Strict` adds 22 that need a maintenance window. |
| `-Level Audit\|Enforce` | `Audit` deploys staged settings in their observing form. `Enforce` requires them. |
| `-Area <groups>` | `Signing`, `LegacyAuth`, `CredentialProtection`, `Protocols`, `PolicyIntegrity`, `Logging`, `Services`, `LOLBins`. `LOLBins` is not in the default set; ask for it by name. |
| `-MemberServerOu <dn>` | Where to link the member server GPOs. Without it they are created but left unlinked, and the run says so. The DC GPOs link to `OU=Domain Controllers` automatically. |
| `-Force` | Proceed even when the scan found evidence that enforcing would break something, and skip the confirmation an unattended `-Apply` otherwise asks for. `-Level Enforce -Apply` runs that scan first, for the selected areas, and stops with exit code `4` without `-Force`. |
| `-ExcludeTopic <names>` | Leave topics out of a Deploy run by name (for example `'Credential Guard and VBS'`). The non-interactive equivalent of declining a topic card. |
| `-EventStream` | One JSON object per line on stdout, prefixed `@@ADHK`, for a front end. Skips the console confirmation, because the front end asks its own. |
| `-AllowDowngrade` | Write a value even where the existing GPO already holds a stricter one. Without it a re-run never weakens a setting, for example a `-Level Audit` run over a GPO that was already enforced. |
| `-NoEventLog` | Skip the unsigned LDAP bind and NTLM sections, the only two that read an event log. Works from 1.3.0; earlier versions ignored it. |

Exit codes: `0` success, `1` failures, `2` drift found, `3` prerequisites failed, `4` enforcing would break something still in use.

## What it deploys

92 settings in 38 topics, plus 28 advanced audit subcategories and 50 LOLBin firewall rules in 6 topics. Each group becomes its own GPO per role, sixteen small ones in total. Names follow `-GpoNamePattern`, so they can match your own convention.

| Group | Domain controllers | Member servers | Settings |
| --- | --- | --- | :-: |
| Signing | `ADHardenKit-DC-Signing` | `ADHardenKit-Member-Signing` | 14 / 12 |
| LegacyAuth | `ADHardenKit-DC-LegacyAuth` | `ADHardenKit-Member-LegacyAuth` | 13 / 11 |
| CredentialProtection | `ADHardenKit-DC-CredentialProtection` | `ADHardenKit-Member-CredentialProtection` | 19 / 21 |
| Protocols | `ADHardenKit-DC-Protocols` | `ADHardenKit-Member-Protocols` | 24 / 26 |
| PolicyIntegrity | `ADHardenKit-DC-PolicyIntegrity` | `ADHardenKit-Member-PolicyIntegrity` | 3 / 3 |
| Logging | `ADHardenKit-DC-Logging` | `ADHardenKit-Member-Logging` | 13 / 10 |
| Services | `ADHardenKit-DC-Services` | `ADHardenKit-Member-Services` | 2 / 1 |
| LOLBins *(opt-in)* | `ADHardenKit-DC-LOLBins` | `ADHardenKit-Member-LOLBins` | 12 / 50 |

| Group | What it covers |
| --- | --- |
| Signing | LDAP server signing, channel binding, client integrity; SMB signing offered and required, with the audit policy that finds what would break first; Netlogon secure channel |
| LegacyAuth | NTLMv2 only, no LM hash; NTLM session security; NTLM restriction in both directions; Kerberos AES only; Kerberos armoring (FAST), the prerequisite for Authentication Policies; strong certificate mapping for Schannel (Windows has enforced the KDC side itself since 2025); no plaintext or guest SMB |
| CredentialProtection | LSA protection; Credential Guard with VBS (HVCI in Strict); RDP with NLA, TLS and no outbound credential delegation; WDigest, stored and cached credentials; four anonymous restrictions; machine account rotation; `LocalAccountTokenFilterPolicy` |
| Protocols | TLS 1.0/1.1, RC4 and Triple DES off in Schannel; LLMNR, NetBIOS and mDNS off, NetBIOS also per interface via a GPO startup script; the SMBv1 driver and its Workstation dependency; WinRM without basic, digest or plaintext; SMB 3.0 minimum dialect, authentication rate limiter, no remote mailslots; Point and Print restricted to administrators |
| PolicyIntegrity | UNC hardened paths for SYSVOL and NETLOGON with SMB encryption (MS15-011); forced reapplication of the security policy; no Group Policy caching, so a reboot applies the current policy |
| Logging | 28 audit subcategories; PowerShell logging; command line in event 4688; NTLM auditing; LDAP interface diagnostics; log sizes; `SCENoApplyLegacyAuditPolicy` |
| Services | Print Spooler disabled on domain controllers; WebClient (WebDAV redirector) disabled everywhere, which closes the HTTP relay path SMB signing cannot cover |
| LOLBins *(opt-in)* | Outbound network access blocked for binaries used as download cradles and C2 channels (certutil, mshta, bitsadmin, regsvr32, rundll32, the script hosts, the .NET proxies), as firewall rules inside the GPO so unlinking removes them |

If SMB signing turns out to have been holding up a NAS, you unlink the one `Signing` GPO and everything else stays in force. Domain controllers and member servers get separate GPOs because the roles need different settings; Credential Guard, for one, adds no security on a domain controller. A group with nothing applicable to a role produces no GPO.

The DC GPOs link to `OU=Domain Controllers` automatically. The member GPOs need `-MemberServerOu`; without it they are created and fully populated but left unlinked.

Audit subcategories are written by GUID. Names are localised, and a policy written by name applies to nothing on a German or French system.

## What runs where

The baseline targets Server 2016 and later, but some settings need a newer build. An older machine accepts the policy and ignores it without an error, so every affected setting carries its minimum version, the interactive card marks the row (for example `[Server 2025+]`), and the confirmation prompt counts them before anything is written.

| Minimum | Settings | What they are |
|---|:-:|---|
| Server 2012 | 2 | Kerberos armoring, KDC and client |
| Server 2016 | 3 | Credential Guard and HVCI (also need virtualisation and Secure Boot); SMB server signing audit (also needs the September 2025 cumulative update) |
| Server 2019 | 1 | mDNS off |
| Server 2025 | 8 | SMB encryption and guest audit, client signing audit, authentication rate limiter, remote mailslots, NetBIOS policy, SMB 3.0 minimum dialect |
| no constraint | 78 | everything else |

On Server 2022 and 2019, 8 of 92 settings do nothing; on Server 2016, 9. Nothing breaks either way, and signing, NTLM, Kerberos, LSA protection and auditing work everywhere.

Functional level and schema are separate from this. Almost everything is delivered as policy and applies at any level. Kerberos armoring is the exception: below domain functional level 2012 the KDC accepts the setting and behaves as though it were *Supported*, whatever level is configured. The prerequisite check reports the domain and forest level and the schema version on every run and warns when the level is too old, but still runs. No schema extension is needed.

## The eight staged settings

These are the settings that can break something.

| Setting | Observing | Enforcing | Where the breakage shows |
| --- | :-: | :-: | --- |
| LDAP server requires signing | `1` negotiate | `2` require | Directory Service log, event 2889 names every unsigned bind |
| LDAP channel binding | `1` when supported | `2` always | Directory Service log, events 3039, 3074, 3075 |
| LDAP client requires signing | `1` negotiate | `2` require | Local tools binding without signing, such as old monitoring or backup agents |
| SMB server requires signing | *not deployed* | `1` require | SMBServer/Audit log. Old NAS devices and appliances |
| SMB client requires signing | *not deployed* | `1` require | SMBClient/Connectivity log. Backup jobs pointed at old appliances |
| Deny outgoing NTLM | `1` audit | `2` deny | NTLM operational log, event 8001 |
| Deny incoming NTLM | *not deployed* | `2` deny | NTLM operational log, event 8002 on the receiving machine |
| Kerberos encryption types | `0x7FFFFFFC` | `0x7FFFFFF8` | Accounts whose `msDS-SupportedEncryptionTypes` still allows RC4 |

SMB signing has no observing value in its registry key. A zero would switch off signing that is already required on a domain controller, where it is on by default. So at `-Level Audit` those settings are left out, and a guard refuses to write a zero for any staged setting. Observe SMB signing with:

```powershell
Set-SmbServerConfiguration -AuditClientDoesNotSupportSigning $true
Set-SmbClientConfiguration -AuditServerDoesNotSupportSigning $true
```

## LOLBins (opt-in)

Check the firewall is on, write the rules switched off, then switch them on:

```powershell
.\ADHardenKit.ps1 -Mode Scan   -Area LOLBins -NoMenu
.\ADHardenKit.ps1 -Mode Deploy -Area LOLBins -MemberServerOu 'OU=Server,DC=example,DC=com' -Apply
.\ADHardenKit.ps1 -Mode Deploy -Area LOLBins -Level Enforce -MemberServerOu 'OU=Server,DC=example,DC=com' -Apply
```

The group writes outbound `Block` rules for 50 binaries into the GPO's own firewall policy:

| GPO | Baseline | Strict |
| --- | :-: | :-: |
| `ADHardenKit-Member-LOLBins` | 31 binaries, 63 rules | 50 binaries, 93 rules |
| `ADHardenKit-DC-LOLBins` | 12 binaries, 20 rules | 12 binaries, 20 rules |

The domain controller list is short on purpose. `certutil` fetching a CRL is part of certificate validation, and blocking it ends in an authentication outage that does not look like a firewall problem. The DC set only has binaries with no plausible role there: the HTML and script hosts, the two TFTP/FTP clients and a few downloaders. None is a Strict setting, so both profiles give the same 20 rules.

Baseline here means little or no compatibility risk, so only the source tool's Low impact entries are Baseline; Medium and High are Strict. Blocking `rundll32` or `wscript` outbound is in Strict.

`-Level Audit` writes the rules disabled, so nothing is blocked and you can review them in the GPMC. `-Level Enforce` switches them on. The run says clearly which one happened.

This group reads no event log. Roll it out with `-Profile Baseline` first, then `-Interactive` to accept or decline whole topics, then `-Profile Strict` if you want the rest. Leaving off `-Apply` prints the full rule set without writing anything.

Before enforcing:

- Firewall program rules match the image path, so a copy of `certutil.exe` in `%TEMP%` is not blocked. Use this under AppLocker or WDAC, as an extra layer.
- Some transfers do not run in the binary. BITS runs inside `svchost.exe`, so blocking `bitsadmin.exe` raises the bar without closing the path. Those entries are marked `Indirect`.
- A machine with the firewall off gets the rules and none of the effect. `-Mode Scan -Area LOLBins` checks the domain controllers' firewall state (one query, no event logs) and will not report the run as clean if a profile is off. It cannot check member servers, so sample one by hand.
- After enforcing, event 5157 names the blocked binary and destination. It comes from the Filtering Platform Connection subcategory, which this tool does not turn on; enable it with `auditpol` on the affected machine.

Unlike the other groups, this one does roll back by unlinking, because the rules live in policy and not in the machine's local firewall store.

## The rollout

| # | Step | Command | Notes |
|:-:|---|---|---|
| 1 | Logging | `-Area Logging -Apply` | Only writes records. Makes every later scan meaningful. |
| 2 | Scan | `-Mode Scan` | Now reading real data instead of an empty log. |
| 3 | Wait | | Weeks. The client that binds unsigned only at month-end is the one you would miss. |
| 4 | Signing, observing | `-Area Signing -Interactive -Apply` | LDAP to negotiate, channel binding to when-supported. Nothing required yet. |
| 5 | Protocols | `-Area Protocols -Apply` | LLMNR, NetBIOS, SMBv1, WinRM. Check for SMBv1 use first. |
| 6 | CredentialProtection | `-Area CredentialProtection -Apply` | Needs a reboot. Do one server first and check System log events 3033 and 3063. |
| 7 | LegacyAuth, observing | `-Area LegacyAuth -Profile Strict -Apply` | NTLMv2 only, and outgoing NTLM to audit. The staged LegacyAuth settings are all Strict, so without `-Profile Strict` there is nothing to observe; at level Audit, Strict adds only their observing forms. The scan also reports certificate mapping failures (System log events 39, 40, 41). |
| 8 | Scan until clean | `-Mode Scan` | Fix or replace what appears. This part is manual. |
| 9 | Enforce one group at a time | `-Level Enforce -Area Signing -Apply`, later `-Level Enforce -Area LegacyAuth -Profile Strict -Apply` | One group at a time, so you know which one broke something. Keep the profile a group was deployed with: a Baseline run over the LegacyAuth GPO drops the Strict values from it. |

### Verifying a deployment

`Created` means the files were written, not that clients have read them.

```powershell
gpupdate /force
.\Verify-LoggingDeployment.ps1
```

The script checks, in order: CSE registration on the GPO object, the files in SYSVOL, every deployed subcategory against `auditpol` output, the registry values, and the PowerShell log size (separating what policy configured from what the Event Log service is running with). `Verify-MemberDeployment.ps1` verifies a deployment on a member server.

## Prerequisites

| Requirement | Detail |
| --- | --- |
| PowerShell | 5.1 or 7.x with the `ActiveDirectory` and `GroupPolicy` modules (RSAT). `LOLBins` also needs the NetSecurity module; without it only that group fails. |
| Privileges | Elevated, permission to create and link GPOs, write access to `\\<domain>\SYSVOL\<domain>\Policies`. |
| Host | A domain controller or a management host with RSAT. The scan reads from the DCs over WinRM. |
| Windows | Server 2016 and later. See [what runs where](#what-runs-where) for settings that need a newer build. |

```powershell
.\ADHardenKit.ps1 -Mode Check
```

## Design notes

Security options are written into SYSVOL directly, because the `GroupPolicy` module cannot set them. The tool writes `GptTmpl.inf` as UTF-16 (the only encoding `secedit` reads), registers the security CSE in `gPCMachineExtensionNames` and bumps the GPO version. The advanced audit policy is its own CSE with its own `audit.csv`, written without a BOM. Getting either detail wrong leaves a policy in SYSVOL that does nothing and reports no error.

The Kerberos setting deploys `0x7FFFFFF8` instead of the often quoted `0x18`. The AES-only result is the same, and the reserved future-type bits stay set. Since the January 2026 updates the KDC side is governed by `DefaultDomainSupportedEncTypes`, defaulting to `0x18`, so the remaining work is finding accounts that still need RC4. The scan lists them.

If the LDAP diagnostic is off, the scan reports that as a finding, since an empty log says nothing about the domain. Settings whose platform default already matches the target are reported as compliant.

Before writing a security option, the tool reads what the GPO already holds and keeps the stricter value, so `-Level Audit` is safe to run again after a group was enforced. `-AllowDowngrade` overrides this.

## Reports

Every run writes a timestamped log to `.\Logs` and a JSON and HTML report to `.\Reports`. The HTML file is self-contained, so it can be emailed and printed. It has a colour-coded verdict, the run context, a card per topic with what it does and what it can break, a searchable table of every action, and next steps. References are KB and CVE numbers instead of links, so they still work when URLs move.

## Troubleshooting

The settings do not appear in the GPMC Settings tab. This is expected for Security Options on paths the GPMC has no friendly name for. Clients still apply them. Check with `gpresult /h` or read `GptTmpl.inf` from SYSVOL.

Nothing changed and the output says "PLAN MODE". `-Mode Deploy` plans by default. Add `-Apply`.

`-Interactive` produced no prompts. It only works in `Deploy` mode.

`auditpol` shows "No Auditing" after deploying Logging. Check the CSE registration first (`Verify-LoggingDeployment.ps1`, section 1). If that is correct, check whether the Default Domain Policy still has its own `audit.csv` in SYSVOL. If it is missing there, advanced auditing stops domain-wide, even for policies set elsewhere.

The PowerShell log is still 15 MB. The Event Log service reads channel sizes at startup and cannot be restarted on its own. The value is in the registry and takes effect at the next reboot.

The scan calls the LDAP result meaningless. The LDAP interface diagnostic is off, so event 2889 is not being written. Deploy the Logging group; it enforces nothing.

The run stops with exit code 3 and lists install commands. The `ActiveDirectory` or `GroupPolicy` module is missing. On a server: `Install-WindowsFeature RSAT-AD-PowerShell, GPMC`. On Windows 11: `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0` and `Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0`.

`-Level Enforce -Apply` stops with exit code 4. The scan found something that still uses what the enforcing value would refuse. The report lists it. Fix it first, or pass `-Force` if you have checked it is harmless. A diagnostic that is switched off (for example the LDAP interface events) also counts, because the scan cannot vouch for a log it cannot read.

The run warns that another GPO "outranks" this one. A GPO linked higher on the same OU, often the Default Domain Controllers Policy, sets the same security option and would win. The tool then links its own GPO at position 1 and reports the conflict. Remove the value from the other GPO when you can, so the result does not depend on link order.

The member GPOs exist but are not linked. No `-MemberServerOu` was given. They sit fully configured under Group Policy Objects in the GPMC. Re-run with the parameter; the link step is idempotent.

## Rolling back

Unlink the GPO. Disabling one link leaves the other groups untouched (verified in a lab). Unlinking stops further enforcement and lets the machine's own defaults reapply, but many settings stay in place:

| Delivered as | On unlink | Count |
| --- | --- | :-: |
| `registry.pol` under a `\Policies\` branch | removed at the next refresh | 34 |
| `registry.pol` outside those branches | stays | 18 |
| Security template (`GptTmpl.inf`) | stays | 39 |
| Startup script | script stops running, value stays | 1 |
| Firewall rules in the GPO | removed at the next refresh | 93 |

A security template sets values and does not take them back when the policy stops applying. That covers every Security Option, including LSA protection, the anonymous restrictions and the Netlogon settings. For a full revert, write the old values back:

```powershell
Set-GPLink -Name 'ADHardenKit-DC-Signing' -Target 'OU=Domain Controllers,DC=example,DC=com' -LinkEnabled No
gpupdate /force

# Diagnostics and log sizes
Set-ItemProperty 'HKLM:\System\CurrentControlSet\Services\NTDS\Diagnostics' -Name '16 LDAP Interface Events' -Value 0
Remove-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Operational' -Name MaxSize
Remove-ItemProperty 'HKLM:\System\CurrentControlSet\Services\EventLog\Directory Service' -Name MaxSize
Remove-ItemProperty 'HKLM:\System\CurrentControlSet\Services\Dnscache\Parameters' -Name EnableMDNS

# Schannel - removing the keys restores the platform default rather than the previous override
Remove-Item 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0' -Recurse
Remove-Item 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1' -Recurse
Get-ChildItem 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers' |
    Where-Object PSChildName -match 'RC4|Triple DES' | Remove-Item -Recurse

# LSA protection and the security template values
Remove-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name RunAsPPL
Remove-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name DisableRestrictedAdminOutboundCreds

# WebClient - the security template does not put a service back when the link goes
Set-Service -Name WebClient -StartupType Manual

# NetBIOS per interface, if the startup script has already run
Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\NetBT\Parameters\Interfaces' |
    ForEach-Object { Set-ItemProperty $_.PSPath -Name NetbiosOptions -Value 0 }
```

Schannel and NetBIOS changes need a reboot to take effect in both directions.

LSA protection is the hard one. `RunAsPPL = 1` also stores a UEFI variable on machines with Secure Boot, so removing the registry value is not enough: undoing it needs Microsoft's LSA protection opt-out tool and a confirmation at the console during boot. `RunAsPPL = 2` has no UEFI lock and is the value to prefer where an undo must stay possible. Test it on one server first.

## Limitations

- Deployment is additive. The tool sets values and never removes what was there before.
- One domain per run. For a forest, run it once per domain.
- The current-state section reads every domain controller in one remote call each and reports a value that differs between controllers as drift. Unreachable controllers are listed.
- Member server event logs are not read; the NTLM, SMB and LDAP findings come from the domain controllers. For the member side, forward NTLM/Operational, SMBServer/Audit and SMBClient/Audit with Windows Event Forwarding, or read them per server.
- The tool never connects to member servers and reaches them only through Group Policy. For the same reason the LOLBin scan only reports what ran on the domain controllers.
- Not included: tiering, OU structure, delegation, administrative accounts, user rights assignment, LAPS, authentication policy silos, AppLocker, BitLocker, Defender. For the tier boundary above this layer, see [ADTierKit](https://github.com/nopcap-tech/ADTierKit).

## Repository layout

```
ADHardenKit.ps1                  the entire tool
Verify-LoggingDeployment.ps1     post-deployment verification for the Logging group
Verify-MemberDeployment.ps1      post-deployment verification on a member server
tests/                           Pester tests (baseline data, parser, static checks)
gui/                             the guided Windows app (WPF, .NET 10) and its tests
PSScriptAnalyzerSettings.psd1    analyzer rules used by CI
.github/workflows/               CI: analyzer, Pester, GUI build and tests; release packaging
README.md · CHANGELOG.md · LICENSE
Logs/ · Reports/                 created on first run
```

The script is split into regions in execution order: `Core`, `Baseline`, `Interactive`, `Gpo`, `Scan`, `Deployment`, `Entry point`. `Baseline` is the largest and holds the settings as data. Each entry carries its explanation, blast radius, staged values, platform default and reference, which the interactive prompts and the report are built from. To change what the tool hardens, edit that table.

## License

[GNU General Public License v3.0](LICENSE). Copyright (C) 2026 nopcap.tech.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. It is distributed in the hope that it will be useful, but without any warranty, without even the implied warranty of merchantability or fitness for a particular purpose. See the licence for details.

Issues and pull requests are welcome. If you run this against a production directory, the maintainers would like to hear which staged setting broke something, and what it was.
