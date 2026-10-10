<div align="center">

# 🛡️ ADHardenKit

**Harden the protocol layer of an Active Directory — signing, credential exposure, legacy authentication and audit logging — in the order that does not break the domain.**

<br>

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?style=for-the-badge&logo=powershell&logoColor=white)](#prerequisites)
[![Platform](https://img.shields.io/badge/Windows_Server-2016%2B-0078D6?style=for-the-badge&logo=windows&logoColor=white)](#prerequisites)
![Lab tested](https://img.shields.io/badge/lab_tested-Server_2025-2ea44f?style=for-the-badge)
[![Settings](https://img.shields.io/badge/92_settings-38_topics-6f42c1?style=for-the-badge)](#what-it-deploys)
[![License](https://img.shields.io/badge/license-GPLv3-555555?style=for-the-badge)](LICENSE)

<br>

[**Quick start**](#quick-start) &nbsp;·&nbsp;
[**Modes**](#modes) &nbsp;·&nbsp;
[**What it deploys**](#what-it-deploys) &nbsp;·&nbsp;
[**Staged settings**](#the-eight-staged-settings) &nbsp;·&nbsp;
[**Rollout**](#the-rollout) &nbsp;·&nbsp;
[**Troubleshooting**](#troubleshooting)

</div>

<br>

```
   1. Logging  ──▶  2. Scan  ──▶  3. Wait  ──▶  4. Audit level  ──▶  5. Enforce
      nothing         read the      weeks,        observing,           the sharp
      can break       evidence      not days      not denying          one
```

<br>

Every setting in this tool can be found in a hardening checklist. That is not the hard part. The
hard part is that almost all of them can break something that used to work, and the breakage
surfaces far away from the cause: require LDAP signing and a print server stops finding the
directory; enforce SMB signing and a NAS drops out at 3 a.m.; restrict NTLM and a line-of-business
application stalls with an error that names nothing useful.

So checklists get half-applied, or applied on a Friday and rolled back on a Monday.

**ADHardenKit is built around the order of operations, not the list.** It turns on the observation
first, reads what the domain is actually doing, tells you by name which clients would break, and
only then offers to enforce. Eight settings carry that risk and each has two forms — one that
watches, one that requires.

One PowerShell script. No module, no configuration file, no build step.

<br>

> [!WARNING]
> **Lab-tested, not production-tested.** Take a system state backup of a domain controller before
> the first enforced deployment.

> [!CAUTION]
> **Unlinking is not a full revert.** Only the 34 settings delivered as policy registry values
> disappear when the link goes. The 39 in the security template and the 18 written outside a
> `Policies` branch stay where they are — see [rolling back](#rolling-back) for what to write back.

> [!NOTE]
> **Built with AI assistance.** Most of the code and documentation here was written by Claude
> (Anthropic) in a pair-programming workflow: requirements defined and reviewed by a human,
> implementation by the model. Review it before running it in production.

---

## Quick start

### With the guided app

Download `ADHardenKit-win-x64.zip` from the releases page, unpack it on a domain controller or a
management host with RSAT, and start `ADHardenKit.exe`. It needs no .NET installation.

The app walks through the recommended rollout and remembers, per domain, which steps are done:

1. **Start** — the rollout with the next step marked, or a plain scan, or a custom deployment.
2. **Check** — RSAT modules, rights and WinRM. Missing RSAT comes with the install command to copy.
3. **Scan** — findings grouped by the group they would block, and how many settings are already in place.
4. **Choose** — profile, level, groups, member server OU (picked from the directory) and each topic,
   with its explanation, its observing and enforcing value and its current value from the scan.
   The equivalent command line is shown for a change ticket or a scheduled task.
5. **Preview** — the engine's plan mode: every change, before anything is written.
6. **Deploy** — an explicit confirmation; at level Enforce, the domain name has to be typed. If the
   engine's scan finds something that still depends on the old behaviour, nothing is written and
   the findings are listed.
7. **Done** — the HTML report, the log, reboot notes and the next rollout step.

The app is a front end only: every run is `ADHardenKit.ps1` in Windows PowerShell 5.1, with the
same parameters, the same log and the same report as on the command line.

### From the console

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

On a domain that has never been watched, the first scan will mostly report that it **cannot see
anything** — the diagnostics that produce the evidence are off by default. That is expected, and it
is what step 2 fixes.

---

## Modes

| Command | Writes? | Purpose |
| --- | :---: | --- |
| `.\ADHardenKit.ps1` | — | **Scan.** The default. Reads event logs and the directory, reports what would break if the staged settings were enforced today. |
| `.\ADHardenKit.ps1 -Mode Deploy` | ⚠️ | Creates and links the GPOs. **Plans by default** — writes only with `-Apply`. |
| `.\ADHardenKit.ps1 -Mode Audit` | — | Read-only drift report against the selected profile. |
| `.\ADHardenKit.ps1 -Mode Check` | — | Prerequisite check only. |
| `.\ADHardenKit.ps1 -Mode Catalog` | — | The baseline as JSON. Needs no domain and no RSAT. What the app reads. |

| Switch | Effect |
| --- | --- |
| `-Apply` | Deploy mode only. Without it nothing is written, but the full plan is produced. |
| `-Interactive` | Ask before each topic, showing its **current state** on the directory server next to what it would become, with an explanation and a Microsoft article number. |
| `-Profile Baseline\|Strict` | `Baseline` (70 settings) carries little or no compatibility risk. `Strict` adds 22 that need a maintenance window. |
| `-Level Audit\|Enforce` | `Audit` deploys staged settings in their observing form. `Enforce` requires them. |
| `-Area <groups>` | `Signing`, `LegacyAuth`, `CredentialProtection`, `Protocols`, `PolicyIntegrity`, `Logging`, `Services`, `LOLBins`. `LOLBins` is **not** in the default set — ask for it by name. |
| `-MemberServerOu <dn>` | Where to link the member server GPOs. Without it they are created but left unlinked, and the run says so. The DC GPOs link to `OU=Domain Controllers` automatically. |
| `-Force` | Proceed even when the scan found evidence that enforcing would break something, and skip the confirmation an unattended `-Apply` otherwise asks for. `-Level Enforce -Apply` runs that scan first, for the selected areas, and stops with exit code `4` without `-Force`. |
| `-ExcludeTopic <names>` | Leave topics out of a Deploy run, by name (for example `'Credential Guard and VBS'`). The non-interactive equivalent of declining a topic card. |
| `-EventStream` | One JSON object per line on stdout, prefixed `@@ADHK`, for a front end. Skips the console confirmation, because the front end asks its own. |
| `-AllowDowngrade` | Write a value even where the existing GPO already holds a stricter one. Without it, a re-run never weakens a setting — for example a `-Level Audit` run over a GPO that was already enforced. |

**Exit codes** &nbsp; `0` success &nbsp;·&nbsp; `1` failures &nbsp;·&nbsp; `2` drift found &nbsp;·&nbsp; `3` prerequisites failed &nbsp;·&nbsp; `4` enforcing would break something still in use

---

## What it deploys

**92 settings in 38 topics, plus 28 advanced audit subcategories and 50 LOLBin firewall rules in 6
topics.** Every group becomes its own GPO per role — sixteen small ones rather than two large ones. Names follow `-GpoNamePattern`, so they
can match your own convention.

| Group | Domain controllers | Member servers | Settings |
| --- | --- | --- | :-: |
| **Signing** | `ADHardenKit-DC-Signing` | `ADHardenKit-Member-Signing` | 14 / 12 |
| **LegacyAuth** | `ADHardenKit-DC-LegacyAuth` | `ADHardenKit-Member-LegacyAuth` | 13 / 11 |
| **CredentialProtection** | `ADHardenKit-DC-CredentialProtection` | `ADHardenKit-Member-CredentialProtection` | 19 / 21 |
| **Protocols** | `ADHardenKit-DC-Protocols` | `ADHardenKit-Member-Protocols` | 24 / 26 |
| **PolicyIntegrity** | `ADHardenKit-DC-PolicyIntegrity` | `ADHardenKit-Member-PolicyIntegrity` | 3 / 3 |
| **Logging** | `ADHardenKit-DC-Logging` | `ADHardenKit-Member-Logging` | 13 / 10 |
| **Services** | `ADHardenKit-DC-Services` | `ADHardenKit-Member-Services` | 2 / 1 |
| **LOLBins** *(opt-in)* | `ADHardenKit-DC-LOLBins` | `ADHardenKit-Member-LOLBins` | 12 / 50 |

| Group | What it covers |
| --- | --- |
| **Signing** | LDAP server signing, channel binding, client integrity · SMB signing offered and required, **with the audit policy that finds what would break first** · Netlogon secure channel |
| **LegacyAuth** | NTLMv2 only, no LM hash · NTLM session security · NTLM restriction both directions · Kerberos AES only · **Kerberos armoring (FAST), the prerequisite for Authentication Policies** · strong certificate mapping for Schannel (the KDC side has been enforced by Windows itself since 2025) · no plaintext or guest SMB |
| **CredentialProtection** | LSA protection · Credential Guard with VBS (HVCI in Strict) · **RDP with NLA, TLS and no outbound credential delegation** · WDigest, stored and cached credentials · four anonymous restrictions · machine account rotation · `LocalAccountTokenFilterPolicy` |
| **Protocols** | **TLS 1.0/1.1, RC4 and Triple DES off in Schannel** · LLMNR, NetBIOS **and mDNS** off, NetBIOS also per interface via a GPO startup script · SMBv1 driver **and** the Workstation dependency that goes with it · WinRM without basic, digest or plaintext · **SMB 3.0 minimum dialect, authentication rate limiter, no remote mailslots** · **Point and Print restricted to administrators** |
| **PolicyIntegrity** | UNC hardened paths for SYSVOL and NETLOGON with SMB encryption (MS15-011) · forced reapplication of the security policy · no Group Policy caching, so a reboot applies the current policy and not the cached one |
| **Logging** | 28 audit subcategories · PowerShell logging · command line in event 4688 · NTLM auditing · LDAP interface diagnostics · log sizes · `SCENoApplyLegacyAuditPolicy` |
| **Services** | Print Spooler disabled on domain controllers · **WebClient (WebDAV redirector) disabled everywhere** — the HTTP relay path that SMB signing cannot cover |
| **LOLBins** *(opt-in)* | Outbound network access blocked for the binaries used as download cradles and C2 channels — certutil, mshta, bitsadmin, regsvr32, rundll32, the script hosts, the .NET proxies — as **firewall rules inside the GPO**, so unlinking removes them again |

The split is deliberate. When SMB signing turns out to have been holding up a NAS, you unlink the
one GPO named `Signing` and everything else stays in force. With one big GPO the only lever is all
or nothing, and under pressure people pick nothing.

Domain controllers and member servers get separate GPOs because the roles need different settings —
Credential Guard, for one, adds no security on a domain controller. A group with nothing applicable
to a role produces **no GPO at all**; before 1.3.1 that was the case for `ADHardenKit-Member-Services`,
which now exists because the WebClient setting applies to member servers too.

The **DC GPOs link to `OU=Domain Controllers` automatically**; the member GPOs need
`-MemberServerOu`. Without it they are created and fully populated but left unlinked, and the run
says so.

Audit subcategories are addressed by **GUID, not name** — names are localised, and a policy written
by name silently applies to nothing on a German or French system.

---

## What runs where

The baseline targets Server 2016 and later, but a handful of settings were introduced with newer
builds. An older machine accepts the policy, applies it, and **ignores it** — no error anywhere,
which is exactly the kind of silent non-effect the rest of this tool exists to surface. So it is
surfaced: every affected setting carries its minimum version, the interactive card marks the row
`[Server 2025+]`, and the confirmation prompt counts them before anything is written.

| Minimum | Settings | What they are |
|---|:-:|---|
| Server 2012 | 2 | Kerberos armoring, KDC and client |
| Server 2016 | 3 | Credential Guard, HVCI — also need virtualisation and Secure Boot; SMB server signing audit — also needs the September 2025 cumulative update |
| Server 2019 | 1 | mDNS off |
| Server 2025 | 8 | SMB encryption and guest audit, client signing audit, authentication rate limiter, remote mailslots, NetBIOS policy, SMB 3.0 minimum dialect |
| no constraint | 78 | everything else |

In practice: on **Server 2022** and **Server 2019**, 8 of 92 settings do nothing. On **Server 2016**, 9. Nothing breaks
either way, and the remainder — signing, NTLM, Kerberos, LSA protection, auditing — is the part
that matters most and works everywhere.

**Functional level and schema are a separate axis.** Almost everything here is delivered as policy
and applies at any level. The exception is Kerberos armoring, which the directory negotiates:
below domain functional level 2012 the KDC accepts the setting and behaves as though it were
*Supported* whatever level is configured. The prerequisite check reports the domain and forest
level and the schema version on every run, and says so when the level is too old — it does not
refuse to run, because a domain that cannot raise its level still benefits from the other ninety
settings. No schema extension is needed for anything in this tool.

---

## The eight staged settings

These are the ones that can break something.

| Setting | Observing | Enforcing | Where the breakage shows |
| --- | :-: | :-: | --- |
| LDAP server requires signing | `1` negotiate | `2` require | Directory Service log, **event 2889** names every unsigned bind |
| LDAP channel binding | `1` when supported | `2` always | Directory Service log, **events 3039, 3074, 3075** |
| LDAP client requires signing | `1` negotiate | `2` require | Local tools binding without signing — old monitoring, backup agents |
| SMB server requires signing | *not deployed* | `1` require | SMBServer/Audit log. Old NAS devices and appliances |
| SMB client requires signing | *not deployed* | `1` require | SMBClient/Connectivity log. Backup jobs pointed at old appliances |
| Deny outgoing NTLM | `1` audit | `2` deny | NTLM operational log, **event 8001** |
| Deny incoming NTLM | *not deployed* | `2` deny | NTLM operational log, **event 8002** on the receiving machine |
| Kerberos encryption types | `0x7FFFFFFC` | `0x7FFFFFF8` | Accounts whose `msDS-SupportedEncryptionTypes` still allows RC4 |

**Three say *not deployed* rather than a value**, and that is the interesting part. SMB signing has
no observation form in its registry key — it is either required or it is not. A zero there would
not observe anything, it would switch off signing that is already required on a domain controller
where it is on by default. So at `-Level Audit` those settings are left out entirely, and a guard
refuses to write a zero for a staged setting even if a future edit reintroduces one.

The observation belongs elsewhere:

```powershell
Set-SmbServerConfiguration -AuditClientDoesNotSupportSigning $true
Set-SmbClientConfiguration -AuditServerDoesNotSupportSigning $true
```

---

## LOLBins — the opt-in group

Check the firewall is actually on, write the rules switched off, then switch them on:

```powershell
.\ADHardenKit.ps1 -Mode Scan   -Area LOLBins -NoMenu
.\ADHardenKit.ps1 -Mode Deploy -Area LOLBins -MemberServerOu 'OU=Server,DC=example,DC=com' -Apply
.\ADHardenKit.ps1 -Mode Deploy -Area LOLBins -Level Enforce -MemberServerOu 'OU=Server,DC=example,DC=com' -Apply
```

Outbound `Block` rules for 50 binaries, written into the GPO's own firewall policy. What lands
where:

| GPO | Baseline | Strict |
| --- | :-: | :-: |
| `ADHardenKit-Member-LOLBins` | 31 binaries, 63 rules | 50 binaries, 93 rules |
| `ADHardenKit-DC-LOLBins` | 12 binaries, 20 rules | 12 binaries, 20 rules |

**The domain controller list is short on purpose.** `certutil` fetching a CRL is how certificate
validation works, and an outbound block there ends as an authentication outage that looks like
anything but a firewall rule. Only binaries with no plausible role on a domain controller are in
the DC set — the HTML and script hosts, the two TFTP/FTP clients, a handful of downloaders. None
of them is a Strict setting, which is why both profiles give the same twenty rules.

**`Baseline` follows impact, not the source tool's tier.** Baseline in this project means little or
no compatibility risk, and blocking `rundll32` or `wscript` outbound does not meet that bar however
sensible it is. Low impact is Baseline; Medium and High are Strict.

**`-Level Audit` writes the rules and leaves them disabled — nothing is blocked.** It is a review
step, so the change can be looked at in the GPMC before it bites. `-Level Enforce` switches them
on. The run says so loudly either way; this is the one group where a green, successful-looking
deployment can block nothing at all.

**Nothing here reads an event log.** The staged rollout is `-Profile Baseline` first (31 binaries,
the ones with no realistic breakage), then `-Interactive` to accept or decline whole topics, then
`-Profile Strict` later if you want the rest. Plan mode — leaving off `-Apply` — prints the
complete rule set without writing anything.

Four things worth knowing before enforcing:

- **A copy is not covered.** Firewall program rules match the image path, so `certutil.exe` copied
  into `%TEMP%` walks straight past this. It is a layer under AppLocker or WDAC, not a substitute
  for one.
- **Some transfers do not belong to the binary.** BITS runs inside `svchost.exe`; blocking
  `bitsadmin.exe` raises the bar without closing the path. Those entries are marked `Indirect`.
- **A machine with the firewall off gets all of this and none of the effect.** `-Mode Scan -Area LOLBins`
  checks the domain controllers' firewall state — one query, no event logs — and refuses to call the
  run clean if it finds a profile switched off. It cannot check member servers, so sample one by hand.
- **After enforcing, event 5157 is the diagnostic.** If something breaks, that event names the
  binary and the destination that was blocked. It comes from the Filtering Platform Connection
  subcategory, which this tool does not switch on — `auditpol` on the affected machine is enough.

Unlike everything else here, **this group really does roll back by unlinking**: the rules live in
policy, not in the machine's local firewall store.

## The rollout

Deploying hardening in one shot is how people end up rolling all of it back.

| # | Step | Command | Why here |
|:-:|---|---|---|
| 1 | **Logging** | `-Area Logging -Apply` | Only writes records. Makes every later scan meaningful. |
| 2 | **Scan** | `-Mode Scan` | Now reading real data instead of an empty log. |
| 3 | **Wait** | — | Weeks. The client that binds unsigned only at month-end is the one you would miss. |
| 4 | **Signing, observing** | `-Area Signing -Interactive -Apply` | LDAP to negotiate, channel binding to when-supported. Nothing required yet. |
| 5 | **Protocols** | `-Area Protocols -Apply` | LLMNR, NetBIOS, SMBv1, WinRM. Check for SMBv1 use first. |
| 6 | **CredentialProtection** | `-Area CredentialProtection -Apply` | Needs a reboot. One server first — check System log events 3033 and 3063. |
| 7 | **LegacyAuth, observing** | `-Area LegacyAuth -Profile Strict -Apply` | NTLMv2 only, and outgoing NTLM to audit. The staged LegacyAuth settings are all Strict, so without `-Profile Strict` there is nothing to observe; at level Audit, Strict adds only their observing forms. The scan also reports certificate mapping failures (System log events 39, 40, 41). |
| 8 | **Scan until clean** | `-Mode Scan` | Fix or replace what appears. This is the actual work, and no tool can do it for you. |
| 9 | **Enforce, one group at a time** | `-Level Enforce -Area Signing -Apply`, later `-Level Enforce -Area LegacyAuth -Profile Strict -Apply` | Never all at once — when something breaks you want to know which group did it. Keep the profile a group was deployed with: a Baseline run over the LegacyAuth GPO drops the Strict values from it. |

### Verifying a deployment

`Created` means files were written. It does not mean the client read them.

```powershell
gpupdate /force
.\Verify-LoggingDeployment.ps1
```

Checks the chain in the order it breaks: CSE registration on the GPO object → the files in SYSVOL
→ every deployed subcategory compared against `auditpol` output → the registry values → the
PowerShell log size, separating what policy configured from what the Event Log service is currently
running with.

---

## Prerequisites

| Requirement | Detail |
| --- | --- |
| PowerShell | 5.1 or 7.x with the `ActiveDirectory` and `GroupPolicy` modules (RSAT). |
| Privileges | Elevated, permission to create and link GPOs, write access to `\\<domain>\SYSVOL\<domain>\Policies`. |
| Host | A domain controller or a management host with RSAT. The scan reads from the DCs over **WinRM**. |
| Windows | Server 2016 and later. See [what runs where](#what-runs-where) — a few settings need a newer build and are marked. |

```powershell
.\ADHardenKit.ps1 -Mode Check
```

---

## Design decisions worth knowing

**Security options are written into SYSVOL directly.** The `GroupPolicy` module cannot set Security
Options, so the tool writes `GptTmpl.inf` (UTF-16 — `secedit` reads nothing else), registers the
security CSE in `gPCMachineExtensionNames` and bumps the GPO version. The advanced audit policy is
its own CSE with its own `audit.csv`, written without a BOM. Both details matter because getting
either wrong produces a policy that sits in SYSVOL doing nothing, with no error anywhere.

**The RC4 story is mostly decided by the platform now.** The Kerberos setting deploys `0x7FFFFFF8`
rather than the commonly quoted `0x18` (same AES-only result, but keeps the reserved future-type
bits). Since the January 2026 updates the KDC side is governed by `DefaultDomainSupportedEncTypes`,
defaulting to `0x18`; the remaining work is finding the accounts that still need RC4, which the
scan lists.

**The scan says when it cannot see.** If the LDAP diagnostic is off, an empty result means an empty
log, not a clean domain — and it is reported as a finding, not a pass. It also distinguishes
*absent* from *wrong*: settings whose platform default already matches the target are reported as
compliant, not as gaps.

**A re-run never weakens a setting.** Before writing a security option the tool reads what the
GPO already holds, and keeps the stricter value. That is what makes `-Level Audit` safe to run
again after a group was enforced. `-AllowDowngrade` is the explicit way back.

**Deployment is additive, and so is most of it on the way out.** The tool sets values and never
removes what was there before. Unlinking stops further enforcement, but only policy registry values
are withdrawn — the security template's values and everything outside a `Policies` branch stay.
Measured in a lab, not assumed.

---

## Reports

Every run writes a timestamped log to `.\Logs` and a JSON + HTML report to `.\Reports`. The HTML
is one self-contained file — no external dependencies, so it survives being emailed and prints
sensibly. It carries a colour-coded verdict, the full run context, an expandable card per topic
with what it does and what it can break, a searchable table of every action, and a
context-dependent "what to do next". References are KB/CVE **numbers, not links** — links rot, a
number can be pasted into any search box years from now.

---

## Troubleshooting

**The settings do not appear in the GPMC Settings tab.** Expected for Security Options on paths the
GPMC has no friendly name for. Clients apply them. Verify with `gpresult /h` or read `GptTmpl.inf`
from SYSVOL.

**Nothing changed and it says "PLAN MODE".** `-Mode Deploy` plans by default. Add `-Apply`.

**`-Interactive` produced no prompts.** It only applies to `Deploy` mode.

**`auditpol` shows "No Auditing" after deploying Logging.** Check the CSE registration first
(`Verify-LoggingDeployment.ps1`, section 1). If that is correct, check whether the **Default Domain
Policy** still has its own `audit.csv` in SYSVOL — a missing one there stops advanced auditing
domain-wide, even for policies set elsewhere.

**The PowerShell log is still 15 MB.** The Event Log service reads channel sizes at startup and
cannot be restarted on its own. The value is in the registry; it takes effect at the next reboot.

**The scan calls the LDAP result meaningless.** The LDAP interface diagnostic is off, so event 2889
is not being written. Deploy the Logging group; it enforces nothing.

**The run stops with exit code 3 and lists install commands.** The `ActiveDirectory` or
`GroupPolicy` module is missing. On a server: `Install-WindowsFeature RSAT-AD-PowerShell, GPMC`.
On Windows 11: `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0`
and `Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0`.

**`-Level Enforce -Apply` stops with exit code 4.** The scan found something that still uses what
the enforcing value would refuse. The report lists it; fix that first, or pass `-Force` if you have
checked it is harmless. A diagnostic that is switched off (for example the LDAP interface events)
also counts, because the scan cannot vouch for a log it cannot read.

**The run warns that another GPO "outranks" this one.** A GPO linked higher on the same OU — often
the Default Domain Controllers Policy — sets the same security option and would win. The tool links
its own GPO at position 1 in that case and reports the conflict; remove the value from the other GPO
when you get the chance, so the outcome does not depend on link order.

**The member GPOs exist but are not linked.** No `-MemberServerOu` was supplied. They sit fully
configured under **Group Policy Objects** in the GPMC, just without a link. Re-run with the
parameter — the link step is idempotent.

---

## Rolling back

Unlink the GPO. That is the design: small GPOs grouped by purpose exist so one can be taken out
without losing the rest — and that part works, verified in a lab: disabling one link left the
other groups untouched.

**But most settings do not disappear when the link goes.** This was measured rather than assumed,
and the result is less convenient than "unlink and you're done":

| Delivered as | On unlink | Count |
| --- | --- | :-: |
| `registry.pol` under a `\Policies\` branch | **removed at the next refresh** | 34 |
| `registry.pol` outside those branches | stays | 18 |
| Security template (`GptTmpl.inf`) | **stays** | 39 |
| Startup script | script stops running, value stays | 1 |
| Firewall rules in the GPO | **removed at the next refresh** | 93 |

The security template is the surprise: a template sets values and does not take them back when the
policy stops applying. That is most of the baseline — every Security Option, including LSA
protection, the anonymous restrictions and the Netlogon settings.

So unlinking is the right first move when something breaks, because it stops any further
enforcement and restores whatever the machine's own defaults reapply. It is not a full revert. For
that, write the old values back:

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

Schannel and NetBIOS changes need a **reboot** to take effect in both directions. LSA protection
is the hard one: `RunAsPPL = 1` also stores a UEFI variable on machines with Secure Boot, so removing
the registry value is not enough. Undoing it needs Microsoft's LSA protection opt-out tool and a
confirmation at the console during boot. `RunAsPPL = 2` (no UEFI lock) avoids this and is the
value to prefer where an undo must stay possible. Test it on one server before
the estate.

---

## Limitations & notes

- **Additive only.** The tool sets values and never removes what was there before. Unlinking stops enforcement without reverting most of it — see [rolling back](#rolling-back).
- **Single domain per run.** For a forest, run once per domain.
- **The current-state section reads every domain controller** in one remote call each, and reports a value that differs between controllers as drift. A controller that cannot be reached is listed, not silently skipped.
- **Member server event logs are not read.** The NTLM, SMB and LDAP findings come from the domain controllers. For the member side, forward the relevant channels (NTLM/Operational, SMBServer/Audit, SMBClient/Audit) with Windows Event Forwarding, or read them per server.
- **Member servers are only reached through Group Policy.** The tool never connects to them, which is also why the LOLBin scan can only report what ran on the domain controllers.
- **`LOLBins` needs the NetSecurity module** on the host running the tool (RSAT). Every other group deploys without it, and a missing module fails that group alone rather than the run.
- **`-NoEventLog` did nothing up to 1.2.0.** It was accepted, documented and never read. From 1.3.0 it skips the unsigned-LDAP-bind and NTLM sections, which are the only two that touch an event log.
- **Not included:** tiering, OU structure, delegation, administrative accounts, user rights assignment, LAPS, authentication policy silos, AppLocker, BitLocker, Defender. The tier boundary above this layer is [ADTierKit](https://github.com/nopcap-tech/ADTierKit).

---

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

The script is organised into regions — `Core`, `Baseline`, `Interactive`, `Gpo`, `Scan`,
`Deployment`, `Entry point` — in the order they execute.

`Baseline` is the largest region and contains almost no logic. That is deliberate: **the settings
are data, not code.** Every entry carries its own explanation, blast radius, staged values,
platform default and reference — which is also what the interactive prompts and the report are
built from. Changing what this tool hardens means editing a table.

## License

[GNU General Public License v3.0](LICENSE)

Copyright (C) 2026 nopcap.tech

This program is free software: you can redistribute it and/or modify it under the terms of the GNU
General Public License as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version. It is distributed in the hope that it will be
useful, but **without any warranty** — without even the implied warranty of merchantability or
fitness for a particular purpose. See the licence for details.

<div align="center">
<br>

**Built for the part of hardening that checklists leave out: the order.**

<sub>Issues and pull requests welcome. If you run this against a production directory, the
maintainers would genuinely like to hear which staged setting broke something, and what it was.</sub>

</div>
