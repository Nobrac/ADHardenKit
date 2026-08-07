<div align="center">

# 🛡️ ADHardenKit

**Harden the protocol layer of an Active Directory — signing, credential exposure, legacy authentication and audit logging — in the order that does not break the domain.**

<br>

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?style=for-the-badge&logo=powershell&logoColor=white)](#prerequisites)
[![Platform](https://img.shields.io/badge/Windows_Server-2016%2B-0078D6?style=for-the-badge&logo=windows&logoColor=white)](#prerequisites)
[![Lab tested](https://img.shields.io/badge/lab_tested-Server_2025-2ea44f?style=for-the-badge)](#what-has-been-tested)
[![Settings](https://img.shields.io/badge/61_settings-29_topics-6f42c1?style=for-the-badge)](#what-it-deploys)
[![License](https://img.shields.io/badge/license-MIT-555555?style=for-the-badge)](LICENSE)

<br>

[**Quick start**](#quick-start) &nbsp;·&nbsp;
[**Modes**](#modes) &nbsp;·&nbsp;
[**What it deploys**](#what-it-deploys) &nbsp;·&nbsp;
[**Staged settings**](#the-nine-staged-settings) &nbsp;·&nbsp;
[**Rollout**](#the-rollout) &nbsp;·&nbsp;
[**Tested**](#what-has-been-tested) &nbsp;·&nbsp;
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
only then offers to enforce. Nine settings carry that risk and each has two forms — one that
watches, one that requires.

One PowerShell script. No module, no configuration file, no build step.

<br>

> [!WARNING]
> **Lab-tested, not production-tested.** Every mode has been run end to end against a Windows
> Server 2025 lab domain and each mechanism verified individually — see [what has been
> tested](#what-has-been-tested). No production directory, no Pester suite, no second reviewer.
> Take a system state backup of a domain controller before the first enforced deployment.

> [!CAUTION]
> **Two settings tattoo.** The LDAP interface diagnostic and the event log sizes live outside the
> `Policies` registry branch, so unlinking the GPO does **not** remove them — see [rolling
> back](#rolling-back). Everything else disappears when the link is removed.

> [!NOTE]
> **Built with AI assistance.** Most of the code and documentation here was written by Claude
> (Anthropic) in a pair-programming workflow: requirements defined and reviewed by a human,
> implementation by the model. Review it before running it in production.

---

## Quick start

```powershell
Unblock-File .\ADHardenKit.ps1

# 1. See where you stand. Read-only.
.\ADHardenKit.ps1

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

| Switch | Effect |
| --- | --- |
| `-Apply` | Deploy mode only. Without it nothing is written, but the full plan is produced. |
| `-Interactive` | Ask before each topic, showing its **current state** on the directory server next to what it would become, with an explanation and a Microsoft article number. |
| `-Profile Baseline\|Strict` | `Baseline` (51 settings) carries little or no compatibility risk. `Strict` adds 10 that need a maintenance window. |
| `-Level Audit\|Enforce` | `Audit` deploys staged settings in their observing form. `Enforce` requires them. |
| `-Area <groups>` | `Signing`, `LegacyAuth`, `CredentialProtection`, `Protocols`, `PolicyIntegrity`, `Logging`, `Services`. |
| `-MemberServerOu <dn>` | Where to link the member server GPOs. Without it they are created but left unlinked, and the run says so. The DC GPOs link to `OU=Domain Controllers` automatically. |
| `-Force` | Proceed even when the scan found evidence that enforcing would break something. |

**Exit codes** &nbsp; `0` success &nbsp;·&nbsp; `1` failures &nbsp;·&nbsp; `2` drift found &nbsp;·&nbsp; `3` prerequisites failed &nbsp;·&nbsp; `4` enforcing would break something still in use

---

## What it deploys

**61 settings in 29 topics, plus 28 advanced audit subcategories.** Every group becomes its own GPO
per role — thirteen small ones rather than two large ones. Names follow `-GpoNamePattern`, so they
can match your own convention.

| Group | Domain controllers | Member servers | Settings |
| --- | --- | --- | :-: |
| **Signing** | `ADHardenKit-DC-Signing` | `ADHardenKit-Member-Signing` | 11 / 9 |
| **LegacyAuth** | `ADHardenKit-DC-LegacyAuth` | `ADHardenKit-Member-LegacyAuth` | 11 / 10 |
| **CredentialProtection** | `ADHardenKit-DC-CredentialProtection` | `ADHardenKit-Member-CredentialProtection` | 15 / 17 |
| **Protocols** | `ADHardenKit-DC-Protocols` | `ADHardenKit-Member-Protocols` | 6 / 6 |
| **PolicyIntegrity** | `ADHardenKit-DC-PolicyIntegrity` | `ADHardenKit-Member-PolicyIntegrity` | 2 / 2 |
| **Logging** | `ADHardenKit-DC-Logging` | `ADHardenKit-Member-Logging` | 13 / 10 |
| **Services** | `ADHardenKit-DC-Services` | — none, no setting applies | 1 / — |

| Group | What it covers |
| --- | --- |
| **Signing** | LDAP server signing, channel binding, client integrity · SMB signing offered and required · Netlogon secure channel |
| **LegacyAuth** | NTLMv2 only, no LM hash · NTLM session security · NTLM restriction both directions · Kerberos AES only · strong certificate binding · no plaintext or guest SMB |
| **CredentialProtection** | LSA protection · Credential Guard with VBS and HVCI · WDigest, stored and cached credentials · four anonymous restrictions · machine account rotation · `LocalAccountTokenFilterPolicy` |
| **Protocols** | LLMNR and NetBIOS off · SMBv1 driver **and** the Workstation dependency that goes with it · WinRM without basic, digest or plaintext |
| **PolicyIntegrity** | UNC hardened paths for SYSVOL and NETLOGON (MS15-011) · forced reapplication, so local drift is corrected within the hour |
| **Logging** | 28 audit subcategories · PowerShell logging · command line in event 4688 · NTLM auditing · LDAP interface diagnostics · log sizes · `SCENoApplyLegacyAuditPolicy` |
| **Services** | Print Spooler disabled on domain controllers |

The split is deliberate. When SMB signing turns out to have been holding up a NAS, you unlink the
one GPO named `Signing` and everything else stays in force. With one big GPO the only lever is all
or nothing, and under pressure people pick nothing.

Domain controllers and member servers get separate GPOs because the roles need different settings —
Credential Guard, for one, adds no security on a domain controller. A group with nothing applicable
to a role produces **no GPO at all**, which is why there is no `ADHardenKit-Member-Services`.

The **DC GPOs link to `OU=Domain Controllers` automatically**; the member GPOs need
`-MemberServerOu`. Without it they are created and fully populated but left unlinked, and the run
says so.

Audit subcategories are addressed by **GUID, not name** — names are localised, and a policy written
by name silently applies to nothing on a German or French system.

---

## The nine staged settings

These are the ones that can break something.

| Setting | Observing | Enforcing | Where the breakage shows |
| --- | :-: | :-: | --- |
| LDAP server requires signing | `1` negotiate | `2` require | Directory Service log, **event 2889** names every unsigned bind |
| LDAP channel binding | `1` when supported | `2` always | Directory Service log, **events 3039, 3074, 3075** |
| LDAP client requires signing | `1` negotiate | `2` require | Local tools binding without signing — old monitoring, backup agents |
| SMB server requires signing | *not deployed* | `1` require | SMBServer/Audit log. Old NAS devices and appliances |
| SMB client requires signing | *not deployed* | `1` require | SMBClient/Connectivity log. Backup jobs pointed at old appliances |
| Deny outgoing NTLM | `1` audit | `2` deny | NTLM operational log, **event 8001** |
| Deny incoming NTLM | *not deployed* | `2` deny | NTLM operational log, **event 8004** |
| Kerberos encryption types | `0x7FFFFFFC` | `0x7FFFFFF8` | Accounts whose `msDS-SupportedEncryptionTypes` still allows RC4 |
| Strong certificate binding | `1` compatibility | `2` enforce | System log, **events 39, 40, 41** |

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
| 7 | **LegacyAuth, observing** | `-Area LegacyAuth -Apply` | Outgoing NTLM to audit, certificate binding to compatibility. |
| 8 | **Scan until clean** | `-Mode Scan` | Fix or replace what appears. This is the actual work, and no tool can do it for you. |
| 9 | **Enforce, one group at a time** | `-Level Enforce -Area Signing -Apply` | Never all at once — when something breaks you want to know which group did it. |

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
| Windows | Server 2016+. Credential Guard and HVCI need virtualisation and Secure Boot. The NetBIOS policy exists only on Windows 11 22H2 / Server 2025 and later. |

```powershell
.\ADHardenKit.ps1 -Mode Check
```

---

## What has been tested

<div align="center">

**Server 2025 lab domain** &nbsp;·&nbsp; **4 GPOs deployed and linked** &nbsp;·&nbsp; **28/28 audit subcategories verified applied** &nbsp;·&nbsp; **0 failures**

</div>

Each mechanism was verified individually rather than inferred from a clean exit code: `GptTmpl.inf`
read back from SYSVOL, CSE registration read from the GPO object, every deployed audit GUID
compared against `auditpol /get /category:* /r`, `audit.csv` checked byte-level for a BOM,
idempotency confirmed at `Created: 0`, and the interactive flow driven through `Y`, `N`, `A`, `S`
and `Q` with scripted answers.

### The bugs the lab found

This list matters more than the successes, because it is the argument for testing rather than
reading:

| Bug | Effect if it had shipped |
|---|---|
| `@()` flattening the audit table | 25 rows became 125 loose strings — `audit.csv` would have been nonsense |
| Audit CSE filed as a tool GUID | `auditcse.dll` never invoked; the entire advanced audit policy silently inert |
| `AuditValue = 0` on SMB signing | The "safe" audit level would have **switched off** required SMB signing on a domain controller |
| `$level` colliding with the `-Level` parameter | The NTLM scan crashed and reported 665 events with "no direction" |
| `$script:Interactive` colliding with the `-Interactive` switch | The switch was silently overwritten; no prompts ever appeared |
| Plan mode skipping the settings loop | `-Mode Deploy` without `-Apply` showed two GPO names and nothing else |

Five of six needed a real directory or a real browser to surface. Two of them — the inert audit
policy and the SMB downgrade — would have caused real harm in production.

**Not tested:** production directory, multi-domain forest, Pester suite, second reviewer, code
signing. `-Level Enforce` has never run against a populated directory, and the GPO version bump is
only verified indirectly.

---

## Design decisions worth knowing

**Security options are written into SYSVOL directly.** The `GroupPolicy` module cannot set Security
Options, so the tool writes `GptTmpl.inf`, registers the security CSE in
`gPCMachineExtensionNames` and bumps the GPO version. The file has to be **UTF-16** — `secedit`
reads nothing else. The extension attribute is a list of bracketed groups where each group is one
CSE GUID followed by all of its tool GUIDs: `[{CSE}{tool}{tool}]`, not `[{CSE}{tool}][{CSE}{tool}]`.
Two groups with the same CSE GUID is malformed and breaks policy processing.

**The advanced audit policy is its own CSE.** `{F3CCC681-…}` is `auditcse.dll` itself, not a tool
GUID under the security CSE. Getting that wrong — as this tool did until it was caught — means the
whole audit policy sits in SYSVOL doing nothing, with no error anywhere. The file is also written
**without a BOM**, because `Set-Content -Encoding UTF8` on PowerShell 5.1 writes one and it lands
in front of the header the CSE parses.

**The RC4 story changed under everyone's feet.** The Kerberos setting deploys `0x7FFFFFF8` rather
than the commonly quoted `0x18` — both are AES-only today, but `0x18` drops the reserved future-type
bits. More importantly this is only the member-side policy: since the January 2026 update the KDC
side is governed by `DefaultDomainSupportedEncTypes`, defaulting to `0x18`, and
`RC4DefaultDisablementPhase` stopped being read with the July 2026 updates.

**The scan says when it cannot see.** If the LDAP diagnostic is off, an empty result means an empty
log, not a clean domain — and that is the most dangerous kind of green, because it invites someone
to enforce on the strength of it. It also distinguishes *absent* from *wrong*: an unset
`UseLogonCredential` means WDigest does not cache, which is compliant, not a gap. Seven settings
carry their documented platform default for exactly this reason.

**Deployment is additive.** The tool sets values; it never removes what was there before. Rollback
is unlinking.

---

## Reports

Every run writes a timestamped log to `.\Logs` and a JSON + HTML report to `.\Reports`. The HTML is
a single self-contained file with no external dependencies, so it survives being emailed, and it
prints sensibly.

It carries a colour-coded verdict, the full run context (domain, server, profile, level, scope, who
ran it from where), the scan findings, an expandable card per topic with what it does and what it
can break, a searchable table of every action, all 28 audit subcategories with reasons, and a
context-dependent "what to do next".

References are **numbers, not links** — KB, ADV and CVE identifiers. Links rot; a number can be
pasted into any search box years from now.

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

**The member GPOs exist but are not linked.** No `-MemberServerOu` was supplied. They sit fully
configured under **Group Policy Objects** in the GPMC, just without a link. Re-run with the
parameter — the link step is idempotent.

---

## Rolling back

Unlink the GPO. That is the design: small GPOs grouped by purpose exist so one can be taken out
without losing the rest.

```powershell
Set-GPLink -Name 'ADHardenKit-DC-Signing' -Target 'OU=Domain Controllers,DC=example,DC=com' -LinkEnabled No
gpupdate /force
```

**Two settings do not disappear**, because they live outside the `Policies` branch:

```powershell
Set-ItemProperty 'HKLM:\System\CurrentControlSet\Services\NTDS\Diagnostics' -Name '16 LDAP Interface Events' -Value 0
Remove-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Operational' -Name MaxSize
Remove-ItemProperty 'HKLM:\System\CurrentControlSet\Services\EventLog\Directory Service' -Name MaxSize
```

Reboot-dependent settings have no undo other than setting them back and rebooting again. Test LSA
protection on one server before the estate.

---

## Limitations & notes

- **Additive only.** Rollback is unlinking, not running the tool backwards.
- **Single domain per run.** For a forest, run once per domain.
- **The scan reads one domain controller** for the current-state section. Settings differing between controllers in a multi-site domain will not be caught.
- **Member servers are only reached through Group Policy.** The tool never connects to them.
- **Not included:** tiering, OU structure, delegation, administrative accounts, user rights assignment, LAPS, authentication policy silos, AppLocker, BitLocker, Defender. The tier boundary above this layer is [ADTierKit](https://github.com/nopcap-tech/ADTierKit).

---

## Repository layout

```
ADHardenKit.ps1                  the entire tool
Verify-LoggingDeployment.ps1     post-deployment verification for the Logging group
README.md · LICENSE
Logs/ · Reports/                 created on first run
```

The script is organised into regions — `Core`, `Baseline`, `Interactive`, `Gpo`, `Scan`,
`Deployment`, `Entry point` — in the order they execute.

`Baseline` is the largest and contains almost no logic. That is deliberate: **the settings are
data, not code.** Changing what this tool hardens means editing a table, and every entry carries its
own explanation, blast radius, staged values, platform default and reference — which is also what
the interactive prompts and the report are built from.

```powershell
$s.Add([ordered]@{
    Id = 'LDAP-ServerSigning'; Topic = 'LDAP signing and channel binding'
    Reference = 'KB4520412, ADV190023, CVE-2017-8563'; Group = 'Signing'
    Name = 'LDAP server requires signing'
    Type = 'SecurityOption'; Target = 'DC'; Profile = 'Baseline'; Staged = $true
    Key = 'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity'
    ValueType = 4; AuditValue = 1; EnforceValue = 2
    Why = 'An unsigned LDAP bind can be relayed. Requiring signing closes that, but any client that binds without signing stops working.'
    Observe = 'Directory Service log, event 2889 names every client that bound without signing.'
})
```

## License

[MIT](LICENSE)

<div align="center">
<br>

**Built for the part of hardening that checklists leave out: the order.**

<sub>Issues and pull requests welcome. If you run this against a production directory, the
maintainers would genuinely like to hear which staged setting broke something, and what it was.</sub>

</div>
