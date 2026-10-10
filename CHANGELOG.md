# Changelog

## 1.4.0

### Fixed

- **Credential Guard was never switched on.** The policy wrote `LsaCfg` instead of `LsaCfgFlags`,
  so VBS came on and Credential Guard stayed off while the run reported the topic as deployed.
- **The Default Domain Controllers Policy could silently override the deployment.** New links were
  added last, so a conflicting value in a higher-ranked GPO won. The tool now compares the security
  options of every GPO linked on the same OU, reports conflicts and links its own GPO at position 1
  when there is one.
- **A re-run could weaken a setting.** `-Level Audit` over a GPO that was already enforced wrote the
  observing value back. Existing stricter values are now kept; `-AllowDowngrade` is the explicit
  way back.
- **`-Level Enforce -Apply` did not check what it would break.** It now runs the scan for the
  selected areas first and stops with exit code 4 unless `-Force` is given.
- **The RC4 scan missed accounts.** The LDAP filter used the AND matching rule for the AES bits and
  so ignored objects with only one AES type set.
- **Event logs were pulled across the network.** LDAP 2889, NTLM and KDC certificate events are now
  read on each domain controller over WinRM, and only the results come back. An empty log is
  recognised by its error id, not by its localised message text.
- **The current-state section read one domain controller.** It now reads all of them in one call
  each and reports values that differ between controllers as drift.
- Corrected event ids and minimum versions: SMB server signing audit is event 3021 and needs Server
  2016 with the September 2025 update; client signing audit is event 31998; SMB minimum dialect
  needs Server 2025; incoming NTLM is event 8002.
- The `RunAsPPL` explanation now says that value 1 writes a UEFI variable on Secure Boot machines.
- Print layout of the HTML report used an invalid CSS construct; it now expands the cards through
  `beforeprint` and `afterprint`.
- Missing RSAT modules end the run with exit code 3 and the install commands, instead of a stack of
  follow-up errors.
- `Verify-MemberDeployment.ps1` claimed the per-interface NetBIOS setting reaches domain controllers
  only. It reaches both roles through the startup script.

### Removed

- **Strong certificate binding on the KDC** (`StrongCertificateBindingEnforcement`). Full enforcement
  is the default since February 2025 and the value is no longer read since September 2025. The scan
  still reports KDC events 39, 40 and 41.

### Added

- `-AllowDowngrade`.
- Pester tests for the baseline data, the audit policy and the security template parser.
- `PSScriptAnalyzerSettings.psd1` and a GitHub Actions workflow running both on Windows PowerShell
  5.1 and PowerShell 7.

### Documentation

- README counts regenerated from the code: 92 settings, eight staged settings, the corrected
  version table and the corrected rollback counts.
