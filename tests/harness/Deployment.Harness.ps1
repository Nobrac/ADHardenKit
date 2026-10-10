# Runs Invoke-HardenDeployment against a fake SYSVOL folder and mocked Group Policy cmdlets:
# plan mode, apply, never-weaken, link precedence, -ExcludeTopic and audit mode. Prints one line
# per check and 'failures: N' at the end; tests/Logic.Tests.ps1 runs it in a child process.
param($Repo)
$ErrorActionPreference = 'Stop'
. (Join-Path $Repo 'tests/TestHelper.ps1')
$root = Join-Path ([IO.Path]::GetTempPath()) ("adhk" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory "$root/Policies" | Out-Null
$script:LogFile = $null; $script:EventStream = $false; $script:ExcludedTopics = @()
$script:Actions = [System.Collections.Generic.List[object]]::new()
$script:InteractiveMode = $false; $script:AutoDecision = $null; $script:DecisionCache = @{}; $script:LiveCache = @{}
$script:BackupDirectory = "$root/Backups"
$script:Context = [pscustomobject]@{ DomainFqdn='corp.test'; DomainDn='DC=corp,DC=test'; DomainControllersDn='OU=Domain Controllers,DC=corp,DC=test'; Server='dc1.corp.test'; SysvolPolicyPath="$root/Policies" }
$global:Gpos = @{}; $global:Links = [System.Collections.Generic.List[object]]::new(); $global:LinkCalls = [System.Collections.Generic.List[string]]::new()
$global:Live = @{}
function global:Get-GPO { param($Name,$Domain,$Server,$ErrorAction) $global:Gpos[$Name] }
function global:New-GPO { param($Name,$Comment,$Domain,$Server,$ErrorAction) $g=[pscustomobject]@{ Id=[guid]::NewGuid(); DisplayName=$Name }; $global:Gpos[$Name]=$g; $g }
function global:Get-GPInheritance { param($Target,$Domain,$Server,$ErrorAction) [pscustomobject]@{ GpoLinks = @($global:Links | Where-Object Target -eq $Target) } }
function global:New-GPLink { param($Name,$Target,$LinkEnabled,$Order,$Domain,$Server,$ErrorAction)
  $global:LinkCalls.Add("New $Name order=$Order")
  $ours=[pscustomobject]@{ DisplayName=$Name; GpoId=$global:Gpos[$Name].Id; Target=$Target; Enabled=$true; Order=0 }
  $list=@($global:Links | Where-Object Target -eq $Target | Sort-Object Order)
  if ($Order -eq 1) { $list = @($ours) + $list } else { $list = $list + @($ours) }
  for($i=0;$i -lt $list.Count;$i++){ $list[$i].Order=$i+1 }
  if ($global:Links -notcontains $ours) { $global:Links.Add($ours) } }
function global:Set-GPLink { param($Name,$Target,$LinkEnabled,$Order,$Domain,$Server,$ErrorAction)
  $global:LinkCalls.Add("Set $Name order=$Order")
  $list=@($global:Links | Where-Object Target -eq $Target | Sort-Object Order); $ours=$list | Where-Object DisplayName -eq $Name
  if ($Order -eq 1) { $list = @($ours) + @($list | Where-Object { $_ -ne $ours }) }
  for($i=0;$i -lt $list.Count;$i++){ $list[$i].Order=$i+1 } }
function Set-HardenRegistrySetting { param($GpoName,$Key,$ValueName,$Type,$Value,[switch]$AuditOnly,$Confirm) if ($WhatIfPreference) { 'Planned' } else { 'Created' } }
function Add-HardenGpoExtension { param($Gpo,$CseGuid,$ToolGuid) }
function Update-HardenGpoVersion { param($Gpo) }
function Set-HardenAuditCsv { 'Created' }
function Set-HardenStartupScript { 'Created' }
function Get-HardenLiveValue { param($Item) $v=$global:Live[$Item.Id]; if ($null -eq $v) { 'not set' } else { "$v" } }
function Write-Host { }
$fail = 0
function Check($name, $cond) { if ($cond) { "  ok   $name" } else { "  FAIL $name"; $script:fail++ } }
function Tmpl($gpoName) { Get-HardenTemplateValue -Gpo $global:Gpos[$gpoName] }
$K='MACHINE\SYSTEM\CURRENTCONTROLSET\SERVICES\NTDS\PARAMETERS\LDAPSERVERINTEGRITY'

# Default Domain Controllers Policy linked on the DC OU, setting LDAP server signing to 1
$ddcp=[pscustomobject]@{ Id=[guid]::NewGuid(); DisplayName='Default Domain Controllers Policy' }; $global:Gpos[$ddcp.DisplayName]=$ddcp
$d="$root/Policies/{$($ddcp.Id.ToString().ToUpper())}/Machine/Microsoft/Windows NT/SecEdit"; New-Item -ItemType Directory $d -Force | Out-Null
[IO.File]::WriteAllText("$d/GptTmpl.inf","[Unicode]`r`nUnicode=yes`r`n[Registry Values]`r`nMACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity=4,1`r`n",[Text.Encoding]::Unicode)
$global:Links.Add([pscustomobject]@{ DisplayName=$ddcp.DisplayName; GpoId=$ddcp.Id; Target='OU=Domain Controllers,DC=corp,DC=test'; Enabled=$true; Order=1 })

"1. Plan mode writes nothing"
$WhatIfPreference = $true
Invoke-HardenDeployment -HardeningProfile Baseline -Level Audit -Area Signing -GpoNamePattern 'ADHardenKit-{ROLE}-{GROUP}' -MemberOu 'OU=Servers,DC=corp,DC=test' -Confirm:$false
$WhatIfPreference = $false
Check 'no GPO created' ($global:Gpos.Count -eq 1)
Check 'LDAP signing planned at 1' (@($script:Actions | ? { $_.Setting -eq 'LDAP-ServerSigning' -and $_.Detail -like '1*' }).Count -eq 1)
Check 'DDCP conflict reported in plan' (@($script:Actions | ? { $_.Setting -like '*precedence' -and $_.Detail -like '*Default Domain Controllers Policy*' }).Count -eq 1)
Check 'no link calls' ($global:LinkCalls.Count -eq 0)

"2. Apply at Audit"
$script:Actions.Clear()
Invoke-HardenDeployment -HardeningProfile Baseline -Level Audit -Area Signing -GpoNamePattern 'ADHardenKit-{ROLE}-{GROUP}' -MemberOu 'OU=Servers,DC=corp,DC=test' -Confirm:$false
Check 'DC GPO created' ($null -ne $global:Gpos['ADHardenKit-DC-Signing'])
Check 'template LDAP=1' ((Tmpl 'ADHardenKit-DC-Signing')[$K] -eq '1')
Check 'DC link created at order 1 (DDCP conflict)' ($global:LinkCalls -contains 'New ADHardenKit-DC-Signing order=1')
Check 'our link now outranks DDCP' ((@($global:Links | ? DisplayName -eq 'ADHardenKit-DC-Signing')[0].Order) -eq 1)
Check 'member link created without order' ($global:LinkCalls -contains 'New ADHardenKit-Member-Signing order=')
Check 'no SMB server signing required at Audit' (-not (Tmpl 'ADHardenKit-DC-Signing').ContainsKey('MACHINE\SYSTEM\CURRENTCONTROLSET\SERVICES\LANMANSERVER\PARAMETERS\REQUIRESECURITYSIGNATURE'))

"3. Enforce, then Audit again: never weaken"
$script:Actions.Clear(); $global:LinkCalls.Clear()
Invoke-HardenDeployment -HardeningProfile Baseline -Level Enforce -Area Signing -GpoNamePattern 'ADHardenKit-{ROLE}-{GROUP}' -MemberOu 'OU=Servers,DC=corp,DC=test' -Confirm:$false
Check 'template LDAP=2 after Enforce' ((Tmpl 'ADHardenKit-DC-Signing')[$K] -eq '2')
Check 'backup written outside SYSVOL' (@(Get-ChildItem "$root/Backups" -Filter '*GptTmpl*').Count -ge 1)
Check 'no .bak left in SYSVOL' (@(Get-ChildItem "$root/Policies" -Recurse -Filter '*.bak*').Count -eq 0)
Check 'link compliant on second run (no relink)' (@($global:LinkCalls | ? { $_ -like '*DC-Signing*' }).Count -eq 0)
$script:Actions.Clear()
Invoke-HardenDeployment -HardeningProfile Baseline -Level Audit -Area Signing -GpoNamePattern 'ADHardenKit-{ROLE}-{GROUP}' -MemberOu 'OU=Servers,DC=corp,DC=test' -Confirm:$false
Check 'Audit run keeps LDAP=2' ((Tmpl 'ADHardenKit-DC-Signing')[$K] -eq '2')
Invoke-HardenDeployment -HardeningProfile Baseline -Level Audit -Area Signing -GpoNamePattern 'ADHardenKit-{ROLE}-{GROUP}' -MemberOu 'OU=Servers,DC=corp,DC=test' -AllowDowngrade -Confirm:$false
Check '-AllowDowngrade lowers to 1' ((Tmpl 'ADHardenKit-DC-Signing')[$K] -eq '1')

"4. Never weaken from the live DC value"
$global:Live['LDAP-ServerSigning'] = 2
Invoke-HardenDeployment -HardeningProfile Baseline -Level Audit -Area Signing -GpoNamePattern 'ADHardenKit-{ROLE}-{GROUP}' -MemberOu 'OU=Servers,DC=corp,DC=test' -Confirm:$false
Check 'DC enforcing already -> kept at 2' ((Tmpl 'ADHardenKit-DC-Signing')[$K] -eq '2')
$global:Live.Clear()

"5. ExcludeTopic"
$script:ExcludedTopics = @('LDAP signing and channel binding'); $script:Actions.Clear()
Invoke-HardenDeployment -HardeningProfile Baseline -Level Audit -Area Signing -GpoNamePattern 'ADHardenKit-{ROLE}-{GROUP}' -MemberOu 'OU=Servers,DC=corp,DC=test' -AllowDowngrade -Confirm:$false
Check 'excluded topic not in template' (-not (Tmpl 'ADHardenKit-DC-Signing').ContainsKey($K))
Check 'excluded topic reported Skipped' (@($script:Actions | ? { $_.Setting -eq 'LDAP-ServerSigning' -and $_.Result -eq 'Skipped' }).Count -ge 1)
Check 'other topic still written' (@((Tmpl 'ADHardenKit-DC-Signing').Keys -match 'NETLOGON').Count -gt 0)
$script:ExcludedTopics = @()

"6. Audit mode (read-only) reports precedence drift"
$global:Links | ? DisplayName -eq 'Default Domain Controllers Policy' | % { $_.Order = 0 }  # DDCP back on top
$script:Actions.Clear(); $before = (Get-ChildItem "$root/Policies" -Recurse | Measure-Object).Count
Invoke-HardenDeployment -HardeningProfile Baseline -Level Audit -Area Signing -GpoNamePattern 'ADHardenKit-{ROLE}-{GROUP}' -MemberOu 'OU=Servers,DC=corp,DC=test' -AuditOnly -Confirm:$false
Check 'AuditOnly writes nothing' ((Get-ChildItem "$root/Policies" -Recurse | Measure-Object).Count -eq $before)

"failures: $fail"
Remove-Item -Recurse -Force $root
