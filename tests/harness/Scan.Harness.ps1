# Runs Invoke-HardenScan against two mocked domain controllers: event logs, registry and the
# directory are fakes, the remote script blocks run locally. Prints one line per check and
# 'failures: N' at the end; tests/Logic.Tests.ps1 runs it in a child process.
param($Repo)
$ErrorActionPreference = 'Stop'
. (Join-Path $Repo 'tests/TestHelper.ps1')
$script:LogFile = $null; $script:EventStream = $false; $script:ExcludedTopics = @()
$script:Actions = [System.Collections.Generic.List[object]]::new(); $script:LiveCache = @{}
$script:Context = [pscustomobject]@{ DomainFqdn='corp.test'; DomainDn='DC=corp,DC=test'; DomainSid='S-1-5-21-1'; DomainControllersDn='OU=Domain Controllers,DC=corp,DC=test'; Server='dc1.corp.test'; SysvolPolicyPath='/nonexistent' }
$global:Log = [System.Collections.Generic.List[string]]::new()
$global:HostLines = [System.Collections.Generic.List[string]]::new()
function Write-Host { param($Object) $global:HostLines.Add("$Object") }
function global:Get-ADDomainController { param($Filter,$Server,$ErrorAction) @([pscustomobject]@{HostName='dc1.corp.test'},[pscustomobject]@{HostName='dc2.corp.test'}) }
function global:Get-ADObject { param($LDAPFilter,$Properties,$Server,$ErrorAction,$Identity) $global:LastFilter=$LDAPFilter; @($global:Rc4Objects) }
function global:Get-ADUser { param($LDAPFilter,$Identity,$Properties,$Server,$ErrorAction)
  if ($Identity) { [pscustomobject]@{ PasswordLastSet=(Get-Date).AddDays(-400); whenCreated=(Get-Date).AddYears(-5) } } else { @() } }
$global:Rc4Objects = @([pscustomobject]@{ Name='svc-old'; samAccountName='svc-old' })
function global:Invoke-Command { param($ComputerName,$ArgumentList,$ErrorAction,$ScriptBlock)
  $global:CurrentDc = $ComputerName
  if ($global:Unreachable -contains $ComputerName) { throw "WinRM cannot reach $ComputerName" }
  & $ScriptBlock @ArgumentList }
function NewEvt($id, $provider, $props, $data) {
  $e=[pscustomobject]@{ Id=$id; ProviderName=$provider; Properties=@($props | % { [pscustomobject]@{Value=$_} }) }
  $xml = '<Event><EventData>' + (($data.GetEnumerator() | % { "<Data Name=`"$($_.Key)`">$($_.Value)</Data>" }) -join '') + '</EventData></Event>'
  $e | Add-Member ScriptMethod ToXml ([scriptblock]::Create("'" + $xml.Replace("'","''") + "'")) -PassThru }
$global:Events = @{
  'dc1.corp.test' = @{
     'Directory Service' = @( (NewEvt 2889 'x' @('10.0.0.5:51234','CORP\scanner') @{}), (NewEvt 2889 'x' @('10.0.0.5:51300','CORP\scanner') @{}), (NewEvt 2889 'x' @('10.0.0.9:1000','') @{}) )
     'Microsoft-Windows-NTLM/Operational' = @( (NewEvt 8002 'NTLM' @() @{ClientUserName='bob';ClientWorkstationName='PC1'}), (NewEvt 8004 'NTLM' @() @{UserName='alice';WorkstationName='PC2'}) )
     'System' = @( (NewEvt 39 'Microsoft-Windows-Kerberos-Key-Distribution-Center' @() @{}), (NewEvt 41 'Microsoft-Windows-Kernel-Power' @() @{}) ) }
  'dc2.corp.test' = @{} }
function global:Get-WinEvent { [CmdletBinding()] param($FilterHashtable)
  $all = @($global:Events[$global:CurrentDc][$FilterHashtable.LogName] | ? { $_ })
  if ($FilterHashtable.Id) { $all = @($all | ? { $_.Id -in @($FilterHashtable.Id) }) }
  if ($all.Count -eq 0) {
    $er = [System.Management.Automation.ErrorRecord]::new([Exception]::new('Es wurden keine Ereignisse gefunden'),'NoMatchingEventsFound',[System.Management.Automation.ErrorCategory]::ObjectNotFound,$null)
    $PSCmdlet.ThrowTerminatingError($er) }
  $all }
$global:Reg = @{
  'dc1.corp.test' = @{ '16 LDAP Interface Events' = 2; 'LDAPServerIntegrity' = 1; 'RequireSignOrSeal' = 1 }
  'dc2.corp.test' = @{ 'LDAPServerIntegrity' = 2; 'RequireSignOrSeal' = 1 } }
function global:Get-ItemProperty { param($Path,$LiteralPath,$Name,$ErrorAction)
  $v = $global:Reg[$global:CurrentDc][$Name]; if ($null -eq $v) { return $null }
  $o=[pscustomobject]@{}; $o | Add-Member NoteProperty $Name $v; $o }
$fail=0
function Check($name, $cond) { if ($cond) { "  ok   $name" } else { "  FAIL $name"; $script:fail++ } }

$blockers = @(Invoke-HardenScan -Days 30 -Level Audit -Area Signing,LegacyAuth -HardeningProfile Baseline)
$f = $script:ScanFindings
"findings:"; $f | % { "    [$($_.Group)] $($_.Text.Substring(0,[Math]::Min(90,$_.Text.Length)))" }
Check 'LDAP 3 unsigned binds -> Signing finding' (@($f | ? { $_.Group -eq 'Signing' -and $_.Text -like 'LDAP signing: 3 *' }).Count -eq 1)
Check 'dc2 diagnostics off -> Signing finding' (@($f | ? { $_.Group -eq 'Signing' -and $_.Text -like 'dc2*diagnostics off*' }).Count -eq 1)
Check 'dc1 diagnostics on -> no finding' (@($f | ? { $_.Text -like 'dc1*diagnostics off*' }).Count -eq 0)
Check 'NTLM inbound finding (LegacyAuth)' (@($f | ? { $_.Group -eq 'LegacyAuth' -and $_.Text -like 'NTLM inbound: 1 *' }).Count -eq 1)
Check 'NTLM domain finding' (@($f | ? { $_.Text -like 'NTLM in the domain: 1 *' }).Count -eq 1)
Check 'cert events: only the KDC one counted, informational' (@($f | ? { $null -eq $_.Group -and $_.Text -like 'Certificate mapping: 1 *' }).Count -eq 1)
Check 'RC4 finding' (@($f | ? { $_.Group -eq 'LegacyAuth' -and $_.Text -like 'Kerberos AES: 1 *' }).Count -eq 1)
Check 'RC4 filter uses OR rule for AES' ($global:LastFilter -like '*1.2.840.113556.1.4.804:=24*')
Check 'krbtgt informational' (@($f | ? { $null -eq $_.Group -and $_.Text -like 'krbtgt*' }).Count -eq 1)
Check 'blockers list = findings' ($blockers.Count -eq $f.Count)
Check 'LDAP server signing drift between DCs' (@($script:Actions | ? { $_.Setting -eq 'LDAP-ServerSigning' -and $_.Result -eq 'Drift' }).Count -eq 1)
Check 'LDAP server signing compliant on dc1 at Audit (1)' (@($script:Actions | ? { $_.Setting -eq 'LDAP-ServerSigning' -and $_.Result -eq 'Compliant' -and $_.Target -eq 'dc1.corp.test' }).Count -eq 1)
Check 'NTLM names parsed from event XML' (@($global:HostLines | ? { $_ -like '*ClientUserName: bob*' }).Count -eq 1)
Check 'LDAP client named from event properties' (@($global:HostLines | ? { $_ -like '*CORP\scanner from 10.0.0.5*' }).Count -eq 1)

"--- unreachable DC and empty logs"
$global:Unreachable=@('dc2.corp.test'); $global:Events['dc1.corp.test'] = @{}; $global:Rc4Objects=@(); $script:Actions.Clear()
$blockers = @(Invoke-HardenScan -Days 30 -Level Enforce -Area Signing -HardeningProfile Baseline)
$f = $script:ScanFindings
"findings:"; $f | % { "    [$($_.Group)] $($_.Text.Substring(0,[Math]::Min(90,$_.Text.Length)))" }
Check 'empty German log is not an error -> no LDAP finding' (@($f | ? { $_.Text -like 'LDAP signing:*' }).Count -eq 0)
Check 'unreachable DC gives no drift rows' (@($script:Actions | ? { $_.Result -eq 'Drift' -and $_.Setting -ne 'krbtgt-PasswordAge' }).Count -eq 0)
Check 'Enforce target 2 vs dc1 value 1 -> Missing' (@($script:Actions | ? { $_.Setting -eq 'LDAP-ServerSigning' -and $_.Result -eq 'Missing' }).Count -eq 1)
"failures: $fail"
