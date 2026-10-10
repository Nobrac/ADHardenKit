#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelper.ps1')
    $script:Baseline = @(Get-HardenBaseline)
    $script:Settings = @($script:Baseline | Where-Object { $_.Type -ne 'FirewallRule' })
    $script:Audit = @(Get-HardenAuditPolicy)
}

Describe 'Scripts parse' {
    It '<_> has no parse errors' -ForEach @('ADHardenKit.ps1', 'Verify-LoggingDeployment.ps1', 'Verify-MemberDeployment.ps1') {
        $path = Join-Path (Split-Path -Parent $PSScriptRoot) $_
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
        $errors.Count | Should -Be 0
    }
}

Describe 'Baseline data' {
    It 'has 92 settings outside the LOLBins group' {
        $script:Settings.Count | Should -Be 92
    }

    It 'has 50 LOLBin firewall entries' {
        @($script:Baseline | Where-Object { $_.Type -eq 'FirewallRule' }).Count | Should -Be 50
    }

    It 'uses every Id only once' {
        $dupes = @($script:Baseline | Group-Object { $_.Id } | Where-Object Count -gt 1 | ForEach-Object Name)
        $dupes | Should -BeNullOrEmpty
    }

    It 'gives every entry the required fields' {
        foreach ($s in $script:Baseline) {
            foreach ($field in 'Id', 'Topic', 'Group', 'Name', 'Type', 'Target', 'Profile') {
                $s[$field] | Should -Not -BeNullOrEmpty -Because "$($s.Id) needs $field"
            }
        }
    }

    It 'uses only known groups, targets, profiles and types' {
        foreach ($s in $script:Baseline) {
            $s.Group | Should -BeIn @('Signing', 'LegacyAuth', 'CredentialProtection', 'Protocols', 'PolicyIntegrity', 'Logging', 'Services', 'LOLBins') -Because $s.Id
            $s.Target | Should -BeIn @('DC', 'Member', 'Both') -Because $s.Id
            $s.Profile | Should -BeIn @('Baseline', 'Strict') -Because $s.Id
            $s.Type | Should -BeIn @('SecurityOption', 'AdminTemplate', 'Service', 'StartupScript', 'FirewallRule') -Because $s.Id
        }
    }

    It 'uses only known minimum versions' {
        foreach ($s in @($script:Settings | Where-Object { $_.MinOS })) {
            $s.MinOS | Should -BeIn @('Server 2012', 'Server 2016', 'Server 2019', 'Server 2022', 'Server 2025') -Because $s.Id
        }
    }

    It 'has eight staged settings' {
        @($script:Settings | Where-Object { $_.Staged }).Count | Should -Be 8
    }

    It 'never stages a zero as the observing value' {
        # A zero in a staged SecurityOption would switch off what a DC already requires by default.
        foreach ($s in @($script:Settings | Where-Object { $_.Staged })) {
            if ($s.Contains('AuditValue') -and $null -ne $s.AuditValue) {
                $s.AuditValue | Should -Not -Be 0 -Because "$($s.Id) must not observe by disabling"
            }
            $s.EnforceValue | Should -Not -BeNullOrEmpty -Because $s.Id
        }
    }

    It 'writes Credential Guard as LsaCfgFlags' {
        $cg = $script:Settings | Where-Object { $_.Id -like 'CredentialGuard*' } | Select-Object -First 1
        $cg | Should -Not -BeNullOrEmpty
        @($cg.Values | ForEach-Object { $_.Name }) | Should -Contain 'LsaCfgFlags'
        @($cg.Values | ForEach-Object { $_.Name }) | Should -Not -Contain 'LsaCfg'
    }

    It 'no longer deploys StrongCertificateBindingEnforcement' {
        # Not read by the KDC since the September 2025 update.
        @($script:Settings | Where-Object { "$($_.Key)" -match 'StrongCertificateBindingEnforcement' }) | Should -BeNullOrEmpty
    }

    It 'gives every SecurityOption a MACHINE\ key and a value type' {
        foreach ($s in @($script:Settings | Where-Object { $_.Type -eq 'SecurityOption' -and $_.Key })) {
            $s.Key | Should -Match '^MACHINE\\' -Because $s.Id
            $s.ValueType | Should -BeIn @(1, 3, 4, 7) -Because $s.Id
        }
    }
}

Describe 'Audit policy' {
    It 'uses well-formed, unique subcategory GUIDs' {
        foreach ($a in $script:Audit) {
            $a.Guid | Should -Match '^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$' -Because $a.Subcategory
        }
        @($script:Audit | Group-Object Guid | Where-Object Count -gt 1) | Should -BeNullOrEmpty
    }

    It 'uses only values 0 to 3' {
        foreach ($a in $script:Audit) {
            $a.DcValue | Should -BeIn 0, 1, 2, 3
            $a.MemberValue | Should -BeIn 0, 1, 2, 3
        }
    }
}

Describe 'Get-HardenTemplateValue' {
    BeforeAll {
        $gpoRoot = Join-Path $TestDrive 'gpo'
        $secDir = Join-Path $gpoRoot 'Machine\Microsoft\Windows NT\SecEdit'
        New-Item -ItemType Directory -Path $secDir -Force | Out-Null
        $inf = @(
            '[Unicode]', 'Unicode=yes',
            '[Registry Values]',
            'MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity=4,2',
            'machine\System\CurrentControlSet\Control\Lsa\RunAsPPL = 4 , 1',
            'MACHINE\Software\Example\Text=1,"quoted"',
            '[Version]', 'signature="$CHICAGO$"', 'Revision=1'
        ) -join "`r`n"
        [System.IO.File]::WriteAllText((Join-Path $secDir 'GptTmpl.inf'), $inf, [System.Text.Encoding]::Unicode)
        Mock Get-HardenGpoPath { Join-Path $TestDrive 'gpo' }
    }

    It 'reads values from a UTF-16 template, keyed upper-case' {
        $v = Get-HardenTemplateValue -Gpo ([pscustomobject]@{ Id = [guid]::NewGuid() })
        $v['MACHINE\SYSTEM\CURRENTCONTROLSET\SERVICES\NTDS\PARAMETERS\LDAPSERVERINTEGRITY'] | Should -Be '2'
        $v['MACHINE\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA\RUNASPPL'] | Should -Be '1'
        $v['MACHINE\SOFTWARE\EXAMPLE\TEXT'] | Should -Be 'quoted'
        $v.Count | Should -Be 3
    }

    It 'returns an empty table when there is no template' {
        Mock Get-HardenGpoPath { Join-Path $TestDrive 'missing' }
        (Get-HardenTemplateValue -Gpo ([pscustomobject]@{ Id = [guid]::NewGuid() })).Count | Should -Be 0
    }
}

Describe 'Catalog mode' {
    It 'prints the whole baseline as JSON without a domain' {
        $json = & (Join-Path (Split-Path -Parent $PSScriptRoot) 'ADHardenKit.ps1') -Mode Catalog
        $catalog = ($json -join '') | ConvertFrom-Json
        @($catalog.settings).Count | Should -Be $script:Baseline.Count
        @($catalog.auditPolicy).Count | Should -Be $script:Audit.Count
        $catalog.version | Should -Match '^\d+\.\d+\.\d+$'
    }
}

Describe 'Topic exclusion' {
    BeforeEach {
        $script:InteractiveMode = $false
        $script:AutoDecision = $null
        $script:DecisionCache = @{}
    }

    It 'approves every topic by default outside interactive mode' {
        $script:ExcludedTopics = @()
        Test-HardenTopicApproved -Topic 'LSA protection' | Should -Be $true
    }

    It 'declines a topic named in -ExcludeTopic' {
        $script:ExcludedTopics = @('LSA protection')
        Test-HardenTopicApproved -Topic 'LSA protection' | Should -Be $false
        Test-HardenTopicApproved -Item @{ Topic = 'LSA protection' } | Should -Be $false
        Test-HardenTopicApproved -Topic 'SMB audit' | Should -Be $true
    }
}

Describe 'Repository hygiene' {
    It 'keeps the README setting count in step with the code' {
        $readme = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'README.md') -Raw
        $readme | Should -Match "\b$($script:Settings.Count) settings\b"
    }
}
