#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

# The harnesses replace Group Policy and Active Directory cmdlets with global fakes, so each runs
# in its own process rather than leaking those fakes into the other tests.
Describe 'Engine logic against mocked domain controllers' {
    BeforeAll {
        $script:Exe = (Get-Process -Id $PID).Path
        $script:Repo = Split-Path -Parent $PSScriptRoot
    }

    It '<_> passes every check' -ForEach @('Deployment', 'Scan') {
        $harness = Join-Path $PSScriptRoot "harness/$_.Harness.ps1"
        $output = & $script:Exe -NoProfile -ExecutionPolicy Bypass -File $harness -Repo $script:Repo 2>&1 | ForEach-Object { "$_" }
        $failed = @($output | Where-Object { $_ -match '^\s+FAIL ' })
        $failed | Should -BeNullOrEmpty -Because ($output -join "`n")
        ($output -join "`n") | Should -Match 'failures: 0'
    }
}
