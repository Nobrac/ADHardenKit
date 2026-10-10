# Loads the function definitions from ADHardenKit.ps1 without running the script body, which
# would import RSAT modules and talk to a domain. Dot-source this file from BeforeAll.
$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:ScriptPath = Join-Path $script:RepoRoot 'ADHardenKit.ps1'

$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "ADHardenKit.ps1 does not parse: $($parseErrors[0].Message)" }

$functions = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)
foreach ($f in $functions) {
    . ([scriptblock]::Create($f.Extent.Text))
}
