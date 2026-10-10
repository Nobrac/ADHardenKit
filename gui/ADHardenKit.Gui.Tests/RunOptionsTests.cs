using ADHardenKit.Gui.Models;
using Xunit;

namespace ADHardenKit.Gui.Tests;

public class RunOptionsTests
{
    [Fact]
    public void Quote_doubles_every_single_quote_powershell_recognises()
    {
        Assert.Equal("'O''Brien'", RunOptions.Quote("O'Brien"));
        Assert.Equal("'Team\u2019\u2019s'", RunOptions.Quote("Team\u2019s"));
        Assert.Equal("'$(evil)'", RunOptions.Quote("$(evil)"));
    }

    [Fact]
    public void Scan_passes_areas_as_a_list()
    {
        var o = new RunOptions { Mode = EngineMode.Scan, Areas = ["Signing", "Logging"], ScanDays = 14 };
        Assert.Equal("-Mode 'Scan' -Level 'Audit' -Area 'Signing','Logging' -ScanDays '14'", RunOptions.Render(o.ToArguments()));
    }

    [Fact]
    public void Deploy_carries_ou_exclusions_and_switches()
    {
        var o = new RunOptions
        {
            Mode = EngineMode.Deploy,
            Profile = "Strict",
            Level = "Enforce",
            Areas = ["Signing"],
            MemberServerOu = "OU=Server,DC=example,DC=com",
            ExcludeTopics = ["SMB audit"],
            Apply = true,
            Force = true,
        };
        var rendered = RunOptions.Render(o.ToArguments());
        Assert.Contains("-MemberServerOu 'OU=Server,DC=example,DC=com'", rendered);
        Assert.Contains("-ExcludeTopic 'SMB audit'", rendered);
        Assert.EndsWith("-Apply -Force", rendered);
    }

    [Fact]
    public void Check_takes_no_scope()
    {
        Assert.Equal("-Mode 'Check'", RunOptions.Render(new RunOptions { Mode = EngineMode.Check }.ToArguments()));
    }

    [Fact]
    public void Command_line_leaves_plain_values_unquoted()
    {
        var o = new RunOptions { Mode = EngineMode.Deploy, Areas = ["Logging"], MemberServerOu = "OU=Server,DC=example,DC=com", Apply = true };
        Assert.Equal(@".\ADHardenKit.ps1 -Mode Deploy -Profile Baseline -Level Audit -Area Logging -MemberServerOu 'OU=Server,DC=example,DC=com' -Apply", o.ToCommandLine());
    }
}
