using ADHardenKit.Gui.Models;
using ADHardenKit.Gui.Services;
using Xunit;

namespace ADHardenKit.Gui.Tests;

public class EngineRunnerTests
{
    [Fact]
    public void Parses_each_event_type()
    {
        Assert.Equal(new LogEvent("Warning", "careful"), EngineRunner.Parse("""@@ADHK {"type":"log","level":"Warning","message":"careful"}"""));
        Assert.Equal(new FindingEvent(null, "krbtgt"), EngineRunner.Parse("""@@ADHK {"type":"finding","group":null,"text":"krbtgt"}"""));
        Assert.Equal(new MissingModuleEvent("GroupPolicy"), EngineRunner.Parse("""@@ADHK {"type":"missingModule","module":"GroupPolicy"}"""));
        var action = Assert.IsType<ActionEvent>(EngineRunner.Parse("""@@ADHK {"type":"action","area":"Signing","setting":"X","target":"T","result":"Planned","severity":"Info","detail":null}"""));
        Assert.Equal("Planned", action.Result);
        var report = Assert.IsType<ReportEvent>(EngineRunner.Parse("""@@ADHK {"type":"report","html":"C:\\r.html","json":"C:\\r.json","log":"C:\\l.log"}"""));
        Assert.Equal(@"C:\r.html", report.Html);
    }

    [Fact]
    public void Plain_and_broken_lines_become_raw_text()
    {
        Assert.IsType<RawLineEvent>(EngineRunner.Parse("  PLAN MODE - nothing will be changed."));
        Assert.IsType<RawLineEvent>(EngineRunner.Parse("@@ADHK {not json"));
        Assert.Null(EngineRunner.Parse("   "));
    }

    static string? FindPwsh()
    {
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator).Append("/opt/pwsh"))
        {
            foreach (var name in new[] { "pwsh", "pwsh.exe" })
            {
                var p = Path.Combine(dir, name);
                if (File.Exists(p)) return p;
            }
        }
        return null;
    }

    static string Script()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "ADHardenKit.ps1"))) dir = dir.Parent;
        return Path.Combine(dir?.FullName ?? throw new FileNotFoundException("ADHardenKit.ps1"), "ADHardenKit.ps1");
    }

    [Fact]
    public async Task Loads_the_catalog_through_an_encoded_command()
    {
        var pwsh = FindPwsh();
        if (pwsh is null) return; // no PowerShell on this machine; the parser tests above still ran

        var catalog = await new EngineRunner(Script(), pwsh).LoadCatalogAsync(CancellationToken.None);
        Assert.Equal(92, catalog.Settings.Count(s => !s.IsFirewallRule));
        Assert.Equal(8, catalog.Settings.Count(s => s.Staged && !s.IsFirewallRule));
        Assert.Contains(catalog.Settings, s => s.Id == "LDAP-ServerSigning" && s.EnforceText == "2" && s.AuditText == "1");
    }

    [Fact]
    public async Task Missing_rsat_is_reported_as_an_event_with_exit_code_3()
    {
        var pwsh = FindPwsh();
        if (pwsh is null || OperatingSystem.IsWindows()) return; // on Windows RSAT may well be installed

        var events = new List<EngineEvent>();
        var progress = new Collect(events);
        var options = new RunOptions { Mode = EngineMode.Scan, Areas = ["Signing", "Logging"], ExcludeTopics = ["O'Brien’s topic"] };
        var exit = await new EngineRunner(Script(), pwsh).RunAsync(options.ToArguments(), progress, CancellationToken.None);
        Assert.Equal(3, exit);
        Assert.Contains(events, e => e is MissingModuleEvent { Module: "ActiveDirectory" });
    }

    sealed class Collect(List<EngineEvent> sink) : IProgress<EngineEvent>
    {
        public void Report(EngineEvent value) { lock (sink) sink.Add(value); }
    }
}
