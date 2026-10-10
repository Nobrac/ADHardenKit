using System.Globalization;

namespace ADHardenKit.Gui.Models;

public enum EngineMode { Check, Scan, Deploy, Audit }

/// <summary>One script parameter: a switch (no value), a single value or a list.</summary>
public sealed record EngineArgument(string Name, IReadOnlyList<string>? Values = null)
{
    public bool IsSwitch => Values is null;
}

/// <summary>Everything a run of the engine is started with. Mirrors the script's parameters.</summary>
public sealed record RunOptions
{
    public EngineMode Mode { get; init; } = EngineMode.Scan;
    public string Profile { get; init; } = "Baseline";
    public string Level { get; init; } = "Audit";
    public IReadOnlyList<string> Areas { get; init; } = Rollout.DefaultAreas;
    public string? MemberServerOu { get; init; }
    public IReadOnlyList<string> ExcludeTopics { get; init; } = [];
    public int ScanDays { get; init; } = 30;
    public string? Server { get; init; }
    public bool Apply { get; init; }
    public bool Force { get; init; }

    public List<EngineArgument> ToArguments()
    {
        var a = new List<EngineArgument> { new("Mode", [Mode.ToString()]) };
        if (Mode is EngineMode.Deploy or EngineMode.Audit) a.Add(new("Profile", [Profile]));
        if (Mode is EngineMode.Deploy or EngineMode.Scan) a.Add(new("Level", [Level]));
        if (Mode != EngineMode.Check && Areas.Count > 0) a.Add(new("Area", Areas));
        if (Mode == EngineMode.Deploy && !string.IsNullOrWhiteSpace(MemberServerOu)) a.Add(new("MemberServerOu", [MemberServerOu!]));
        if (Mode == EngineMode.Deploy && ExcludeTopics.Count > 0) a.Add(new("ExcludeTopic", ExcludeTopics));
        if (Mode == EngineMode.Scan || (Mode == EngineMode.Deploy && Level == "Enforce"))
        {
            a.Add(new("ScanDays", [ScanDays.ToString(CultureInfo.InvariantCulture)]));
        }
        if (!string.IsNullOrWhiteSpace(Server)) a.Add(new("Server", [Server!]));
        if (Mode == EngineMode.Deploy && Apply) a.Add(new("Apply"));
        if (Mode == EngineMode.Deploy && Force) a.Add(new("Force"));
        return a;
    }

    /// <summary>
    /// The arguments as PowerShell source. Every value is a single-quoted literal, so nothing in
    /// an OU name or a topic can be interpreted - the runner passes this as -EncodedCommand.
    /// </summary>
    public static string Render(IEnumerable<EngineArgument> args, bool compact = false)
    {
        var parts = new List<string>();
        foreach (var arg in args)
        {
            parts.Add("-" + arg.Name);
            if (arg.IsSwitch) continue;
            parts.Add(string.Join(",", arg.Values!.Select(v => compact && IsPlain(v) ? v : Quote(v))));
        }
        return string.Join(" ", parts);
    }

    /// <summary>The same run as a command line an admin can paste into a console or a scheduled task.</summary>
    public string ToCommandLine() => @".\ADHardenKit.ps1 " + Render(ToArguments(), compact: true);

    public static string Quote(string s)
    {
        // PowerShell also closes a single-quoted string on the typographic quotes, so those are
        // doubled as well - an OU called "Team’s servers" must not end the literal.
        var sb = new System.Text.StringBuilder("'");
        foreach (var c in s)
        {
            sb.Append(c);
            if (c is '\'' or '\u2018' or '\u2019' or '\u201A' or '\u201B') sb.Append(c);
        }
        return sb.Append('\'').ToString();
    }

    static bool IsPlain(string s) => s.Length > 0 && s.All(c => char.IsLetterOrDigit(c) || c is '-' or '.');
}
