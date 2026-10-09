namespace ADHardenKit.Gui.ViewModels;

/// <summary>One line of engine output as the run pages show it.</summary>
public sealed record LogLine(string Level, string Message)
{
    public DateTime Time { get; } = DateTime.Now;

    public bool IsHeader => Level == "Header";

    /// <summary>Segoe Fluent Icons glyph for the level.</summary>
    public string Glyph => Level switch
    {
        "Success" => "",
        "Warning" => "",
        "Error" => "",
        "Skip" => "",
        "Header" => "",
        "Raw" => "",
        _ => "",
    };
}
