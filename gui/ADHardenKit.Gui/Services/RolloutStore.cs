using System.IO;
using System.Text.Json;

namespace ADHardenKit.Gui.Services;

/// <summary>Where a domain stands in the rollout. One small JSON file per domain, per user.</summary>
public sealed class RolloutState
{
    public string Domain { get; set; } = "";
    public Dictionary<string, DateTimeOffset> Completed { get; set; } = [];
    public DateTimeOffset? LastScan { get; set; }
    public int? LastScanFindings { get; set; }
    public string? LastReport { get; set; }
}

public static class RolloutStore
{
    static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    static string Folder => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ADHardenKit");

    static string PathFor(string domain)
    {
        var safe = string.Concat(domain.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));
        return Path.Combine(Folder, $"rollout-{safe.ToLowerInvariant()}.json");
    }

    public static RolloutState Load(string domain)
    {
        try
        {
            var path = PathFor(domain);
            if (File.Exists(path))
            {
                var state = JsonSerializer.Deserialize<RolloutState>(File.ReadAllText(path), Options);
                if (state is not null) return state;
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            // A damaged or unreadable state file must not keep the tool from starting; the
            // rollout view simply starts from the beginning.
        }
        return new RolloutState { Domain = domain };
    }

    public static void Save(RolloutState state)
    {
        try
        {
            Directory.CreateDirectory(Folder);
            File.WriteAllText(PathFor(state.Domain), JsonSerializer.Serialize(state, Options));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Progress tracking is a convenience; failing to save it never fails a run.
        }
    }
}
