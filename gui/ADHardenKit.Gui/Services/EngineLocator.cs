using System.IO;

namespace ADHardenKit.Gui.Services;

/// <summary>Finds ADHardenKit.ps1: next to the executable, or in a parent folder of it.</summary>
public static class EngineLocator
{
    public const string ScriptName = "ADHardenKit.ps1";

    public static string? Find()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; dir is not null && i < 8; i++, dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, ScriptName);
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }
}
