using System.Text.Json;
using System.Text.Json.Serialization;

namespace ADHardenKit.Gui.Models;

/// <summary>The baseline as the engine prints it with -Mode Catalog.</summary>
public sealed class Catalog
{
    public string Version { get; set; } = "";
    public List<SettingInfo> Settings { get; set; } = [];
    public List<AuditEntry> AuditPolicy { get; set; } = [];
}

public sealed class SettingInfo
{
    public string Id { get; set; } = "";
    public string Topic { get; set; } = "";
    public string Group { get; set; } = "";
    public string Name { get; set; } = "";
    public string Type { get; set; } = "";
    public string Target { get; set; } = "";
    public string Profile { get; set; } = "";
    public bool Staged { get; set; }
    public bool NeedsReboot { get; set; }
    [JsonPropertyName("MinOS")] public string? MinOs { get; set; }
    public string? Why { get; set; }
    public string? Observe { get; set; }
    public string? Reference { get; set; }
    public string? Impact { get; set; }
    public JsonElement? AuditValue { get; set; }
    public JsonElement? EnforceValue { get; set; }

    public bool IsFirewallRule => Type == "FirewallRule";

    public string AuditText => Format(AuditValue);
    public string EnforceText => Format(EnforceValue);

    static string Format(JsonElement? e) => e is null || e.Value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined
        ? "not deployed"
        : e.Value.ValueKind == JsonValueKind.String ? e.Value.GetString() ?? "" : e.Value.GetRawText();
}

public sealed class AuditEntry
{
    public string Subcategory { get; set; } = "";
    public string Guid { get; set; } = "";
    public int DcValue { get; set; }
    public int MemberValue { get; set; }
    public string? Why { get; set; }
}
