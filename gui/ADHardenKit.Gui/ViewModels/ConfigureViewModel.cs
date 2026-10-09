using System.Collections.ObjectModel;
using System.ComponentModel;
using ADHardenKit.Gui.Models;
using ADHardenKit.Gui.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace ADHardenKit.Gui.ViewModels;

public sealed partial class AreaOption(string name, string description) : ObservableObject
{
    public string Name { get; } = name;
    public string Description { get; } = description;
    public bool IsOptIn => Name == "LOLBins";

    [ObservableProperty] private bool _isSelected;
    [ObservableProperty] private int _settingCount;
}

/// <summary>A setting as the topic details show it, with its current value from the last scan.</summary>
public sealed record SettingRow(SettingInfo Info, string? Current, string? CurrentResult)
{
    public string TargetText => Info.Target switch { "DC" => "Domain controllers", "Member" => "Member servers", _ => "DCs and members" };
    public bool HasCurrent => Current is not null;
}

public sealed partial class TopicOption(string name, string group, IReadOnlyList<SettingRow> settings) : ObservableObject
{
    public string Name { get; } = name;
    public string Group { get; } = group;
    public IReadOnlyList<SettingRow> Settings { get; } = settings;

    public int Count => Settings.Count;
    public bool HasStaged => Settings.Any(s => s.Info.Staged);
    public bool NeedsReboot => Settings.Any(s => s.Info.NeedsReboot);
    public bool IsStrict => Settings.All(s => s.Info.Profile == "Strict");
    public string? MinOs => Settings.Select(s => s.Info.MinOs).Where(m => m is not null).OrderByDescending(m => m).FirstOrDefault();
    public string? Reference => Settings.Select(s => s.Info.Reference).FirstOrDefault(r => !string.IsNullOrEmpty(r));
    public int GapCount => Settings.Count(s => s.CurrentResult is "Missing" or "Drift");

    [ObservableProperty] private bool _isIncluded = true;
}

public sealed partial class ConfigureViewModel : StepViewModel
{
    public ConfigureViewModel(MainViewModel owner) : base(owner, "Choose", "Profile, level and scope")
    {
        foreach (var a in Rollout.AllAreas)
        {
            var option = new AreaOption(a, Rollout.AreaDescriptions[a]);
            option.PropertyChanged += OnAreaChanged;
            Areas.Add(option);
        }
    }

    public ObservableCollection<AreaOption> Areas { get; } = [];
    public ObservableCollection<TopicOption> Topics { get; } = [];
    public ObservableCollection<string> OrganizationalUnits { get; } = [];
    public ObservableCollection<string> EnforceWarnings { get; } = [];

    [ObservableProperty] private bool _isStrict;
    [ObservableProperty] private bool _isEnforce;
    [ObservableProperty] private string? _memberServerOu;
    [ObservableProperty] private string? _ouHint;
    [ObservableProperty] private TopicOption? _selectedTopic;
    [ObservableProperty] private string _commandLine = "";
    [ObservableProperty] private string _scopeSummary = "";

    public bool IsBaseline { get => !IsStrict; set => IsStrict = !value; }
    public bool IsAudit { get => !IsEnforce; set => IsEnforce = !value; }

    public override bool CanGoNext => base.CanGoNext && Areas.Any(a => a.IsSelected) && Topics.Any(t => t.IsIncluded);

    public override string NextLabel => "Preview";

    bool _ousLoaded;
    bool _applying;

    public void ApplyJourney(Journey journey)
    {
        _applying = true;
        foreach (var a in Areas) a.IsSelected = journey.Areas.Contains(a.Name);
        IsEnforce = journey.Level == "Enforce";
        _applying = false;
        Rebuild();
    }

    public override async Task OnEnterAsync()
    {
        Owner.NotifyNextLabel();
        Rebuild();
        if (_ousLoaded) return;
        _ousLoaded = true;
        try
        {
            OuHint = "Reading organisational units...";
            var ous = await DirectoryBrowser.GetOrganizationalUnitsAsync(CancellationToken.None);
            OrganizationalUnits.Clear();
            foreach (var ou in ous) OrganizationalUnits.Add(ou);
            UpdateOuHint();
        }
        catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or InvalidOperationException or UnauthorizedAccessException)
        {
            OuHint = "Could not list the OUs (" + ex.Message.Trim() + "). Type the distinguished name instead.";
        }
    }

    void OnAreaChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(AreaOption.IsSelected) && !_applying) Rebuild();
    }

    partial void OnIsStrictChanged(bool value)
    {
        OnPropertyChanged(nameof(IsBaseline));
        Rebuild();
    }

    partial void OnIsEnforceChanged(bool value)
    {
        OnPropertyChanged(nameof(IsAudit));
        Rebuild();
    }

    partial void OnMemberServerOuChanged(string? value)
    {
        UpdateOuHint();
        UpdateCommandLine();
    }

    void UpdateOuHint()
    {
        if (string.IsNullOrWhiteSpace(MemberServerOu))
        {
            OuHint = "Empty: the member server GPOs are created but not linked. Domain controller GPOs always link to OU=Domain Controllers.";
        }
        else if (OrganizationalUnits.Count > 0 && !OrganizationalUnits.Contains(MemberServerOu.Trim(), StringComparer.OrdinalIgnoreCase))
        {
            OuHint = "This OU is not in the directory listing. The engine checks it again before linking.";
        }
        else
        {
            OuHint = "Member server GPOs link here.";
        }
    }

    void Rebuild()
    {
        if (_applying) return;
        var catalog = Owner.Catalog;
        var selectedAreas = Areas.Where(a => a.IsSelected).Select(a => a.Name).ToHashSet();
        var excluded = Topics.Where(t => !t.IsIncluded).Select(t => t.Name).ToHashSet();
        var previous = SelectedTopic?.Name;

        foreach (var t in Topics) t.PropertyChanged -= OnTopicChanged;
        Topics.Clear();
        if (catalog is not null)
        {
            var inProfile = catalog.Settings.Where(s => IsStrict || s.Profile == "Baseline").ToList();
            foreach (var a in Areas) a.SettingCount = inProfile.Count(s => s.Group == a.Name);

            foreach (var g in inProfile.Where(s => selectedAreas.Contains(s.Group)).GroupBy(s => (s.Group, s.Topic)))
            {
                var rows = g.Select(s =>
                {
                    Owner.CurrentState.TryGetValue(s.Id, out var cur);
                    return new SettingRow(s, cur?.Detail, cur?.Result);
                }).ToList();
                var topic = new TopicOption(g.Key.Topic, g.Key.Group, rows) { IsIncluded = !excluded.Contains(g.Key.Topic) };
                topic.PropertyChanged += OnTopicChanged;
                Topics.Add(topic);
            }
        }
        SelectedTopic = Topics.FirstOrDefault(t => t.Name == previous) ?? Topics.FirstOrDefault();

        EnforceWarnings.Clear();
        if (IsEnforce)
        {
            foreach (var f in Owner.LastFindings.Where(f => f.Group is not null && selectedAreas.Contains(f.Group)))
            {
                EnforceWarnings.Add($"[{f.Group}] {f.Text}");
            }
        }

        UpdateScope();
        UpdateCommandLine();
        RefreshNavigation();
    }

    void OnTopicChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(TopicOption.IsIncluded)) return;
        UpdateScope();
        UpdateCommandLine();
        RefreshNavigation();
    }

    void UpdateScope()
    {
        var included = Topics.Where(t => t.IsIncluded).ToList();
        var settings = included.Sum(t => t.Count);
        var staged = included.SelectMany(t => t.Settings).Count(s => s.Info.Staged);
        var reboot = included.Count(t => t.NeedsReboot);
        ScopeSummary = $"{included.Count} of {Topics.Count} topics, {settings} settings" +
                       (staged > 0 ? $", {staged} staged ({(IsEnforce ? "enforcing" : "observing")})" : "") +
                       (reboot > 0 ? $", {reboot} topic(s) need a reboot" : "") + ".";
    }

    void UpdateCommandLine() => CommandLine = BuildOptions(EngineMode.Deploy, apply: true, force: false).ToCommandLine();

    public RunOptions BuildOptions(EngineMode mode, bool apply, bool force) => new()
    {
        Mode = mode,
        Profile = IsStrict ? "Strict" : "Baseline",
        Level = IsEnforce ? "Enforce" : "Audit",
        Areas = Areas.Where(a => a.IsSelected).Select(a => a.Name).ToList(),
        MemberServerOu = string.IsNullOrWhiteSpace(MemberServerOu) ? null : MemberServerOu.Trim(),
        ExcludeTopics = Topics.Where(t => !t.IsIncluded).Select(t => t.Name).ToList(),
        ScanDays = Owner.Scan.ScanDays,
        Apply = apply,
        Force = force,
    };

    [RelayCommand]
    private void CopyCommandLine() => System.Windows.Clipboard.SetText(CommandLine);

    [RelayCommand]
    private void IncludeAllTopics()
    {
        foreach (var t in Topics) t.IsIncluded = true;
    }

    [RelayCommand]
    private void ExcludeAllTopics()
    {
        foreach (var t in Topics) t.IsIncluded = false;
    }
}
